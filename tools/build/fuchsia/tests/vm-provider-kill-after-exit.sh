#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-provider.sh's monitor (vm-monitor.py and the shell block around it),
# with a stand-in QEMU (a shell) writing a stand-in serial log; no guest.
# - A guest that powers off by itself during the grace after a problem is
#   not killed, the grace ends at its exit, and the run goes on to results
#   extraction and the verdict with forced=1
#   (5bsd-issues 2026-11-18-vm-provider-kill-after-guest-exit-aborts.md).
# - A fatal line, an unknown reversal and the deadline stop QEMU; a guest
#   that ends cleanly, a known shutdown reversal and FATAL_LOR=no do not;
#   a report is not judged before it is complete.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mon=$root/vm-monitor.py
fix=$root/tests/known-lor
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }
fatal='panic:|Fatal trap'
log=$work/serial.log
# run GRACE DEADLINE_S FATAL_LOR SCRIPT: start SCRIPT (the stand-in QEMU,
# writing $log), monitor it; sets mrc, out, secs.
run() {
	: > "$log"
	sh -c "$4" sh "$log" & q=$!
	t0=$(date +%s)
	mrc=0
	out=$(python3.12 -I "$mon" --pid $q --log "$log" \
	    --deadline $(($(date +%s) + $2)) --fatal "$fatal" \
	    --known "$root/known-lor.txt" --fatal-lor "$3" --grace "$1") || mrc=$?
	secs=$(($(date +%s) - t0))
	kill $q 2>/dev/null || :
	wait $q 2>/dev/null || :
}
# Problem, then the guest powers off by itself during a long grace.
run 60 600 yes 'echo "panic: test" >> "$1"; sleep 2; exit 0'
[ $mrc = 3 ] || fail "exit-during-grace: exit $mrc ($out)"
echo "$out" | grep -qx 'qemu had already exited' || fail "not seen as exited: $out"
[ $secs -lt 30 ] || fail "the grace did not end at the exit (${secs}s)"
# Problem, guest keeps running: stopped after the grace.
run 1 600 yes 'echo "Fatal trap 12" >> "$1"; exec sleep 600'
[ $mrc = 3 ] || fail "fatal: exit $mrc ($out)"
echo "$out" | grep -qx 'KERNEL/INIT PROBLEM in serial log' || fail "fatal: $out"
echo "$out" | grep -q 'already exited' && fail "fatal: wrongly 'already exited'"
[ $secs -lt 30 ] || fail "fatal: not stopped (${secs}s)"
# A fatal prompt without a newline (mountroot>) is seen too.
fatal='mountroot>'
run 1 600 yes 'printf "mountroot> " >> "$1"; exec sleep 600'
[ $mrc = 3 ] || fail "prompt: exit $mrc ($out)"
fatal='panic:|Fatal trap'
# Deadline.
run 60 1 yes 'exec sleep 600'
[ $mrc = 4 ] && echo "$out" | grep -qx TIMEOUT || fail "deadline: exit $mrc ($out)"
# Clean guest.
run 1 600 yes 'echo booting >> "$1"; sleep 1; echo "Powering system off" >> "$1"'
[ $mrc = 0 ] && [ -z "$out" ] || fail "clean: exit $mrc ($out)"
# A known shutdown reversal, written in two parts: not judged half-written.
k=$fix/known-shutdown-tmpfs-devfs.txt
run 1 600 yes "head -n 6 '$k' >> \"\$1\"; sleep 1; tail -n +7 '$k' >> \"\$1\"; echo 'Uptime: 1m' >> \"\$1\"; sleep 1"
[ $mrc = 0 ] || fail "known report: exit $mrc ($out)"
# An unknown test-time reversal (WITNESS reports a class pair once per boot:
# a mid-run match would hide later ones) stops the run; FATAL_LOR=no does not.
u=$fix/unknown-test-time-tmpfs-ufs-rootvp.txt
run 1 600 yes "cat '$u' >> \"\$1\"; echo 'next line' >> \"\$1\"; exec sleep 600"
[ $mrc = 3 ] || fail "unknown report: exit $mrc ($out)"
run 1 600 no "cat '$u' >> \"\$1\"; echo 'next line' >> \"\$1\"; sleep 1"
[ $mrc = 0 ] || fail "FATAL_LOR=no: exit $mrc ($out)"
# The shell block of vm-provider.sh, with the guest gone before the grace ends.
sed -n '/^# --- monitor (tests/,/^# --- end of the monitor$/p' \
    "$root/vm-provider.sh" > "$work/block.sh"
grep -q 'vm-monitor' "$work/block.sh" || fail 'no monitor block'
cat > "$work/run.sh" <<'EOS'
set -eu
log=$1 monitor=$2 known_lor=$3 fatal='panic:' end=$(($(date +%s) + 600))
forced=0
: > "$log"
sh -c 'echo "panic: x" >> "$1"; sleep 1' sh "$log" & qpid=$!
. "$4"
echo "AFTER forced=$forced rc=$rc"
EOS
out=$(sh "$work/run.sh" "$log" "$mon" "$root/known-lor.txt" "$work/block.sh" 2>&1) ||
    fail "the block ended the script: $out"
echo "$out" | grep -q '^AFTER forced=1 rc=0$' || fail "block: $out"
echo 'PASS the monitor waits on events, stops for problems and the deadline, and a guest gone before the kill still reaches the verdict'
