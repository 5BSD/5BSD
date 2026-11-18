#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-provider.sh: when the guest exits on its own between the problem (or
# the deadline) and the kill, kill fails with ESRCH.  Under set -eu that
# must not end the run before the results disk is extracted and the
# verdict printed (5bsd-issues 2026-11-18-vm-provider-kill-after-guest-exit-aborts.md).
# Runs the actual monitor loop with a QEMU that has already exited; no guest.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }
sed -n '/^# --- monitor loop/,/^# --- end of the monitor loop$/p' \
    "$root/vm-provider.sh" > "$work/block.sh"
grep -q 'while kill -0 "\$qpid"' "$work/block.sh" || fail 'no block'
# The loop's view of the guest: alive at the check, gone at the kill.  The
# pid is a child that has already exited and been reaped.
cat > "$work/run.sh" <<'EOS'
set -eu
log=$1 end=$2 fatal='panic:'
unknown_lor() { return 1; }
sleep() { :; }
kill() { if [ "$1" = -0 ]; then return 0; fi; command kill "$@"; }
/usr/bin/true & qpid=$!
command wait "$qpid" || :
forced=0
. "$3"
echo "AFTER_LOOP forced=$forced rc=$rc"
EOS
echo 'panic: test' > "$work/fatal.log"
: > "$work/quiet.log"
now=$(date +%s)
out=$(sh "$work/run.sh" "$work/fatal.log" $((now + 3600)) "$work/block.sh" 2>&1) ||
    fail "the problem branch ended the script: $out"
echo "$out" | grep -q '^KERNEL/INIT PROBLEM' || fail "no problem line: $out"
echo "$out" | grep -q '^AFTER_LOOP forced=1 ' || fail "not forced: $out"
out=$(sh "$work/run.sh" "$work/quiet.log" $((now - 1)) "$work/block.sh" 2>&1) ||
    fail "the TIMEOUT branch ended the script: $out"
echo "$out" | grep -q '^TIMEOUT' || fail "no TIMEOUT line: $out"
echo "$out" | grep -q '^AFTER_LOOP forced=1 ' || fail "not forced: $out"
echo 'PASS a guest gone before the kill still reaches extraction and the verdict (forced=1)'
