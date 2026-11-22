#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-provider.sh phase bounds, on the actual guest-script blocks with stub
# commands (no guest):
#  1. a step that blocks past the run deadline is reported
#     PHASE_STEP_EXPIRED with the dump (its own process's stack included),
#     the results are still exported, and later steps are skipped;
#  2. a stopped lifecycle dependency gives PHASE_DEPENDENCY_STOPPED and
#     BSDTIME_LIFECYCLE_FAIL without running the phase's commands;
#  3. the gate wait ends on a log write that comes with convergence, ends at
#     once for a unit the circuit breaker disabled, and expires at the run
#     deadline otherwise;
#  4. the host verdict is not clean after either line;
#  5. vm-monitor --progress records host-load samples and progress lines.
# Every wait in it ends on an event or on the deadline the case sets.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
bgpids=
trap 'for p in $bgpids; do kill "$p" 2>/dev/null || true; done; rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; [ ! -f "$work/out" ] || cat "$work/out"; exit 1; }
vp=$root/vm-provider.sh
guest() { sed -n '/^cat >> "$x\/kyua-planeon.sh" <<.EOF.$/,/^EOF$/p' "$vp" | sed '1d;$d'; }
block() { guest | sed -n "/^# --- $1 (/,/^# --- end of the $1\$/p"; }

# Stub commands.  Each records its call; switchboardctl answers from a file.
stub=$work/bin
mkdir -p "$stub" "$work/R"
for c in procstat geom BSDTimectl logger BSDPowerctl sysctlcmpctl; do
	printf '#!/bin/sh\necho "%s $*" >> "%s/calls"\n' "$c" "$work" > "$stub/$c"
done
printf '#!/bin/sh\necho "procstat $*" >> "%s/calls"\necho "STACK-OF $2"\n' \
    "$work" > "$stub/procstat"
printf '#!/bin/sh\necho "geom $*" >> "%s/calls"\necho "   ident: kyua-results"\n' \
    "$work" > "$stub/geom"
printf '#!/bin/sh\necho "switchboardctl $*" >> "%s/calls"\ncat "%s/status"\n' \
    "$work" "$work" > "$stub/switchboardctl"
chmod +x "$stub"/*
: > "$work/messages"; : > "$work/daemon.log"
# The blocks, with the guest's paths moved into the work directory.
paths() {
	sed -e "s|/var/log/messages|$work/messages|g" \
	    -e "s|/var/log/daemon.log|$work/daemon.log|g" \
	    -e "s|/dev/vtbd1|$work/results.tar|g" \
	    -e "s|-C /tmp kyua-results|-C $work R|g"
}
block 'phase bounds' | paths > "$work/helpers.sh"
grep -q '^run_step()' "$work/helpers.sh" || fail 'no phase-bounds block'
block 'gate wait' | paths > "$work/gate.sh"
grep -q '^gate_check()' "$work/gate.sh" || fail 'no gate-wait block'
block 'lifecycle phase' | paths > "$work/lifecycle.sh"
grep -q '^phase_deps_stopped()' "$work/lifecycle.sh" || fail 'no lifecycle block'
running_status() {
	for u in system.Time/bsdtime system.Log/bsdlog system.Power/bsdpower system.Sysctl/bsdsysctl; do
		echo "  $u running  pid 1 restart=on-failure mgmt=core"
	done
}
# guest_sh DEADLINE_IN SCRIPT...: run the helpers and SCRIPT as the guest does.
guest_sh() {
	local in=$1; shift
	env PATH="$stub:$PATH" R="$work/R" RUN_DEADLINE=$(( $(date +%s) + in )) \
	    REQUIRE_UNITS="system.Time/bsdtime system.Log/bsdlog" \
	    sh -c '. "$1"; shift; for f; do . "$f"; done' sh "$work/helpers.sh" "$@"
}

# 1. Expiry.  The run deadline is the reserve plus one second away, so the
# blocking step (sleep, which waits on no event at all) runs it out.
cat > "$work/expire.sh" <<'EOF'
PHASE_RESERVE=$(( RUN_DEADLINE - $(date +%s) - 1 ))
run_step blocker sleep 3600 && echo "blocker returned 0"
echo "rc after expiry"
run_step later true || echo "later rc=$?"
EOF
rm -f "$work/calls" "$work/results.tar"
guest_sh 30 "$work/expire.sh" > "$work/out" 2>&1 || fail "expiry script failed"
grep -q '^PHASE_STEP blocker begin' "$work/out" || fail 'no begin line'
grep -q '^PHASE_STEP_EXPIRED step=blocker elapsed=' "$work/out" || fail 'no PHASE_STEP_EXPIRED'
grep -q '^PHASE_DUMP_BEGIN step=blocker' "$work/out" || fail 'no dump'
spid=$(sed -n 's/^--- procstat -kk \([0-9]*\) (sleep)$/\1/p' "$work/out" | head -n 1)
[ -n "$spid" ] || fail "the dump does not show the blocked step's process"
grep -q "^STACK-OF $spid\$" "$work/out" || fail 'no stack of the blocked step'
grep -q '^PHASE_EXPIRY_RESULTS_SAVED' "$work/out" || fail 'results not saved on expiry'
tar -tf "$work/results.tar" > /dev/null 2>&1 || fail 'the export is not a tar'
grep -q '^PHASE_STEP later skipped: the run deadline was reached' "$work/out" || fail 'later step not skipped'
grep -q '^later rc=124' "$work/out" || fail 'skipped step did not return 124'
! grep -q 'blocker returned 0' "$work/out" || fail 'expired step returned 0'
! kill -0 "$spid" 2>/dev/null || fail 'the blocked step was not killed'
echo 'PASS expiry: PHASE_STEP_EXPIRED, dump with the step stack, results exported, later steps skipped'

# 2. A stopped dependency ends the lifecycle phase without running it.
{ running_status | grep -v bsdlog
  echo '  system.Log/bsdlog    stopped  restart=on-failure mgmt=core restarts=10'
} > "$work/R/switchboard-status.txt"
cp "$work/R/switchboard-status.txt" "$work/status"
rm -f "$work/calls"
guest_sh 3600 "$work/lifecycle.sh" > "$work/out" 2>&1 || fail 'lifecycle script failed'
grep -q '^PHASE_DEPENDENCY_STOPPED unit=system.Log/bsdlog state=stopped restarts=10$' "$work/out" ||
    fail 'no PHASE_DEPENDENCY_STOPPED for bsdlog'
grep -q '^BSDTIME_LIFECYCLE_FAIL$' "$work/out" || fail 'lifecycle not failed'
! grep -q BSDTimectl "$work/calls" 2>/dev/null || fail 'the phase ran with a stopped dependency'
# And all running: the phase runs (stub commands), and a unit gone after the
# refused restart ends it there.
running_status > "$work/R/switchboard-status.txt"
cp "$work/R/switchboard-status.txt" "$work/status"
rm -f "$work/calls"
guest_sh 3600 "$work/lifecycle.sh" > "$work/out" 2>&1 || fail 'lifecycle script failed'
grep -q 'BSDTimectl get' "$work/calls" || fail 'the phase did not run'
grep -q '^BSDTIME_SESSIONS_PROGRESS=1 ' "$work/out" || fail 'no session progress at 1'
grep -q '^BSDTIME_SESSIONS_PROGRESS=128 ' "$work/out" || fail 'no session progress at 128'
grep -q '^BSDTIME_SESSIONS_PROGRESS=200 ' "$work/out" || fail 'no session progress at the last'
[ "$(grep -c '^BSDTIME_SESSIONS_PROGRESS=' "$work/out")" = 9 ] || fail 'progress lines not geometric'
grep -q '^PHASE_STEP sessions end status=0 elapsed=' "$work/out" || fail 'no step end line'
echo 'PASS dependency: a stopped dependency stops the phase with PHASE_DEPENDENCY_STOPPED; progress is geometric'

# 3. Gate wait.  (a) Converges on the log write that comes with it.
: > "$work/calls"
{ echo '  system.Time/bsdtime  starting'; echo '  system.Log/bsdlog running'; } > "$work/status"
guest_sh 3600 "$work/gate.sh" > "$work/out" 2>&1 &
gpid=$!; bgpids="$bgpids $gpid"
# Change the state, then write the log, once the gate has read the status.
python3.12 -I - "$work/calls" <<'EOF'
import os, select, sys
p = sys.argv[1]
kq = select.kqueue()
fd = os.open(p, os.O_RDONLY)
kq.control([select.kevent(fd, select.KQ_FILTER_VNODE,
    select.KQ_EV_ADD | select.KQ_EV_CLEAR,
    select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND)], 0)
while b"switchboardctl status" not in open(p, "rb").read():
    kq.control(None, 1, None)
EOF
running_status > "$work/status"
echo "service system.Time/bsdtime: started" >> "$work/daemon.log"
wait "$gpid" || fail 'gate script failed'
grep -q '^PHASE_STEP gate-convergence end' "$work/out" || fail 'gate did not end'
! grep -q PHASE_STEP_EXPIRED "$work/out" || fail 'gate expired instead of converging'
# (b) A disabled unit ends the wait at once.
{ echo '  system.Time/bsdtime  stopped restarts=10'; echo '  system.Log/bsdlog running'; } > "$work/status"
echo "switchboard[2]: service system.Time/bsdtime: failed 10 times, disabling" >> "$work/messages"
guest_sh 3600 "$work/gate.sh" > "$work/out" 2>&1 || fail 'gate script failed'
grep -q '^PHASE_STEP gate-convergence end' "$work/out" || fail 'gate did not end for a disabled unit'
! grep -q PHASE_STEP_EXPIRED "$work/out" || fail 'gate waited for a disabled unit'
: > "$work/messages"
# (c) No convergence: the wait expires at the run deadline, with the dump.
{ echo '  system.Time/bsdtime  starting'; echo '  system.Log/bsdlog running'; } > "$work/status"
printf 'PHASE_RESERVE=$(( RUN_DEADLINE - $(date +%%s) - 1 ))\n. "%s"\n' "$work/gate.sh" > "$work/gate-expire.sh"
guest_sh 30 "$work/gate-expire.sh" > "$work/out" 2>&1 || fail 'gate script failed'
grep -q '^PHASE_STEP_EXPIRED step=gate-convergence .*waiting for: system.Time/bsdtime' "$work/out" ||
    fail 'gate did not expire'
grep -q '^PHASE_DUMP_BEGIN step=gate-convergence' "$work/out" || fail 'no gate dump'
echo 'PASS gate: converges on a log write, ends for a disabled unit, expires at the deadline'

# 4. The host verdict.
sed -n '/^# --- phase verdict (/,/^# --- end of the phase verdict$/p' "$vp" > "$work/verdict.sh"
grep -q verdict=VM_NOT_CLEAN "$work/verdict.sh" || fail 'no phase-verdict block'
for line in 'PHASE_STEP_EXPIRED step=kyua elapsed=9' 'PHASE_DEPENDENCY_STOPPED unit=system.Log/bsdlog state=stopped restarts=3' 'PHASE_STEP get1 end status=0 elapsed=1'; do
	printf '%s\r\n' "$line" > "$work/log"
	v=$(log=$work/log sh -c 'verdict=VM_CLEAN; . "$1"; echo $verdict' sh "$work/verdict.sh")
	case $line in
	PHASE_STEP_EXPIRED*|PHASE_DEPENDENCY_STOPPED*) [ "$v" = VM_NOT_CLEAN ] || fail "clean with: $line" ;;
	*) [ "$v" = VM_CLEAN ] || fail "not clean with: $line" ;;
	esac
done
echo 'PASS verdict: PHASE_STEP_EXPIRED and PHASE_DEPENDENCY_STOPPED are never clean'

# 5. vm-monitor progress and host load.  The watched "QEMU" is a sleep the
# case ends itself.
sleep 3600 &
qpid=$!; bgpids="$bgpids $qpid"
: > "$work/serial"
: > "$work/progress.txt"
python3.12 -I "$root/vm-monitor.py" --pid "$qpid" --log "$work/serial" \
    --deadline $(( $(date +%s) + 3600 )) --fatal 'panic:' \
    --known "$root/known-lor.txt" --progress "$work/progress.txt" > "$work/mon.out" 2>&1 &
mpid=$!; bgpids="$bgpids $mpid"
printf 'boot noise\r\nPHASE_STEP get1 begin\r\nBSDTIME_SESSIONS_PROGRESS=4 at=1\r\n' >> "$work/serial"
# The monitor reads the log on its write events: wait for it to record them
# (an event on progress.txt), then end the "QEMU".
python3.12 -I - "$work/progress.txt" <<'EOF'
import os, select, sys
p = sys.argv[1]
kq = select.kqueue()
fd = os.open(p, os.O_RDONLY)
kq.control([select.kevent(fd, select.KQ_FILTER_VNODE,
    select.KQ_EV_ADD | select.KQ_EV_CLEAR, select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND)], 0)
while b"BSDTIME_SESSIONS_PROGRESS=4" not in open(p, "rb").read():
    kq.control(None, 1, None)
EOF
kill "$qpid"
wait "$mpid" || fail "vm-monitor exited $?"
grep -q '^PROGRESS [0-9]* PHASE_STEP get1 begin$' "$work/progress.txt" || fail 'no PROGRESS line'
grep -q '^PROGRESS [0-9]* BSDTIME_SESSIONS_PROGRESS=4 at=1$' "$work/progress.txt" || fail 'no session PROGRESS line'
! grep -q 'boot noise' "$work/progress.txt" || fail 'a non-progress line was recorded'
[ "$(grep -c '^LOAD [0-9]* [0-9.]* [0-9.]* [0-9.]* ncpu=[0-9]* qemus=[0-9-]* heavy_build=\(held\|free\)$' "$work/progress.txt")" -ge 4 ] ||
    fail 'host-load samples missing (start, two lines, end)'
echo 'PASS monitor: progress lines and host-load samples at start, each progress line and the end'
