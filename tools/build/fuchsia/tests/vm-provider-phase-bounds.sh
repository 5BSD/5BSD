#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-provider.sh phase bounds, on the actual guest-script blocks with stub
# commands (no guest):
#  1. a step that blocks past the run deadline is reported
#     PHASE_STEP_EXPIRED with its processes' stacks, all its processes are
#     killed (an orphaned grandchild too: timeout(1) is the reaper), the
#     results are exported, and later steps are skipped, also when the
#     step ran in a command substitution or a pipeline;
#  2. the lifecycle dependency check: a stopped dependency (no restart
#     scheduled) gives PHASE_DEPENDENCY_STOPPED with a dump, a failed status
#     PHASE_DEPENDENCY_UNKNOWN, a restart-pending one lets the phase run;
#     session progress is geometric;
#  3. the gate wait: ends on a SwitchBoard unit line, is not woken by the
#     line every status request logs, ends at once for a unit that will not
#     run by itself, and expires at the run deadline otherwise;
#  4. the host verdict is not clean after any of those lines;
#  5. vm-monitor --progress records host-load samples and progress lines.
# Every wait in it ends on an event or at a deadline the case sets.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
bgpids=
trap 'for p in $bgpids; do kill "$p" 2>/dev/null || true; done; rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; [ ! -f "$work/out" ] || cat "$work/out"; exit 1; }
vp=$root/vm-provider.sh
guest() { sed -n '/^cat >> "$x\/kyua-planeon.sh" <<.EOF.$/,/^EOF$/p' "$vp" | sed '1d;$d'; }
block() { guest | sed -n "/^# --- $1 (/,/^# --- end of the $1\$/p"; }

# Stub commands.  Each records its call.  switchboardctl answers from a
# file and logs its control connection, as SwitchBoard does for each
# status request.
stub=$work/bin
mkdir -p "$stub" "$work/R"
for c in BSDTimectl logger BSDPowerctl sysctlcmpctl; do
	printf '#!/bin/sh\necho "%s $*" >> "%s/calls"\n' "$c" "$work" > "$stub/$c"
done
printf '#!/bin/sh\necho "procstat $*" >> "%s/calls"\necho "STACK-OF $2"\n' \
    "$work" > "$stub/procstat"
printf '#!/bin/sh\necho "geom $*" >> "%s/calls"\necho "   ident: kyua-results"\n' \
    "$work" > "$stub/geom"
cat > "$stub/switchboardctl" <<EOF
#!/bin/sh
echo "switchboardctl \$*" >> "$work/calls"
echo "Nov 22 00:00:00 guest switchboard[2]: capability control connection adopted (admin)" >> "$work/daemon.log"
cat "$work/status"
exit \$(cat "$work/status.rc" 2>/dev/null || echo 0)
EOF
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
# guest_sh DEADLINE_IN SCRIPT...: the helpers and SCRIPT as the guest runs
# them; PHASE lines go to stderr.
guest_sh() {
	local in=$1 rc=0; shift
	env PATH="$stub:$PATH" R="$work/R" PHASE_CONSOLE=/dev/stderr \
	    RUN_DEADLINE=$(( $(date +%s) + in )) \
	    REQUIRE_UNITS="system.Time/bsdtime system.Log/bsdlog" \
	    sh -c '. "$1"; shift; for f; do . "$f"; done' sh "$work/helpers.sh" "$@" 2>&1 |
	    tee "$work/raw"
	# A shell or awk error in a block is a failure, whatever else it printed.
	! grep -Eq 'syntax error|illegal statement|not found|bad substitution' "$work/raw" ||
	    { echo "error in a guest block:"; cat "$work/raw"; return 1; }
}
# Leave one second before the reserve: the next step expires after it.
tight='PHASE_RESERVE=$(( RUN_DEADLINE - $(date +%s) - 1 ))'

# 1. Expiry.  The step runs sleep (which waits on no event at all) and
# leaves an orphaned grandchild; both must be killed.
cat > "$work/expire.sh" <<EOF
$tight
run_step blocker sh -c '(sleep 3601 &); exec sleep 3601' && echo "blocker returned 0"
run_step later true || echo "later rc=\$?"
EOF
rm -f "$work/calls" "$work/results.tar"
guest_sh 30 "$work/expire.sh" > "$work/out" 2>&1 || fail "expiry script failed"
grep -q '^PHASE_STEP blocker begin' "$work/out" || fail 'no begin line'
grep -q '^PHASE_STEP_EXPIRED step=blocker elapsed=' "$work/out" || fail 'no PHASE_STEP_EXPIRED'
grep -q '^PHASE_DUMP_BEGIN step=blocker' "$work/out" || fail 'no dump'
[ "$(grep -c '^--- procstat -kk [0-9]* (sleep)$' "$work/out")" = 2 ] ||
    fail "the dump does not show both sleeps"
grep -q '^--- procstat -kk [0-9]* (timeout)$' "$work/out" || fail 'the dump does not show the reaper'
grep -q '^PHASE_EXPIRY_RESULTS_SAVED' "$work/out" || fail 'results not saved on expiry'
tar -tf "$work/results.tar" > /dev/null 2>&1 || fail 'the export is not a tar'
grep -q '^PHASE_DUMP_END step=blocker' "$work/out" || fail 'the dump did not end'
grep -q '^PHASE_STEP later skipped: the run deadline was reached' "$work/out" || fail 'later step not skipped'
grep -q '^later rc=124' "$work/out" || fail 'skipped step did not return 124'
! grep -q 'blocker returned 0' "$work/out" || fail 'expired step returned 0'
! pgrep -f '^sleep 3601$' > /dev/null || fail 'a process of the expired step survived'
[ -e "$work/R/phase-expired" ] || fail 'the expiry was not recorded'
# In a command substitution and in a pipeline, as the guest runs get1 and
# kyua: the expiry outlives the subshell.
for form in 'v=$(run_step sub sleep 3601)' '{ run_step sub sleep 3601; } | cat'; do
	printf '%s\n%s\n%s\n' "$tight" "$form || true" 'run_step after true || echo "after rc=$?"' \
	    > "$work/sub.sh"
	guest_sh 30 "$work/sub.sh" > "$work/out" 2>&1 || fail "subshell script failed: $form"
	grep -q '^PHASE_STEP_EXPIRED step=sub ' "$work/out" || fail "no expiry in: $form"
	grep -q '^PHASE_STEP after skipped' "$work/out" || fail "expiry lost in: $form"
done
echo 'PASS expiry: stacks, every process killed, results exported, later steps skipped (also from subshells)'

# 2. The dependency check.
log_stopped='  system.Log/bsdlog    stopped  restart=on-failure mgmt=core restarts=10'
log_pending='  system.Log/bsdlog    stopped  restart=on-failure mgmt=core restarts=2 restart-pending'
run_lifecycle() {   # STATUS_LINES GATE_RC
	printf '%s\n' "$1" > "$work/R/switchboard-status.txt"
	cp "$work/R/switchboard-status.txt" "$work/status"
	printf 'gate_status_rc=%s\n' "$2" > "$work/pre.sh"
	rm -f "$work/calls"
	guest_sh 3600 "$work/pre.sh" "$work/lifecycle.sh" > "$work/out" 2>&1 ||
	    fail 'lifecycle script failed'
}
run_lifecycle "$(running_status | grep -v bsdlog; echo "$log_stopped")" 0
grep -q '^PHASE_DEPENDENCY_STOPPED unit=system.Log/bsdlog state=stopped restarts=10$' "$work/out" ||
    fail 'no PHASE_DEPENDENCY_STOPPED for bsdlog'
grep -q '^PHASE_DUMP_BEGIN step=dependency' "$work/out" || fail 'no dump for the stopped dependency'
grep -q '^BSDTIME_LIFECYCLE_FAIL$' "$work/out" || fail 'lifecycle not failed'
! grep -q BSDTimectl "$work/calls" 2>/dev/null || fail 'the phase ran with a stopped dependency'
run_lifecycle "switchboardctl: cannot reach switchboard" 69
grep -q '^PHASE_DEPENDENCY_UNKNOWN reason=status-failed rc=69' "$work/out" || fail 'no PHASE_DEPENDENCY_UNKNOWN'
! grep -q PHASE_DEPENDENCY_STOPPED "$work/out" || fail 'a failed status named a stopped unit'
run_lifecycle "$(running_status | grep -v bsdlog; echo "$log_pending")" 0
! grep -q '^PHASE_DEPENDENCY' "$work/out" || fail 'a restart-pending dependency stopped the phase'
grep -q 'BSDTimectl get' "$work/calls" || fail 'the phase did not run'
run_lifecycle "$(running_status)" 0
grep -q 'BSDTimectl get' "$work/calls" || fail 'the phase did not run'
[ "$(grep -c '^BSDTIME_SESSIONS_PROGRESS=' "$work/out")" = 9 ] || fail 'progress lines not geometric'
for n in 1 2 4 8 16 32 64 128 200; do
	grep -q "^BSDTIME_SESSIONS_PROGRESS=$n " "$work/out" || fail "no session progress at $n"
done
grep -q '^PHASE_STEP sessions end status=0 elapsed=' "$work/out" || fail 'no step end line'
echo 'PASS dependency: stopped (dump) and unknown end the phase, restart-pending does not; progress is geometric'

# 3. The gate wait.
rm -f "$work/status.rc"
# (a) The python wait alone: a line SwitchBoard logs for each status request,
# appended after the snapshot, does not end it; a unit line does.
sed -n '/^gate_log_wait() {/,/^}/p' "$work/gate.sh" > "$work/lw.sh"
printf 'GATE_LOGS="%s %s"\n' "$work/messages" "$work/daemon.log" >> "$work/lw.sh"
sizes="$(stat -f %z "$work/messages")
$(stat -f %z "$work/daemon.log")"
echo "Nov 22 00:00:01 guest switchboard[2]: capability control connection adopted (admin)" >> "$work/daemon.log"
rc=0; sh -c '. "$1"; gate_sizes=$2; gate_log_wait 2' sh "$work/lw.sh" "$sizes" || rc=$?
[ "$rc" = 124 ] || fail "the wait ended on a status request's own log line (rc $rc)"
echo "Nov 22 00:00:02 guest switchboard[2]: service system.Time/bsdtime: exec confirmed (pid 9)" >> "$work/daemon.log"
rc=0; sh -c '. "$1"; gate_sizes=$2; gate_log_wait 3600' sh "$work/lw.sh" "$sizes" || rc=$?
[ "$rc" = 0 ] || fail "the wait did not end on a unit line (rc $rc)"
# (b) Converges when the unit runs and its line is logged.
: > "$work/calls"
{ echo '  system.Time/bsdtime  starting'; echo '  system.Log/bsdlog running'; } > "$work/status"
guest_sh 3600 "$work/gate.sh" > "$work/out" 2>&1 &
gpid=$!; bgpids="$bgpids $gpid"
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
echo "Nov 22 00:00:03 guest switchboard[2]: service system.Time/bsdtime: exec confirmed (pid 10)" >> "$work/daemon.log"
wait "$gpid" || fail 'gate script failed'
grep -q '^PHASE_STEP gate-convergence end' "$work/out" || fail 'gate did not end'
! grep -q PHASE_STEP_EXPIRED "$work/out" || fail 'gate expired instead of converging'
# (c) A unit that will not run by itself ends the wait at once: stopped
# without a scheduled restart, done, absent.
echo 'echo "GATE_RESULT missing=[$missing] waiting=[$gate_waiting]"' > "$work/gate-result.sh"
for st in '  system.Time/bsdtime  stopped restarts=10' '  system.Time/bsdtime  done' ''; do
	{ [ -z "$st" ] || echo "$st"; echo '  system.Log/bsdlog running'; } > "$work/status"
	guest_sh 3600 "$work/gate.sh" "$work/gate-result.sh" > "$work/out" 2>&1 || fail 'gate script failed'
	grep -q '^PHASE_STEP gate-convergence end' "$work/out" || fail "gate did not end for: $st"
	! grep -q PHASE_STEP_EXPIRED "$work/out" || fail "gate waited for: $st"
	grep -qx 'GATE_RESULT missing=\[ system.Time/bsdtime\] waiting=\[\]' "$work/out" ||
	    fail "gate did not judge the unit missing and not waited for: $st"
done
# (d) A restart-pending unit is waited for, to the run deadline here.
{ echo '  system.Time/bsdtime  stopped restarts=2 restart-pending'; echo '  system.Log/bsdlog running'; } > "$work/status"
printf '%s\n. "%s"\n' "$tight" "$work/gate.sh" > "$work/gate-expire.sh"
guest_sh 30 "$work/gate-expire.sh" > "$work/out" 2>&1 || fail 'gate script failed'
grep -q '^PHASE_STEP_EXPIRED step=gate-convergence .*waiting for: system.Time/bsdtime' "$work/out" ||
    fail 'gate did not wait for the restart-pending unit until the deadline'
grep -q '^PHASE_DUMP_BEGIN step=gate-convergence' "$work/out" || fail 'no gate dump'
echo 'PASS gate: ends on a unit line, not on status requests, ends for units that will not run, expires at the deadline'

# 4. The host verdict.
sed -n '/^# --- phase verdict (/,/^# --- end of the phase verdict$/p' "$vp" > "$work/verdict.sh"
grep -q verdict=VM_NOT_CLEAN "$work/verdict.sh" || fail 'no phase-verdict block'
for line in 'PHASE_STEP_EXPIRED step=kyua elapsed=9' \
    'PHASE_DEPENDENCY_STOPPED unit=system.Log/bsdlog state=stopped restarts=3' \
    'PHASE_DEPENDENCY_UNKNOWN reason=status-failed rc=69: x' \
    'PHASE_STEP get1 end status=0 elapsed=1'; do
	printf '%s\r\n' "$line" > "$work/log"
	v=$(log=$work/log sh -c 'verdict=VM_CLEAN; . "$1"; echo $verdict' sh "$work/verdict.sh")
	case $line in
	PHASE_STEP_EXPIRED*|PHASE_DEPENDENCY_*) [ "$v" = VM_NOT_CLEAN ] || fail "clean with: $line" ;;
	*) [ "$v" = VM_CLEAN ] || fail "not clean with: $line" ;;
	esac
done
echo 'PASS verdict: PHASE_STEP_EXPIRED and PHASE_DEPENDENCY_* are never clean'

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
[ "$(grep -c '^LOAD [0-9]* [0-9.]* [0-9.]* [0-9.]* ncpu=[0-9]* qemus=[0-9-]* slots=[0-9-]* heavy_build_lockf=[0-9-]*$' "$work/progress.txt")" -ge 4 ] ||
    fail 'host-load samples missing (start, two lines, end)'
echo 'PASS monitor: progress lines and host-load samples at start, each progress line and the end'
