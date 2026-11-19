#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# SwitchBoard starts and restarts under Capsule as PID 1 (capsule(8)): the
# EXTRA_SCRIPT of a vm-provider.sh reroot run (REROOT=1, PLANE_OFF=1,
# KERNEL_TIER=test, LOADER_EXTRA with kern.mac_capability.test_issuer="1").
# Cases that kill SwitchBoard also need switchboard_test_no_sigkill="1"; cases
# that pass through single-user need SINGLE_USER_SHELL=/root/vm-extra.sh, so
# that this script is also the single-user shell.  The loader variable
# sb_case selects:
#
#   plain      one SwitchBoard start with its issuer; the control tools work;
#   crash      SwitchBoard is killed after boot: the restart does not run
#              /etc/rc again, and this shell, started before the crash,
#              reaches the new SwitchBoard;
#   next       the issuer Capsule creates in advance for the next start fails
#              once (ENFILE): Capsule logs it and capsulectl status shows it;
#              after a kill, that start creates its own and runs;
#   refused    the advance create and every later one fail (ENFILE) until the
#              single-user shell clears the fault: after a kill the restart is
#              refused, PID 1 enters single-user, and when that shell exits the
#              boot that follows runs /etc/rc and reaches multi-user;
#   firstboot  PID 1's first create fails (ENFILE): SwitchBoard is never
#              started, PID 1 enters recovery, and after the single-user shell
#              the boot runs /etc/rc and reaches multi-user.
#
# The single-user and post-single-user passes are told apart by a state file,
# /var/db/sb-no-issuer.state.  Whether /etc/rc ran is read from an rc.d script
# this test installs, ordered before fsck, that appends a line to
# /var/db/sb-no-issuer.rc for every /etc/rc run once root is writable.
#
# Waits are on events, never timed re-checks: pwait(1) for a process exit and
# tail -f (kqueue, no timeout) for a log line.  None has its own deadline:
# the harness deadline (vm-provider.sh TIMEOUT_S) bounds the run.
set -u
case=$(kenv -q sb_case || echo plain)
ENFILE=23
REASON='Too many open files in system'
STATE=/var/db/sb-no-issuer.state
RCLOG=/var/db/sb-no-issuer.rc
failures=0
fail() { echo "SB_NO_ISSUER_FAIL: $*"; failures=$((failures + 1)); }
note() { echo "SB_NO_ISSUER: $*"; }
knob() { sysctl -n "$1" 2>/dev/null || echo absent; }
logs() { { dmesg -a; cat /var/log/messages /var/log/capability.log; } 2>/dev/null; }
# Messages with one pattern, each once (the console copy of a message also
# reaches /var/log/messages).  Only NOTICE and above reach the files.
count() { logs | grep -o "$1" | sort -u | wc -l | tr -d ' '; }
# Wait for the n-th message matching PATTERN in /var/log/messages.  tail -f
# sleeps in kevent until the file grows; grep stops at the n-th match.
waitlog() {	# waitlog PATTERN N
	sh -c 'tail -f -n +1 /var/log/messages 2>/dev/null |
	    { grep -q -m "$2" -- "$1"; r=$?; pkill -P $$ -x tail; exit $r; }' \
	    sh "$1" "$2"
}
sbpid() { pgrep -x switchboard | head -n 1; }
rcruns() { [ -f "$RCLOG" ] && wc -l < "$RCLOG" | tr -d ' ' || echo 0; }
showlogs() {
	logs | grep -E 'bootstrap: |inherited service fds|authority issuer|catalogue|etc-rc: |after boot' |
	    sort -u | sed 's/^/SB_NO_ISSUER_LOG: /'
}
# What the control tools can do from this (pre-existing) shell: reads
# (status) and an administrative request that changes nothing (reload).
tools() {
	capsulectl status > /tmp/sb-cs.out 2>&1; cs=$?
	switchboardctl status > /tmp/sb-ss.out 2>&1; ss=$?
	switchboardctl reload > /tmp/sb-sr.out 2>&1; sr=$?
	note "$1 capsulectl_status=$cs [$(tr '\n' ' ' < /tmp/sb-cs.out | head -c 240)]"
	note "$1 switchboardctl_status=$ss [$(head -c 120 /tmp/sb-ss.out | tr '\n' ' ')]"
	note "$1 switchboardctl_reload=$sr [$(head -c 120 /tmp/sb-sr.out | tr '\n' ' ')]"
}
# The rc.d marker: runs first in every /etc/rc, before fsck.
install_rc_marker() {
	cat > /etc/rc.d/sbnoissuer <<'EOS'
#!/bin/sh
# PROVIDE: sbnoissuer
# BEFORE: fsck
echo "rc $(date +%s)" >> /var/db/sb-no-issuer.rc 2>/dev/null
EOS
	chmod 555 /etc/rc.d/sbnoissuer
}
# Kill SwitchBoard; the kill must succeed before its exit is awaited.
kill_sb() {	# kill_sb LABEL: sets old
	old=$(sbpid)
	[ -n "$old" ] || { fail "$1: no SwitchBoard to kill"; return 1; }
	kill -KILL "$old" || { fail "$1: cannot kill SwitchBoard $old"; return 1; }
	pwait "$old"
}
# Kill SwitchBoard and wait for the restart after boot to finish its startup:
# the n-th restart's completion is the n-th "restart after boot: launched".
restart() {	# restart LABEL N
	kill_sb "$1" || return 1
	waitlog 'startup: restart after boot: launched' "$2" ||
	    { fail "$1: no restart after boot completed"; return 1; }
	note "$1: switchboard $old -> $(sbpid)"
}
# The rc.d marker, syslogd and cron as rc left them: a restart after boot
# must not run /etc/rc again.
rc_snapshot() { echo "$(rcruns) $(pgrep -x syslogd) $(pgrep -x cron)"; }
# The pass after single-user: /etc/rc ran once more and the system is up.
after_single_user() {	# after_single_user LABEL RCRUNS_BEFORE
	[ "$(rcruns)" -gt "$2" ] ||
	    fail "$1: /etc/rc did not run on the way back to multi-user"
	[ -n "$(pgrep -x syslogd)" ] || fail "$1: no syslogd (rc did not run)"
	[ "$(count 'restart after boot: /etc/rc not replayed')" = 0 ] ||
	    fail "$1: the start after single-user skipped /etc/rc"
	[ "$(count 'startup: running /etc/rc (fastboot, after single-user)')" -ge 1 ] ||
	    fail "$1: /etc/rc after single-user was not a fastboot (init passes no autoboot)"
	logs | grep -q 'inherited service fds: .* authority=8 discovery=9' ||
	    fail "$1: SwitchBoard has no issuer or no boot discovery route"
	tools "$1"
	[ "$cs$ss$sr" = 000 ] || fail "$1: a control tool failed"
}

note "pass ${VM_REROOT:-single-user}, case $case, state $(cat $STATE 2>/dev/null || echo none), pid1=$(ps -o comm= -p 1 | tr -d ' ')"

# --- single-user: this script is the shell PID 1 started (no VM_REROOT).
if [ -z "${VM_REROOT:-}" ]; then
	[ "$(ps -o comm= -p 1 | tr -d ' ')" = capsule ] || fail 'PID 1 is not capsule'
	case $case:$(cat $STATE 2>/dev/null) in
	refused:killed)
		logs | grep -q "no authority issuer: $REASON; entering single-user" ||
		    fail 'refused: Capsule did not log why it entered single-user' ;;
	firstboot:)
		logs | grep -q "no authority issuer: $REASON; switchboard not started; entering recovery" ||
		    fail 'firstboot: Capsule did not log why it entered recovery' ;;
	*)	fail "single-user in case $case, state $(cat $STATE 2>/dev/null)" ;;
	esac
	# Recovery after the reroot leaves root read-only, as single-user does.
	mount -u -o rw / || fail 'cannot mount root read-write'
	# Clear the fault so the boot that follows has its issuer.
	sysctl debug.mac_capability.test_issuer_fail_init=0 >/dev/null ||
	    fail 'cannot clear fail_init'
	echo "single $(rcruns)" > $STATE
	note "single-user: failures=$failures; leaving single-user"
	[ "$failures" = 0 ] && echo SB_NO_ISSUER_SINGLE_PASS
	exit 0
fi

case ${VM_REROOT:-} in
before)
	[ "$(knob kern.mac_capability.test_issuer)" = 1 ] || fail 'test_issuer is not 1'
	rm -f $STATE $RCLOG
	install_rc_marker
	# count 0: every create fails until cleared (a kernel before K2 takes
	# a large count instead).
	until_cleared() {
		sysctl debug.mac_capability.test_issuer_fail_init_count=0 ||
		    sysctl debug.mac_capability.test_issuer_fail_init_count=1000
	}
	case $case in
	plain|crash) ;;
	next)
		sysctl debug.mac_capability.test_issuer_fail_init_skip=1 &&
		    sysctl debug.mac_capability.test_issuer_fail_init_count=1 &&
		    sysctl debug.mac_capability.test_issuer_fail_init=$ENFILE ||
		    fail 'cannot arm fail_init' ;;
	refused)
		sysctl debug.mac_capability.test_issuer_fail_init_skip=1 &&
		    until_cleared &&
		    sysctl debug.mac_capability.test_issuer_fail_init=$ENFILE ||
		    fail 'cannot arm fail_init' ;;
	firstboot)
		sysctl debug.mac_capability.test_issuer_fail_init_count=1 &&
		    sysctl debug.mac_capability.test_issuer_fail_init=$ENFILE ||
		    fail 'cannot arm fail_init' ;;
	*) fail "unknown sb_case $case" ;;
	esac
	[ "$failures" = 0 ] && echo SB_NO_ISSUER_BEFORE_PASS
	exit $((failures != 0))
	;;
after) ;;
*)
	fail "VM_REROOT=${VM_REROOT:-unset}: run this with vm-provider.sh REROOT=1"
	exit 1 ;;
esac

# --- after the reroot, and again after a return from single-user.
[ "$(ps -o comm= -p 1 | tr -d ' ')" = capsule ] || fail 'PID 1 is not capsule'
state=$(cat $STATE 2>/dev/null || true)
case $state in
single\ *)
	after_single_user "$case-returned" "${state#single }"
	rm -f $STATE /etc/rc.d/sbnoissuer
	note "fail_init_now=$(knob debug.mac_capability.test_issuer_fail_init)"
	[ "$failures" = 0 ] && echo SB_NO_ISSUER_AFTER_PASS
	exit $((failures != 0)) ;;
'') ;;
*)	fail "after the reroot in state $state"; exit 1 ;;
esac
[ "$case" != firstboot ] || { fail 'firstboot: the boot went on without an issuer'; exit 1; }
starts=$(count 'bootstrap: started switchboard pid [0-9]*')
aborts=$(count 'switchboard [0-9]* - - application catalogue init failed')
sched=$(count 'bootstrap: scheduling restart in [0-9]*s')
next_missing=$(count "no authority issuer for the next switchboard start: $REASON")
note "starts=$starts catalogue_aborts=$aborts restart_scheduled=$sched next_missing=$next_missing rc_runs=$(rcruns)"
logs | grep -q 'inherited service fds: .* authority=8 discovery=9' ||
    fail 'SwitchBoard does not report its issuer and the boot discovery route'
[ "$aborts$sched" = 00 ] || fail 'SwitchBoard aborted or was restarted during boot'
tools boot
[ "$cs$ss$sr" = 000 ] || fail 'boot: a control tool failed'

case $case in
plain)
	[ "$next_missing" = 0 ] || fail 'plain: the next issuer is missing'
	! grep -q 'next authority issuer' /tmp/sb-cs.out ||
	    fail 'plain: capsulectl status reports a missing next issuer'
	;;
crash)
	before=$(rc_snapshot)
	restart crash 1
	showlogs
	[ "$(rc_snapshot)" = "$before" ] ||
	    fail "crash: /etc/rc ran again (rc runs, syslogd, cron: $before -> $(rc_snapshot))"
	[ "$(count 'restart after boot: /etc/rc not replayed')" = 1 ] ||
	    fail 'crash: SwitchBoard did not log the skipped /etc/rc'
	tools crash
	[ "$cs$ss$sr" = 000 ] || fail 'crash: a control tool failed from a shell started before the crash'
	;;
next)
	[ "$next_missing" = 1 ] || fail 'next: Capsule did not log the missing next issuer'
	grep -q "next authority issuer: none ($REASON)" /tmp/sb-cs.out ||
	    fail 'next: capsulectl status does not report the missing next issuer'
	[ "$(knob debug.mac_capability.test_issuer_fail_init)" = 0 ] ||
	    fail 'next: the fault did not clear after one failure'
	before=$(rc_snapshot)
	restart next 1
	showlogs
	[ "$(rc_snapshot)" = "$before" ] || fail 'next: /etc/rc ran again'
	[ "$(count "no authority issuer: $REASON")" = 0 ] ||
	    fail 'next: the restart was refused'
	tools next-restarted
	[ "$cs$ss$sr" = 000 ] || fail 'next: a control tool failed after the restart'
	! grep -q 'next authority issuer' /tmp/sb-cs.out ||
	    fail 'next: the restart still reports a missing next issuer'
	;;
refused)
	[ "$next_missing" = 1 ] || fail 'refused: Capsule did not log the missing next issuer'
	showlogs
	[ "$failures" = 0 ] || exit 1
	# The login after single-user starts this script's after pass again:
	# give it the saved results back, as the reroot did.
	tar -cf /var/db/vm-provider-reroot.tar -C /tmp kyua-results
	echo killed > $STATE
	note 'refused: killing SwitchBoard; PID 1 must enter single-user'
	kill_sb refused || exit 1
	# Single-user ends this shell; PID 1 never exits, so this waits for that.
	pwait 1
	exit 1
	;;
esac
note "fail_init_now=$(knob debug.mac_capability.test_issuer_fail_init) count_now=$(knob debug.mac_capability.test_issuer_fail_init_count) skip_now=$(knob debug.mac_capability.test_issuer_fail_init_skip)"
rm -f /etc/rc.d/sbnoissuer
[ "$failures" = 0 ] && echo SB_NO_ISSUER_AFTER_PASS
exit $((failures != 0))
