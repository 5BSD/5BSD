#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# SwitchBoard starts and restarts under Capsule as PID 1 (capsule(8)): the
# EXTRA_SCRIPT of a vm-provider.sh reroot run (REROOT=1, PLANE_OFF=1,
# KERNEL_TIER=test, LOADER_EXTRA with kern.mac_capability.test_issuer="1").
# Cases that kill SwitchBoard also need switchboard_test_no_sigkill="1".  The
# loader variable sb_case selects:
#
#   plain      one SwitchBoard start with its issuer; the control tools work;
#   crash      SwitchBoard is killed after boot: the restart does not replay
#              /etc/rc, and this shell, started before the crash, reaches the
#              new SwitchBoard;
#   next       the issuer Capsule creates in advance for the next start fails
#              (EMFILE, skip 1, count 1): Capsule logs it and capsulectl status
#              shows it; after a kill, that start creates its own and runs;
#   refused    as next, but every later create fails (count 1000): after a
#              kill the start has no issuer, and PID 1 enters single-user.
#              This script cannot report past that point; the host checks the
#              serial log for "no authority issuer: Too many open files" and
#              "entering single-user";
#   firstboot  PID 1's first create fails (EMFILE): SwitchBoard is never
#              started and PID 1 enters recovery.  This script never runs
#              after the reroot; the host checks the serial log for
#              "no authority issuer: Too many open files".
#
# Waits are on events, never timed re-checks: pwait(1) for a process exit, and
# for a log line tail -F (kqueue) on /var/log/messages under timeout(1), which
# is only the deadline.
set -u
case=$(kenv -q sb_case || echo plain)
EMFILE=24
failures=0
fail() { echo "SB_NO_ISSUER_FAIL: $*"; failures=$((failures + 1)); }
note() { echo "SB_NO_ISSUER: $*"; }
knob() { sysctl -n "$1" 2>/dev/null || echo absent; }
logs() { { dmesg -a; cat /var/log/messages /var/log/capability.log; } 2>/dev/null; }
# Messages with one pattern, each once (the console copy of a message also
# reaches /var/log/messages).  Only NOTICE and above reach the files.
count() { logs | grep -o "$1" | sort -u | wc -l | tr -d ' '; }
# Wait for the n-th message matching PATTERN in /var/log/messages; SECONDS is
# the deadline.  tail -F is woken by kqueue; grep stops at the n-th match.
waitlog() {	# waitlog PATTERN N SECONDS
	timeout "$3" sh -c 'tail -F -n +1 /var/log/messages 2>/dev/null |
	    { grep -q -m "$2" -- "$1"; r=$?; pkill -P $$ -x tail; exit $r; }' \
	    sh "$1" "$2"
}
sbpid() { pgrep -x switchboard | head -n 1; }
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
# Kill SwitchBoard and wait for the restart after boot to finish its startup:
# the n-th restart's completion is the n-th "restart after boot: launched".
restart() {	# restart LABEL N
	old=$(sbpid)
	[ -n "$old" ] || { fail "$1: no SwitchBoard to kill"; return 1; }
	kill -KILL "$old" || { fail "$1: cannot kill SwitchBoard $old"; return 1; }
	pwait -t 30 "$old" || { fail "$1: SwitchBoard $old did not exit"; return 1; }
	waitlog 'startup: restart after boot: launched' "$2" 120 ||
	    { fail "$1: no restart after boot completed"; return 1; }
	note "$1: switchboard $old -> $(sbpid)"
}

note "reroot ${VM_REROOT:-unset}, case $case, pid1=$(ps -o comm= -p 1 | tr -d ' ')"
case ${VM_REROOT:-} in
before)
	[ "$(knob kern.mac_capability.test_issuer)" = 1 ] || fail 'test_issuer is not 1'
	case $case in
	plain|crash) ;;
	next|refused)
		[ "$case" = next ] && n=1 || n=1000
		sysctl debug.mac_capability.test_issuer_fail_init_skip=1 &&
		    sysctl debug.mac_capability.test_issuer_fail_init_count=$n &&
		    sysctl debug.mac_capability.test_issuer_fail_init=$EMFILE ||
		    fail 'cannot arm fail_init' ;;
	firstboot)
		sysctl debug.mac_capability.test_issuer_fail_init_count=1 &&
		    sysctl debug.mac_capability.test_issuer_fail_init=$EMFILE ||
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

# This runs after the boot converged (vm-provider's login hook).
[ "$(ps -o comm= -p 1 | tr -d ' ')" = capsule ] || fail 'PID 1 is not capsule'
[ "$case" != firstboot ] || fail 'firstboot: the boot went on without an issuer'
starts=$(count 'bootstrap: started switchboard pid [0-9]*')
aborts=$(count 'switchboard [0-9]* - - application catalogue init failed')
sched=$(count 'bootstrap: scheduling restart in [0-9]*s')
next_missing=$(count 'no authority issuer for the next switchboard start: Too many open files')
note "starts=$starts catalogue_aborts=$aborts restart_scheduled=$sched next_missing=$next_missing"
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
	restart crash 1
	showlogs
	[ "$(count 'oneshot etc-rc: failed')" = 0 ] || fail 'crash: /etc/rc was replayed'
	[ "$(count 'restart after boot: /etc/rc not replayed')" = 1 ] ||
	    fail 'crash: SwitchBoard did not log the skipped /etc/rc'
	tools crash
	[ "$cs$ss$sr" = 000 ] || fail 'crash: a control tool failed from a shell started before the crash'
	;;
next)
	[ "$next_missing" = 1 ] || fail 'next: Capsule did not log the missing next issuer'
	grep -q 'next authority issuer: none (Too many open files)' /tmp/sb-cs.out ||
	    fail 'next: capsulectl status does not report the missing next issuer'
	[ "$(knob debug.mac_capability.test_issuer_fail_init)" = 0 ] ||
	    fail 'next: the fault did not clear after one failure'
	restart next 1
	showlogs
	[ "$(count 'no authority issuer: Too many open files')" = 0 ] ||
	    fail 'next: the restart was refused'
	tools next-restarted
	[ "$cs$ss$sr" = 000 ] || fail 'next: a control tool failed after the restart'
	! grep -q 'next authority issuer' /tmp/sb-cs.out ||
	    fail 'next: the restart still reports a missing next issuer'
	;;
refused)
	[ "$next_missing" = 1 ] || fail 'refused: Capsule did not log the missing next issuer'
	showlogs
	note 'refused: killing SwitchBoard; PID 1 must enter single-user (checked on the host)'
	[ "$failures" = 0 ] && echo SB_NO_ISSUER_AFTER_PASS
	old=$(sbpid)
	kill -KILL "$old"
	# Single-user ends this shell: wait for that event, not for a clock.
	pwait "$old"
	waitlog 'no authority issuer: Too many open files; entering single-user' 1 120
	exit $((failures != 0))
	;;
esac
note "fail_init_now=$(knob debug.mac_capability.test_issuer_fail_init) count_now=$(knob debug.mac_capability.test_issuer_fail_init_count) skip_now=$(knob debug.mac_capability.test_issuer_fail_init_skip)"
[ "$failures" = 0 ] && echo SB_NO_ISSUER_AFTER_PASS
exit $((failures != 0))
