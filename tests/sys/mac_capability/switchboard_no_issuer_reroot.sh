#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# SwitchBoard starts and restarts under Capsule as PID 1: the EXTRA_SCRIPT of a
# vm-provider.sh reroot run (REROOT=1, PLANE_OFF=1, KERNEL_TIER=test,
# LOADER_EXTRA with kern.mac_capability.test_issuer="1").  The loader variable
# sb_case selects the case:
#
#   plain       nothing fails: one SwitchBoard start, with the issuer;
#   transient   PID 1's first issuer create fails with EMFILE
#               (test_issuer_fail_init_count=1);
#   persistent  every create fails with EMFILE (count 1000) until this script
#               clears the fault after the reroot;
#   crash       SwitchBoard is killed after boot (needs the loader variable
#               switchboard_test_no_sigkill="1" so its shield allows SIGKILL).
#
# sb_expect names the build whose behaviour is checked:
#   dev    dev 64b85df72cd: a transient failure aborts the first SwitchBoard
#          and the restart runs; persistent never reaches this script (PID 1
#          enters recovery);
#   wait   Capsule waits for the issuer, then starts SwitchBoard degraded, and
#          restarts it once the issuer comes; a restart after boot replays
#          /etc/rc and leaves existing shells without a route;
#   fixed  as wait, and a restart after boot does not replay /etc/rc, existing
#          shells reach the new SwitchBoard, and root can get status and power
#          off a degraded system.
set -u
case=$(kenv -q sb_case || echo plain)
expect=$(kenv -q sb_expect || echo fixed)
EMFILE=24
failures=0
fail() { echo "SB_NO_ISSUER_FAIL: $*"; failures=$((failures + 1)); }
note() { echo "SB_NO_ISSUER: $*"; }
knob() { sysctl -n "$1" 2>/dev/null || echo absent; }
logs() { { dmesg -a; cat /var/log/messages /var/log/capability.log; } 2>/dev/null; }
# Messages with one pattern, each once (the console copy of a message also
# reaches /var/log/messages).  Only NOTICE and above reach the files.
count() { logs | grep -o "$1" | sort -u | wc -l | tr -d ' '; }
await() {	# await PATTERN SECONDS
	i=0
	while [ "$i" -lt "$2" ]; do
		logs | grep -q "$1" && return 0
		i=$((i + 1)); sleep 1
	done
	return 1
}
sbpid() { pgrep -x switchboard | head -n 1; }
await_new_pid() {	# await_new_pid OLD SECONDS: prints the new pid
	i=0
	while [ "$i" -lt "$2" ]; do
		p=$(sbpid)
		[ -n "$p" ] && [ "$p" != "$1" ] && { echo "$p"; return 0; }
		i=$((i + 1)); sleep 1
	done
	return 1
}
showlogs() {
	logs | grep -E 'bootstrap: |inherited service fds|authority issuer|catalogue|etc-rc|after boot' |
	    sort -u | sed 's/^/SB_NO_ISSUER_LOG: /'
}
# What the control tools can do from this (pre-existing) shell: reads
# (status) and an administrative request that changes nothing (reload).
tools() {
	capsulectl status > /tmp/sb-cs.out 2>&1; cs=$?
	switchboardctl status > /tmp/sb-ss.out 2>&1; ss=$?
	switchboardctl reload > /tmp/sb-sr.out 2>&1; sr=$?
	note "$1 capsulectl_status=$cs [$(head -c 120 /tmp/sb-cs.out | tr '\n' ' ')]"
	note "$1 switchboardctl_status=$ss [$(head -c 120 /tmp/sb-ss.out | tr '\n' ' ')]"
	note "$1 switchboardctl_reload=$sr [$(head -c 120 /tmp/sb-sr.out | tr '\n' ' ')]"
}
# After a restart after boot: rc replayed or not, and the shell's route.
check_restart() {	# check_restart LABEL
	replays=$(count 'oneshot etc-rc: failed')
	skipped=$(count 'restart after boot: /etc/rc not replayed')
	note "$1 rc_replay_failures=$replays rc_not_replayed=$skipped"
	tools "$1"
	case $expect in
	wait)
		[ "$replays" -ge 1 ] || fail "$1: /etc/rc was not replayed (pinned: it is)"
		[ "$cs$ss" != 00 ] || fail "$1: the old route still works (pinned: it does not)"
		;;
	fixed)
		[ "$replays" = 0 ] || fail "$1: /etc/rc was replayed after boot"
		[ "$skipped" -ge 1 ] || fail "$1: SwitchBoard did not log the skipped rc"
		[ "$cs$ss$sr" = 000 ] || fail "$1: a control tool failed from an existing shell"
		;;
	esac
}

note "reroot ${VM_REROOT:-unset}, case $case, expect $expect, pid1=$(ps -o comm= -p 1 | tr -d ' ')"
case ${VM_REROOT:-} in
before)
	[ "$(knob kern.mac_capability.test_issuer)" = 1 ] || fail 'test_issuer is not 1'
	case $case in
	plain|crash) ;;
	transient)
		sysctl debug.mac_capability.test_issuer_fail_init_count=1 &&
		    sysctl debug.mac_capability.test_issuer_fail_init=$EMFILE ||
		    fail 'cannot arm fail_init' ;;
	persistent)
		sysctl debug.mac_capability.test_issuer_fail_init_count=1000 &&
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

[ "$(ps -o comm= -p 1 | tr -d ' ')" = capsule ] || fail 'PID 1 is not capsule'
# Let the boot settle: SwitchBoard's restart, if any, is 1 s after its abort.
sleep 20
starts=$(count 'bootstrap: started switchboard pid [0-9]*')
exits=$(count 'switchboard [0-9]* - - application catalogue init failed')
sched=$(count 'bootstrap: scheduling restart in [0-9]*s')
waiting=$(count 'issuer unavailable: .*; waiting up to [0-9]*s')
degraded=$(count 'bootstrap: no authority issuer: starting switchboard degraded')
note "starts=$starts catalogue_aborts=$exits restart_scheduled=$sched waiting=$waiting degraded=$degraded"
showlogs

case $expect:$case in
*:plain)
	[ "$starts" = 1 ] || fail "plain: $starts SwitchBoard starts"
	[ "$exits$sched" = 00 ] || fail 'plain: SwitchBoard aborted or was restarted'
	tools plain
	[ "$cs$ss$sr" = 000 ] || fail 'plain: a control tool failed'
	;;
dev:transient)
	[ "$starts" = 2 ] || fail "dev transient: $starts starts, not 2"
	[ "$exits" = 1 ] || fail "dev transient: $exits catalogue aborts, not 1"
	[ "$sched" -ge 1 ] || fail 'dev transient: no restart scheduled'
	tools transient
	;;
wait:transient|fixed:transient)
	[ "$waiting" = 1 ] || fail "transient: Capsule did not log its wait ($waiting)"
	[ "$starts" = 1 ] || fail "transient: $starts SwitchBoard starts, not 1"
	[ "$exits$sched$degraded" = 000 ] ||
	    fail 'transient: SwitchBoard aborted, was restarted or started degraded'
	logs | grep -q 'inherited service fds: .* authority=8' ||
	    fail 'transient: SwitchBoard does not report its issuer'
	tools transient
	[ "$cs$ss$sr" = 000 ] || fail 'transient: a control tool failed'
	;;
wait:persistent|fixed:persistent)
	[ "$waiting" = 1 ] || fail "persistent: Capsule did not log its wait ($waiting)"
	[ "$degraded" -ge 1 ] || fail 'persistent: no degraded start'
	[ "$exits$sched" = 00 ] || fail 'persistent: SwitchBoard aborted or was restarted'
	logs | grep -q 'inherited service fds: .* authority=-1' ||
	    fail 'persistent: SwitchBoard does not report the missing issuer'
	logs | grep -q 'no authority issuer: application catalogue not registered' ||
	    fail 'persistent: SwitchBoard did not log the unregistered catalogue'
	# Fail closed: no grants, so administrative requests are refused.
	tools degraded
	[ "$sr" != 0 ] || fail 'degraded: switchboardctl reload was allowed'
	if [ "$expect" = fixed ]; then
		[ "$cs$ss" = 00 ] || fail 'degraded: root cannot get status'
	else
		[ "$cs$ss" != 00 ] || fail 'degraded: status works (pinned: it does not)'
	fi
	[ "$(knob debug.mac_capability.test_issuer_fail_init)" = $EMFILE ] ||
	    fail 'persistent: the fault cleared on its own'
	old=$(sbpid)
	# Clear the outage; Capsule's next retry gets the issuer.
	sysctl debug.mac_capability.test_issuer_fail_init=0 ||
	    fail 'cannot clear fail_init after the reroot'
	# Degraded retries back off to 320 s (capsule(8)).
	await 'bootstrap: authority issuer acquired' 400 ||
	    fail 'Capsule did not acquire the issuer after the fault cleared'
	new=$(await_new_pid "$old" 60) || fail 'no new SwitchBoard after the planned restart'
	sleep 20
	sched=$(count 'bootstrap: scheduling restart in [0-9]*s')
	planned=$(count 'bootstrap: planned switchboard restart')
	note "recovered switchboard $old -> ${new:-none} restart_scheduled=$sched planned=$planned"
	showlogs
	[ "$planned" = 1 ] || fail "persistent: $planned planned restarts, not 1"
	[ "$sched" = 0 ] || fail 'persistent: the planned restart used the restart limit'
	check_restart recovered
	;;
wait:crash|fixed:crash)
	[ "$starts$exits$sched" = 100 ] || fail 'crash: the boot was not a plain one'
	tools before-crash
	[ "$cs$ss$sr" = 000 ] || fail 'crash: a control tool failed before the crash'
	old=$(sbpid)
	kill -KILL "$old" || fail "crash: cannot kill SwitchBoard $old"
	new=$(await_new_pid "$old" 60) || fail 'crash: SwitchBoard was not restarted'
	sleep 20
	note "crash switchboard $old -> ${new:-none}"
	showlogs
	check_restart crash
	;;
*)
	fail "no expectation for $expect:$case" ;;
esac
note "fail_init_now=$(knob debug.mac_capability.test_issuer_fail_init) count_now=$(knob debug.mac_capability.test_issuer_fail_init_count)"
[ "$failures" = 0 ] && echo SB_NO_ISSUER_AFTER_PASS
exit $((failures != 0))
