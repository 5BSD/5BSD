#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# SwitchBoard when PID 1 has no authority issuer (capsule(8), "Authority
# issuer"): the EXTRA_SCRIPT of a vm-provider.sh reroot run (REROOT=1,
# PLANE_OFF=1, KERNEL_TIER=test, LOADER_EXTRA with
# kern.mac_capability.test_issuer="1").  The loader variable sb_case selects
# what PID 1's creates do after the reroot into Capsule:
#
#   plain       nothing fails: one SwitchBoard start, with the issuer;
#   transient   one create fails with EMFILE (test_issuer_fail_init_count=1);
#               Capsule waits, the retry succeeds, SwitchBoard starts once,
#               with the issuer, and nothing is counted against the restart
#               limit;
#   persistent  every create fails with EMFILE (count 1000) until this script
#               clears the fault after the reroot: Capsule waits
#               BOOTSTRAP_ISSUER_WAIT, starts SwitchBoard degraded (no
#               application grants), keeps retrying, and once the fault is
#               cleared restarts SwitchBoard with the issuer as a planned
#               restart, not counted against the restart limit.
#
# sb_expect="today" checks the behaviour before the change (64b85df72cd)
# instead: transient aborts the first SwitchBoard in its catalogue sync and the
# restart runs; persistent never reaches this script (PID 1 enters recovery
# after the restart limit), so the host reads that from the serial log.
set -u
case=$(kenv -q sb_case || echo plain)
expect=$(kenv -q sb_expect || echo fixed)
EMFILE=24
failures=0
fail() { echo "SB_NO_ISSUER_FAIL: $*"; failures=$((failures + 1)); }
note() { echo "SB_NO_ISSUER: $*"; }
knob() { sysctl -n "$1" 2>/dev/null || echo absent; }
logs() { { dmesg -a; cat /var/log/messages /var/log/capability.log; } 2>/dev/null; }
# Lines with one pattern, each message once (the console copy of a message
# also reaches /var/log/messages).
count() { logs | grep -o "$1" | sort -u | wc -l | tr -d ' '; }
await() {	# await PATTERN SECONDS
	i=0
	while [ "$i" -lt "$2" ]; do
		logs | grep -q "$1" && return 0
		i=$((i + 1)); sleep 1
	done
	return 1
}
# What the control tools can do: a read (status) and an administrative
# request that changes nothing (reload re-reads the registry).
tools() {
	capsulectl status > /tmp/sb-cs.out 2>&1; cs=$?
	switchboardctl status > /tmp/sb-ss.out 2>&1; ss=$?
	switchboardctl reload > /tmp/sb-sr.out 2>&1; sr=$?
	note "$1 capsulectl_status=$cs [$(head -c 120 /tmp/sb-cs.out | tr '\n' ' ')]"
	note "$1 switchboardctl_status=$ss [$(head -c 120 /tmp/sb-ss.out | tr '\n' ' ')]"
	note "$1 switchboardctl_reload=$sr [$(head -c 120 /tmp/sb-sr.out | tr '\n' ' ')]"
}

note "reroot ${VM_REROOT:-unset}, case $case, expect $expect, pid1=$(ps -o comm= -p 1 | tr -d ' ')"
case ${VM_REROOT:-} in
before)
	[ "$(knob kern.mac_capability.test_issuer)" = 1 ] || fail 'test_issuer is not 1'
	case $case in
	plain) ;;
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
logs | grep -E 'bootstrap: |inherited service fds|authority issuer|catalogue' | sort -u | sed 's/^/SB_NO_ISSUER_LOG: /'

case $expect:$case in
today:plain|fixed:plain)
	[ "$starts" = 1 ] || fail "plain: $starts SwitchBoard starts"
	[ "$exits$sched" = 00 ] || fail 'plain: SwitchBoard aborted or was restarted'
	tools plain
	[ "$cs$ss$sr" = 000 ] || fail 'plain: a control tool failed'
	;;
today:transient)
	[ "$starts" = 2 ] || fail "today transient: $starts starts, not 2"
	[ "$exits" = 1 ] || fail "today transient: $exits catalogue aborts, not 1"
	[ "$sched" -ge 1 ] || fail 'today transient: no restart scheduled'
	tools transient
	;;
fixed:transient)
	[ "$waiting" = 1 ] || fail "transient: Capsule did not log its wait ($waiting)"
	[ "$starts" = 1 ] || fail "transient: $starts SwitchBoard starts, not 1"
	[ "$exits$sched$degraded" = 000 ] ||
	    fail 'transient: SwitchBoard aborted, was restarted or started degraded'
	logs | grep -q 'inherited service fds: .* authority=8' ||
	    fail 'transient: SwitchBoard does not report its issuer'
	tools transient
	[ "$cs$ss$sr" = 000 ] || fail 'transient: a control tool failed'
	;;
fixed:persistent)
	[ "$waiting" = 1 ] || fail "persistent: Capsule did not log its wait ($waiting)"
	[ "$degraded" -ge 1 ] || fail 'persistent: no degraded start'
	[ "$starts" = 1 ] || fail "persistent: $starts SwitchBoard starts before the fault cleared"
	[ "$exits$sched" = 00 ] || fail 'persistent: SwitchBoard aborted or was restarted'
	logs | grep -q 'inherited service fds: .* authority=-1' ||
	    fail 'persistent: SwitchBoard does not report the missing issuer'
	logs | grep -q 'no authority issuer: application catalogue not registered' ||
	    fail 'persistent: SwitchBoard did not log the unregistered catalogue'
	# Pin what the degraded world allows.  Fail closed: the control tools
	# hold no grant, so administrative requests are refused.
	tools degraded
	[ "$sr" != 0 ] || fail 'degraded: switchboardctl reload was allowed'
	[ "$(knob debug.mac_capability.test_issuer_fail_init)" = $EMFILE ] ||
	    fail 'persistent: the fault cleared on its own'
	degraded_pid=$(pgrep -x switchboard | head -n 1)
	# Clear the outage; Capsule's next retry gets the issuer.
	sysctl debug.mac_capability.test_issuer_fail_init=0 ||
	    fail 'cannot clear fail_init after the reroot'
	await 'bootstrap: authority issuer acquired' 60 ||
	    fail 'Capsule did not acquire the issuer after the fault cleared'
	# After the reroot only NOTICE and above reach the log files, so the
	# new SwitchBoard is found by its process, not its INFO start line.
	i=0 new_pid=
	while [ "$i" -lt 60 ]; do
		new_pid=$(pgrep -x switchboard | head -n 1)
		[ -n "$new_pid" ] && [ "$new_pid" != "$degraded_pid" ] && break
		i=$((i + 1)); sleep 1
	done
	[ -n "$new_pid" ] && [ "$new_pid" != "$degraded_pid" ] ||
	    fail 'no new SwitchBoard after the planned restart'
	sleep 20
	sched=$(count 'bootstrap: scheduling restart in [0-9]*s')
	planned=$(count 'bootstrap: planned switchboard restart')
	note "recovered switchboard $degraded_pid -> $new_pid restart_scheduled=$sched planned=$planned"
	logs | grep -E 'bootstrap: |inherited service fds|authority issuer|catalogue|etc-rc' | sort -u | sed 's/^/SB_NO_ISSUER_LOG: /'
	[ "$planned" = 1 ] || fail "persistent: $planned planned restarts, not 1"
	[ "$sched" = 0 ] || fail 'persistent: the planned restart used the restart limit'
	tools recovered
	[ "$cs$ss$sr" = 000 ] || fail 'recovered: a control tool failed'
	;;
*)
	fail "no expectation for $expect:$case" ;;
esac
note "fail_init_now=$(knob debug.mac_capability.test_issuer_fail_init) count_now=$(knob debug.mac_capability.test_issuer_fail_init_count)"
[ "$failures" = 0 ] && echo SB_NO_ISSUER_AFTER_PASS
exit $((failures != 0))
