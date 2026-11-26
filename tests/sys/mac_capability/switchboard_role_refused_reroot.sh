#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# A SwitchBoard that Capsule as PID 1 started without the Core role
# (P2_CAP_EXCLUDED, cap_process(2) BASE EXCLUSION) refuses to start the boot:
# it says why on the console and exits before READY, and the boot ends in
# single-user with that reason (switchboard(8), capsule(8)).  It must not
# bring the system up half-way or skip /etc/rc quietly.
#
# EXTRA_SCRIPT of a vm-provider.sh reroot run, which is also the single-user
# shell: REROOT=1 KERNEL_TIER=test PLANE_OFF=1
# LOADER_EXTRA='kern.mac_capability.test_issuer="1"'
# SINGLE_USER_SHELL=/root/vm-extra.sh
# SINGLE_USER_PASSWORDS="wrongpw sbrolepw".  A failed boot's single-user asks
# for root's password (capsule(8)); the before pass gives root sbrolepw.
#
# How the role check is made to fail: the test kernel's
# security.cap_exclusion.test_refuse, set to 1 on the plane-off boot, makes
# the next exec that would be excluded (other than PID 1's) not excluded.
# Nothing is excluded on the plane-off boot and the reroot's exec is PID 1's,
# so the count is spent on the first SwitchBoard start under Capsule, and
# the start after single-user takes the Core role.  Other ways to refuse the
# role do not reach that start: a relay image loses SwitchBoard's delegated
# descriptors at its second exec, and a ktrace of PID 1 ends at the reroot
# (the trace file's file system is unmounted, and PID 1's next fork record
# fails to write).
#
#   before       (plane-off boot) sets root's password and the refusal count;
#                the guest then reroots into Capsule;
#   single-user  (the shell PID 1 starts after the failed boot) reads the
#                reason from the console log and checks that /etc/rc did not
#                run and that the count was spent;
#   after        the boot that follows: Capsule is PID 1 and SwitchBoard
#                answers.  Reaching it without the single-user pass is the
#                failure this pins: the boot went on without the Core role.
#
# Waits are on events only: the run's deadline (vm-provider.sh TIMEOUT_S)
# bounds everything.
set -u
KNOB=security.cap_exclusion.test_refuse
STATE=/var/db/sb-role.state
REASON='the Core role was refused at exec'
failures=0
fail() { echo "SB_ROLE_FAIL: $*"; failures=$((failures + 1)); }
note() { echo "SB_ROLE: $*"; }
logs() { { dmesg -a; cat /var/log/messages; } 2>/dev/null; }
showlogs() {
	logs | grep -E 'bootstrap: |Core role|refusing to start|converge|single-user' |
	    sort -u | sed 's/^/SB_ROLE_LOG: /'
}
pid1() { ps -o comm= -p 1 | tr -d ' '; }

note "pass ${VM_REROOT:-single-user}, state $(cat $STATE 2>/dev/null || echo none), pid1=$(pid1)"

# --- single-user: this script is the shell PID 1 started (no VM_REROOT).
if [ -z "${VM_REROOT:-}" ]; then
	[ "$(pid1)" = capsule ] || fail 'PID 1 is not capsule'
	[ "$(cat $STATE 2>/dev/null)" = rerooted ] ||
	    fail "single-user in state $(cat $STATE 2>/dev/null || echo none)"
	showlogs
	logs | grep -q "switchboard\[[0-9]*\]: $REASON" ||
	    fail 'no console line from SwitchBoard saying the Core role was refused'
	logs | grep -q 'refusing to start the boot' ||
	    fail 'SwitchBoard did not say it refused to start the boot'
	# /etc/rc did not run: none of its daemons is up.
	for d in syslogd cron devd; do
		! pgrep -x $d > /dev/null || fail "$d is running: /etc/rc ran"
	done
	[ "$(sysctl -n $KNOB)" = 0 ] ||
	    fail "$KNOB is $(sysctl -n $KNOB): no exec was refused the role"
	mount -u -o rw / || fail 'cannot mount root read-write'
	echo "single $failures" > $STATE
	note "single-user: failures=$failures; leaving single-user"
	[ "$failures" = 0 ] && echo SINGLE_USER_SHELL_PASS
	exit 0
fi

case ${VM_REROOT:-} in
before)
	rm -f $STATE
	echo sbrolepw | pw usermod root -h 0 || { fail 'pw usermod'; exit 1; }
	sysctl $KNOB=1 > /dev/null || { fail "cannot set $KNOB"; exit 1; }
	echo rerooted > $STATE
	sync
	note "$KNOB=1: the next excluded exec is refused the role"
	echo SB_ROLE_BEFORE_PASS
	exit 0
	;;
after) ;;
*)
	fail "VM_REROOT=${VM_REROOT:-unset}: run this with vm-provider.sh REROOT=1"
	exit 1 ;;
esac

# --- after the reroot and the single-user pass.
[ "$(pid1)" = capsule ] || fail 'PID 1 is not capsule'
state=$(cat $STATE 2>/dev/null || true)
case $state in
single\ *)
	set -- $state
	[ "${2:-x}" = 0 ] ||
	    fail "the single-user pass failed ${2:-?} check(s) (see its SB_ROLE_FAIL lines)"
	switchboardctl status > /dev/null 2>&1 ||
	    fail 'switchboardctl status failed after single-user'
	;;
rerooted)
	showlogs
	fail 'the boot went on although SwitchBoard ran without the Core role'
	;;
*)	fail "after the reroot in state ${state:-none}" ;;
esac
rm -f $STATE
[ "$failures" = 0 ] && echo SB_ROLE_AFTER_PASS
exit $((failures != 0))
