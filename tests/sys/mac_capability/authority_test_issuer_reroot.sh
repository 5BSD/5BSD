#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# The reroot stage of a test-issuer kernel (design test-relax-switch, section
# 8): the EXTRA_SCRIPT of a vm-provider.sh run with REROOT=1, PLANE_OFF=1,
# KERNEL_TIER=test and LOADER_EXTRA='kern.mac_capability.test_issuer="1"'.
#
#   VM_REROOT=before  (plane off, stock init) a test issuer is created and,
#                     in the fail_init variant, PID 1's second create (the
#                     issuer Capsule holds for the next SwitchBoard start) is
#                     made to fail with ENOSPC (test_issuer_fail_init_skip=1,
#                     test_issuer_fail_init);
#   VM_REROOT=after   (Capsule as PID 1, plane on) the boot is anchored, a
#                     relaxed create is refused, SwitchBoard runs with its
#                     issuer, and in the variant Capsule logged that the next
#                     start has none.  A first create that fails sends PID 1 to
#                     single-user; switchboard_no_issuer_reroot.sh covers that.
#
# The variant is the default; the loader variable vm_reroot_variant="plain"
# selects the plain reroot.  kenv survives the reroot.
set -eu
helper=/usr/tests/sys/mac_capability/authority_issuer_helper
variant=$(kenv -q vm_reroot_variant || echo fail_init)
ENOSPC=28
fail() {
	echo "REROOT_CHECK_FAIL: $*"
	if [ "${VM_REROOT:-}" = after ]; then
		mount -p; ps -axo pid,ppid,comm
		tail -n 40 /var/log/messages /var/log/capability.log 2>/dev/null
		dmesg -a | grep 'mac_capability' || true
	fi
	exit 1
}
knob() { sysctl -n "$1" 2>/dev/null || echo absent; }

echo "reroot $VM_REROOT, variant $variant, pid1=$(ps -o comm= -p 1 | tr -d ' ')"
case $VM_REROOT in
before)
	[ "$(knob kern.mac_capability.test_issuer)" = 1 ] || fail 'test_issuer is not 1'
	[ "$(knob kern.mac_capability.test_issuer_state)" != anchored ] ||
	    fail 'anchored before the reroot'
	created=$(knob kern.mac_capability.test_issuers)
	[ "$("$helper" create)" = created ] || fail 'relaxed create refused before the reroot'
	[ "$(knob kern.mac_capability.test_issuer_state)" = test ] || fail 'state is not test'
	[ "$(knob kern.mac_capability.test_issuers)" -gt "$created" ] ||
	    fail 'the test issuer count did not grow'
	if [ "$variant" = fail_init ]; then
		sysctl debug.mac_capability.test_issuer_fail_init_skip=1 ||
		    fail 'fail_init_skip not set'
		sysctl debug.mac_capability.test_issuer_fail_init=$ENOSPC
		[ "$(knob debug.mac_capability.test_issuer_fail_init)" = $ENOSPC ] ||
		    fail 'fail_init not set'
		# Only the listed errnos are accepted.
		if sysctl debug.mac_capability.test_issuer_fail_init=5 2>/dev/null; then
			fail 'fail_init accepted EIO'
		fi
		[ "$(knob debug.mac_capability.test_issuer_fail_init)" = $ENOSPC ] ||
		    fail 'a refused write changed fail_init'
	fi
	echo "REROOT_CHECK_BEFORE_PASS"
	;;
after)
	[ "$(ps -o comm= -p 1 | tr -d ' ')" = capsule ] || fail 'PID 1 is not capsule'
	[ -z "$(kenv -q capability_plane || true)" ] || fail 'the plane is still off'
	[ "$(knob kern.mac_capability.test_issuer_state)" = anchored ] ||
	    fail "state $(knob kern.mac_capability.test_issuer_state) after the reroot"
	[ "$(knob kern.mac_capability.test_issuers_live)" = 0 ] ||
	    fail "$(knob kern.mac_capability.test_issuers_live) test issuers alive"
	out=$("$helper" create || true)
	[ "$out" = "refused errno=1" ] || fail "relaxed create after the anchor: $out"
	[ "$(knob debug.mac_capability.test_issuer_fail_init)" = 0 ] ||
	    fail 'fail_init was not consumed'
	# This runs after the boot converged, so both creates are long done.
	# Capsule's bootstrap logs through syslog(3) before syslogd runs: to
	# the console, which the message buffer keeps.
	line=$({ dmesg -a; cat /var/log/messages /var/log/capability.log; } 2>/dev/null |
	    grep 'no authority issuer' | tail -n 1 || true)
	dmesg -a | grep 'mac_capability: TEST MODE' || true
	if [ "$variant" = fail_init ]; then
		echo "$line" | grep -q 'no authority issuer for the next switchboard start: No space left on device' ||
		    fail "Capsule did not log the failed create: [$line]"
	else
		[ -z "$line" ] || fail "Capsule has no issuer: $line"
		# The boot issuer was created by PID 1, not as a test issuer.
		dmesg -a | grep -q 'TEST MODE: pid 1 ' && fail 'PID 1 made a test issuer'
	fi
	echo "Capsule: ${line:-boot issuer created}"
	echo "REROOT_CHECK_AFTER_PASS"
	;;
*)
	fail "VM_REROOT=${VM_REROOT:-unset}: run this with vm-provider.sh REROOT=1"
	;;
esac
