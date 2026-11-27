#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# LA0 pins on dev that need SwitchBoard units (launch-authority-reshape.md
# rev 1, section 3: "handed-out end dead in another process / after exec"),
# run against a test-local Capsule and SwitchBoard: the stack tier
# (GENERIC-TEST, plane off, kern.mac_capability.test_issuer=1), which gives
# the units software authority.  Elsewhere the case skips as
# DEFERRED_STACK_TIER (capd_require_unit_issuer).  The unit program is
# subset_unit (scenario requester-exec); launch_authority_probe is the
# other image it executes.
#
# What the end SwitchBoard hands a unit allows (every row records today's
# answer; LA3 rewrites the binding, so these rows are its acceptance):
#   - a name its provider did not mark sendable: bound to the unit's grant
#     (naming.c:570).  The unit and its fork child use it (same grant);
#     once a fork child executes another image the grant is invalid there
#     and the end answers EPERM.
#   - a sendable name: not bound.  The exec'd image uses it (0).
#   - system.switchboard, SwitchBoard's own control name: bound to the
#     requesting invocation (naming.c:363).  The fork child is refused
#     (EPERM), and so is the exec'd image.
# The same unit's lookup of the control name succeeds (the unit holds
# authority): subset_stack_test NR3 pins that; its anonymous half (a root
# login reaches public names only, ENOENT elsewhere) is subset_test NR9 and
# service_reachability_test.
#
# Every wait is on file events (capd_wait_path); the case's ATF timeout
# bounds a wait that never ends, and the cleanup prints the evidence.
#

. "$(dirname "$0")/test_helpers.sh"

# The other image, copied into the work directory the units can reach.
install_probe()
{
	local probe

	probe="$(atf_get_srcdir)/launch_authority_probe"
	[ -x "$probe" ] || atf_fail "launch_authority_probe is unavailable: $probe"
	readelf -l "$probe" | grep -q INTERP &&
	    atf_fail "launch_authority_probe must be static (units are in capability mode)"
	cp "$probe" "${WORK}/launch_authority_probe" ||
	    atf_fail "cannot copy the probe"
	chmod 0555 "${WORK}/launch_authority_probe"
}

atf_test_case handed_out_end_after_exec cleanup
handed_out_end_after_exec_head()
{
	atf_set "descr" "LA0: the end a unit is handed for a non-sendable" \
	    "name is bound to its grant: usable by the unit and its fork" \
	    "child, EPERM once that child executes another image; a sendable" \
	    "name's end is unbound (0 after the exec); the control name's end" \
	    "is bound to the invocation: its fork child and the exec'd image" \
	    "are EPERM"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "300"
}
handed_out_end_after_exec_body()
{
	capd_require_unit_issuer
	require_mac_capability
	find_subset_unit
	prepare_paths
	install_probe
	install_unit org.test.la0.plain '"org.test.la0.plain"' never \
	    provider la0-plain.result org.test.la0.plain plain
	install_unit org.test.la0.sendable '"org.test.la0.sendable"' never \
	    provider la0-sendable.result org.test.la0.sendable sendable
	write_config
	start_stack
	capd_expect_test_issuer
	await_result la0-plain.result "end=1"
	await_result la0-sendable.result "end=1"
	expect la0-plain.result "ready=0"
	expect la0-sendable.result "ready=0"

	install_unit org.test.la0.requester '' never \
	    requester-exec la0-requester.result launch_authority_probe \
	    org.test.la0.plain org.test.la0.sendable system.switchboard
	reload_stack
	await_result la0-requester.result "end=1"
	cat "${WORK}/la0-requester.result"
	expect la0-requester.result "probe_open=0"
	expect la0-requester.result "ready=0"
	expect la0-requester.result "authority_valid=1"
	# LA0 pin: rewritten by LA3 (binding).  Grant-bound (naming.c:570).
	expect la0-requester.result "org.test.la0.plain connect=0"
	expect la0-requester.result "org.test.la0.plain getinfo=0"
	expect la0-requester.result "org.test.la0.plain child_getinfo=0"
	expect la0-requester.result "org.test.la0.plain child_cleared_getinfo=EPERM"
	expect la0-requester.result "org.test.la0.plain exec_getinfo=EPERM"
	# Not bound: the exec'd image keeps it.
	expect la0-requester.result "org.test.la0.sendable connect=0"
	expect la0-requester.result "org.test.la0.sendable getinfo=0"
	expect la0-requester.result "org.test.la0.sendable child_getinfo=0"
	expect la0-requester.result "org.test.la0.sendable child_cleared_getinfo=0"
	expect la0-requester.result "org.test.la0.sendable exec_getinfo=0"
	# LA0 pin: rewritten by LA3 (binding).  Invocation-bound (naming.c:363).
	expect la0-requester.result "system.switchboard connect=0"
	expect la0-requester.result "system.switchboard getinfo=0"
	expect la0-requester.result "system.switchboard child_getinfo=EPERM"
	expect la0-requester.result "system.switchboard child_cleared_getinfo=EPERM"
	expect la0-requester.result "system.switchboard exec_getinfo=EPERM"
	: > "${WORK}/case.done"
}
handed_out_end_after_exec_cleanup() { unit_case_cleanup; }

atf_init_test_cases()
{
	atf_add_test_case handed_out_end_after_exec
}
