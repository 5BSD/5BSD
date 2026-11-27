#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# NS0 pins on dev that need SwitchBoard units (nested-supervisors.md rev 1.3,
# section 9), run against a test-local Capsule and SwitchBoard: the stack
# tier (GENERIC-TEST, plane off, kern.mac_capability.test_issuer=1), which
# gives the units software authority.  Elsewhere the cases skip as
# DEFERRED_STACK_TIER (capd_require_unit_issuer).  The unit program is
# subset_unit; the rest of the NS0 pins are subset_test and
# tests/sys/mac_capability/nested_supervisor_test.
#
#   NR3 claim_outside_provides_eacces  a unit's claim of a name outside its
#	provides[] is EACCES, system.* names included; and system.switchboard
#	is answered only by SwitchBoard's self-control path, never by a unit,
#	even one that lists the name in provides[].
#   NR7 relay_as_self_zero_hops_unit  a unit holding software authority
#	looks up a name its provider did not mark sendable: the end it
#	receives is CAP_XFER_NONE, so it cannot pass it on, and the end is
#	bound to the unit's authority (naming.c naming_lookup_impl), so a
#	process without that authority cannot use it.  A sendable name is the
#	contrast.
#
# Every wait is on file events (capd_wait_path); the case's ATF timeout
# bounds a wait that never ends, and the cleanup prints the evidence.
#

. "$(dirname "$0")/test_helpers.sh"

subset_unit=

find_subset_unit()
{
	subset_unit="$(atf_get_srcdir)/subset_unit"
	[ -x "$subset_unit" ] || atf_fail "subset_unit is unavailable: $subset_unit"
	readelf -l "$subset_unit" | grep -q INTERP ||
	    atf_fail "subset_unit must be dynamically linked for SwitchBoard"
}

# install_unit LABEL "ipc names (UCL list body, or empty)" RESTART ARG...
install_unit()
{
	local label="$1" ipc="$2" restart="$3" activation dir unit arg sep
	shift 3

	activation="activation { boot = true; }"
	[ -z "$ipc" ] || activation="activation { boot = true; ipc = [${ipc}]; }"
	dir=$(make_svc_bin system "$label" "restart = \"${restart}\";
${activation}" "$subset_unit") || atf_fail "cannot install $label"
	unit=${label##*.}
	sep=
	printf 'arguments = [' >> "$dir/Units/$unit.unit/Unit.ucl"
	for arg in "$@"; do
		printf '%s"%s"' "$sep" "$arg" >> "$dir/Units/$unit.unit/Unit.ucl"
		sep=', '
	done
	printf '];\n' >> "$dir/Units/$unit.unit/Unit.ucl"
}

# await_result FILE TEXT: wait until FILE holds TEXT.
await_result()
{
	echo "waiting for $2 in $1"
	capd_wait_path "${WORK}/$1" "$2" || fail_with_log "no \"$2\" in $1"
}

# expect FILE LINE: FILE has the exact line LINE.
expect()
{
	grep -qx -- "$2" "${WORK}/$1" ||
	    fail_with_log "$1: expected the line \"$2\""
}

case_cleanup()
{
	[ -f "${WORK}/evidence.shown" ] || [ -f "${WORK}/case.done" ] ||
	    case_evidence
	cleanup_common
}

atf_test_case claim_outside_provides_eacces cleanup
claim_outside_provides_eacces_head()
{
	atf_set "descr" "NR3: a unit's claim of a name outside its provides[] is" \
	    "EACCES (org.test names, system.switchboard, system.lifecycle);" \
	    "a unit that lists and claims system.switchboard never receives" \
	    "its clients: SwitchBoard answers that name itself"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "300"
}
claim_outside_provides_eacces_body()
{
	capd_require_unit_issuer
	require_mac_capability
	find_subset_unit
	prepare_paths
	install_unit org.test.nr3.claimer '"org.test.nr3.claimer"' never \
	    claimer nr3-claimer.result org.test.nr3.claimer \
	    org.test.nr3.undeclared system.switchboard system.lifecycle
	install_unit org.test.nr3.declared \
	    '"system.switchboard", "org.test.nr3.declared"' never \
	    declared nr3-declared.result system.switchboard \
	    org.test.nr3.declared
	write_config
	start_stack
	capd_expect_test_issuer
	await_result nr3-claimer.result "end=1"
	await_result nr3-declared.result "end=1"
	cat "${WORK}/nr3-claimer.result" "${WORK}/nr3-declared.result"
	expect nr3-claimer.result "claim org.test.nr3.undeclared=EACCES"
	expect nr3-claimer.result "claim system.switchboard=EACCES"
	expect nr3-claimer.result "claim system.lifecycle=EACCES"
	expect nr3-claimer.result "claim own org.test.nr3.claimer=0"
	expect nr3-claimer.result "ready=0"
	expect nr3-declared.result "claim system.switchboard=0"
	expect nr3-declared.result "claim own org.test.nr3.declared=0"
	expect nr3-declared.result "ready=0"

	# A unit with authority looks up system.switchboard, then the declaring
	# unit's own name; that unit's first client tells whether a client of
	# system.switchboard ever reached it.
	install_unit org.test.nr3.requester '' never \
	    requester nr3-requester.result system.switchboard \
	    org.test.nr3.declared
	reload_stack
	await_result nr3-requester.result "end=1"
	await_result nr3-declared.result "own_client="
	cat "${WORK}/nr3-requester.result" "${WORK}/nr3-declared.result"
	expect nr3-requester.result "authority_valid=1"
	expect nr3-requester.result "system.switchboard connect=0"
	expect nr3-requester.result "org.test.nr3.declared connect=0"
	expect nr3-declared.result "sys_pending=0"
	: > "${WORK}/case.done"
}
claim_outside_provides_eacces_cleanup() { case_cleanup; }

atf_test_case relay_as_self_zero_hops_unit cleanup
relay_as_self_zero_hops_unit_head()
{
	atf_set "descr" "NR7, unit requester: the end a unit holding software" \
	    "authority receives for a name not marked sendable is" \
	    "CAP_XFER_NONE (passing it on fails ENOTCAPABLE) and bound to" \
	    "the unit's authority (a fork child that cleared its authority" \
	    "gets EPERM); a sendable name's end can be passed on"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "300"
}
relay_as_self_zero_hops_unit_body()
{
	capd_require_unit_issuer
	require_mac_capability
	find_subset_unit
	prepare_paths
	install_unit org.test.nr7.plain '"org.test.nr7.plain"' never \
	    provider nr7-plain.result org.test.nr7.plain plain
	install_unit org.test.nr7.sendable '"org.test.nr7.sendable"' never \
	    provider nr7-sendable.result org.test.nr7.sendable sendable
	write_config
	start_stack
	capd_expect_test_issuer
	await_result nr7-plain.result "end=1"
	await_result nr7-sendable.result "end=1"
	expect nr7-plain.result "ready=0"
	expect nr7-sendable.result "ready=0"

	install_unit org.test.nr7.requester '' never \
	    requester nr7-requester.result org.test.nr7.plain \
	    org.test.nr7.sendable
	reload_stack
	await_result nr7-requester.result "end=1"
	cat "${WORK}/nr7-requester.result"
	expect nr7-requester.result "authority_valid=1"
	# Not sendable: delivered CAP_XFER_NONE, bound to the authority.
	expect nr7-requester.result "org.test.nr7.plain connect=0"
	expect nr7-requester.result "org.test.nr7.plain xfer_once=ENOTCAPABLE"
	expect nr7-requester.result "org.test.nr7.plain xfer_none=0"
	expect nr7-requester.result "org.test.nr7.plain scm_send=ENOTCAPABLE"
	expect nr7-requester.result "org.test.nr7.plain chan_send=ENOTCAPABLE"
	expect nr7-requester.result "org.test.nr7.plain getinfo=0"
	expect nr7-requester.result "org.test.nr7.plain child_getinfo=0"
	expect nr7-requester.result \
	    "org.test.nr7.plain child_cleared_getinfo=EPERM"
	# Sendable: transferable, and not bound.
	expect nr7-requester.result "org.test.nr7.sendable connect=0"
	expect nr7-requester.result "org.test.nr7.sendable scm_send=0"
	expect nr7-requester.result "org.test.nr7.sendable chan_send=0"
	expect nr7-requester.result "org.test.nr7.sendable xfer_once=0"
	expect nr7-requester.result \
	    "org.test.nr7.sendable child_cleared_getinfo=0"
	: > "${WORK}/case.done"
}
relay_as_self_zero_hops_unit_cleanup() { case_cleanup; }

atf_init_test_cases()
{
	atf_add_test_case claim_outside_provides_eacces
	atf_add_test_case relay_as_self_zero_hops_unit
}
