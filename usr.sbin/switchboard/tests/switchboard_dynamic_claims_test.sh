#!/usr/libexec/atf-sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Dynamic system-gate claim/release integration tests for capsule + switchboard.
# Path and network capabilities are deliberately absent from service manifests:
# filesystem access is brokered by bsdfilesystem and network access by bsdnetwork.
#

. "$(dirname "$0")/test_helpers.sh"

wait_for_log()
{
	local pattern i
	pattern=$1
	i=0
	while ! grep -Eq "$pattern" "$logfile" 2>/dev/null &&
	    [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	grep -Eq "$pattern" "$logfile" 2>/dev/null
}

make_gate_service()
{
	local label=$1 gates=$2 pidfile=$3 ready=$4
	make_fixture_svc system "$label" "capabilities {
    system = [${gates}];
}" lifecycle-hold "$pidfile" "$ready" running >/dev/null
}

claim_status()
{
	capd_capsule_ctl "$sockpath" status
}

atf_test_case shared_path_survives_exit cleanup
shared_path_survives_exit_head()
{
	atf_set "descr" "A shared dynamic system gate survives one consumer exit"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
shared_path_survives_exit_body()
{
	require_mac_capability
	start_stack
	make_gate_service gate-a '"kldload"' "${WORK}/gate-a.pid" \
	    "${WORK}/gate-a-ready.out"
	make_gate_service gate-b '"kldload"' "${WORK}/gate-b.pid" \
	    "${WORK}/gate-b-ready.out"
	reload_stack
	wait_for_file gate-a-ready.out || atf_fail "gate-a did not start"
	wait_for_file gate-b-ready.out || atf_fail "gate-b did not start"
	claim_status > status-both.out
	atf_check -s exit:0 -o match:'kldload.*service, refcount=2' cat status-both.out
	kill "$(cat gate-a.pid)"
	wait_for_log 'gate-a.*(exited|killed)'
	claim_status > status-after.out
	atf_check -s exit:0 -o match:'kldload.*service, refcount=1' cat status-after.out
}
shared_path_survives_exit_cleanup() { cleanup_common; }

atf_test_case dynamic_claim_fully_released cleanup
dynamic_claim_fully_released_head()
{
	atf_set "descr" "The last dynamic system-gate reference is released"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
dynamic_claim_fully_released_body()
{
	require_mac_capability
	start_stack
	make_gate_service sole-gate '"kldunload"' "${WORK}/sole-gate.pid" \
	    "${WORK}/sole-gate-ready.out"
	reload_stack
	wait_for_file sole-gate-ready.out || atf_fail "service did not start"
	claim_status > status-before.out
	atf_check -s exit:0 -o match:'kldunload.*service, refcount=1' cat status-before.out
	kill "$(cat sole-gate.pid)"
	wait_for_log 'released dynamic system gates'
	claim_status > status-after.out
	atf_check -s exit:1 -o empty grep 'kldunload.*service' status-after.out
}
dynamic_claim_fully_released_cleanup() { cleanup_common; }

atf_test_case policy_claim_immune_to_release cleanup
policy_claim_immune_to_release_head()
{
	atf_set "descr" "A policy system gate survives a service release"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
policy_claim_immune_to_release_body()
{
	require_mac_capability
	prepare_paths
	find_switchboard
	cat > "$conffile" <<-UCL
	pidfile = "$pidfile";
	control_socket = "$sockpath";
	control_socket_mode = "0700";
	service_manager = "$switchboard_bin";
	claims {
	    system = ["kldload"];
	}
	UCL
	export SWITCHBOARD_BUNDLE_DIR_SYSTEM="${APPS_DIR}"
	export SWITCHBOARD_BUNDLE_DIR_USER="${USER_APPS_DIR}"
	export SWITCHBOARD_SKIP_RC=1
	make_gate_service policy-gate '"kldload"' \
	    "${WORK}/policy-gate.pid" "${WORK}/policy-gate-ready.out"
	capd_start_stack
	daemon_pid=$("$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status |
	    sed -n 's/^running pid=//p')
	reload_stack
	wait_for_file policy-gate-ready.out || atf_fail "service did not start"
	claim_status > status-before.out
	atf_check -s exit:0 -o match:'kldload.*policy' cat status-before.out
	kill "$(cat policy-gate.pid)"
	wait_for_log 'policy-gate.*(exited|killed)'
	claim_status > status-after.out
	atf_check -s exit:0 -o match:'kldload.*policy' cat status-after.out
}
policy_claim_immune_to_release_cleanup() { cleanup_common; }

atf_test_case multi_cap_batched_release cleanup
multi_cap_batched_release_head()
{
	atf_set "descr" "A combined system-gate release is atomic and leaves the channel healthy"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
multi_cap_batched_release_body()
{
	require_mac_capability
	start_stack
	make_gate_service multi-gate '"kldload", "kldunload"' \
	    "${WORK}/multi-gate.pid" "${WORK}/multi-gate-ready.out"
	reload_stack
	wait_for_file multi-gate-ready.out || atf_fail "service did not start"
	claim_status > status-before.out
	atf_check -s exit:0 -o match:'kldload.*service, refcount=1' cat status-before.out
	atf_check -s exit:0 -o match:'kldunload.*service, refcount=1' cat status-before.out
	kill "$(cat multi-gate.pid)"
	wait_for_log 'released dynamic system gates'
	claim_status > status-after.out
	atf_check -s exit:1 -o empty grep 'kldload.*service' status-after.out
	atf_check -s exit:1 -o empty grep 'kldunload.*service' status-after.out
	make_gate_service health-gate '"kldload"' - "${WORK}/health-gate-ready.out"
	reload_stack
	wait_for_file health-gate-ready.out ||
	    atf_fail "Capsule channel was unhealthy after release"
	claim_status > status-health.out
	atf_check -s exit:0 -o match:'kldload.*service, refcount=1' cat status-health.out
}
multi_cap_batched_release_cleanup() { cleanup_common; }

atf_test_case duplicate_release_no_underflow cleanup
duplicate_release_no_underflow_head()
{
	atf_set "descr" "Release followed by a fresh mint starts at refcount one"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
duplicate_release_no_underflow_body()
{
	require_mac_capability
	start_stack
	make_gate_service first-gate '"kldunload"' \
	    "${WORK}/first-gate.pid" "${WORK}/first-gate-ready.out"
	reload_stack
	wait_for_file first-gate-ready.out || atf_fail "first service did not start"
	kill "$(cat first-gate.pid)"
	wait_for_log 'released dynamic system gates'
	make_gate_service second-gate '"kldunload"' - "${WORK}/second-gate-ready.out"
	reload_stack
	wait_for_file second-gate-ready.out || atf_fail "second service did not start"
	claim_status > status-fresh.out
	atf_check -s exit:0 -o match:'kldunload.*service, refcount=1' cat status-fresh.out
}
duplicate_release_no_underflow_cleanup() { cleanup_common; }

atf_test_case sweep_all_claim_types cleanup
sweep_all_claim_types_head()
{
	atf_set "descr" "Orderly manager shutdown releases every dynamic system gate"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
sweep_all_claim_types_body()
{
	require_mac_capability
	start_stack
	make_gate_service shutdown-gates '"kldload", "kldunload"' \
	    "${WORK}/shutdown-gates.pid" "${WORK}/shutdown-gates-ready.out"
	reload_stack
	wait_for_file shutdown-gates-ready.out || atf_fail "service did not start"
	claim_status > status-before.out
	atf_check -s exit:0 -o match:'kldload.*service' cat status-before.out
	atf_check -s exit:0 -o match:'kldunload.*service' cat status-before.out
	stop_stack
	atf_check -s exit:0 -o match:'released dynamic system gates' \
	    grep 'released dynamic system gates' "$logfile"
}
sweep_all_claim_types_cleanup() { cleanup_common; }

atf_init_test_cases()
{
	atf_add_test_case shared_path_survives_exit
	atf_add_test_case dynamic_claim_fully_released
	atf_add_test_case policy_claim_immune_to_release
	atf_add_test_case multi_cap_batched_release
	atf_add_test_case duplicate_release_no_underflow
	atf_add_test_case sweep_all_claim_types
}
