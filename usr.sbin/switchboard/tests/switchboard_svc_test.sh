#
# SPDX-License-Identifier: BSD-2-Clause
#
# Service lifecycle tests for switchboard.
#
# Ported from capsule_stress_test.sh and capsule_svc_test.sh for the
# two-daemon architecture (capsule + switchboard).  These tests verify
# restart policies, shutdown sequencing, credential dropping,
# environment contracts, and dependency ordering.
#

_helpers="$(dirname "$0")/test_helpers.sh"
if [ ! -f "$_helpers" ]; then
	_helpers="/usr/src/usr.sbin/switchboard/tests/test_helpers.sh"
fi
. "$_helpers"

assert_stack_alive()
{
	if ! capd_guardian_is_running; then
		cat "$logfile" 2>/dev/null
		atf_fail "capsule exited unexpectedly"
	fi
	capd_capsule_ctl "$sockpath" status | grep -q running ||
	    atf_fail "Capsule status request failed"
}

# ===================================================================
# Restart policy: restart=never
# ===================================================================

atf_test_case restart_never_no_restart cleanup
restart_never_no_restart_head()
{
	atf_set "descr" "restart=never service stays stopped after exit"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
restart_never_no_restart_body()
{
	prepare_paths
	make_fixture_svc system exit0 'restart = "never";' \
	    lifecycle-exit "${WORK}/exit0.pid" 0

	start_stack
	if ! wait_for_file exit0.pid; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi
	sleep 1
	atf_check -s exit:0 -o ignore \
	    grep 'service [^ ]*exit0[^ ]*: exited status 0' "$logfile"
	atf_check -s not-exit:0 \
	    grep 'service [^ ]*exit0[^ ]*: restarting\|service [^ ]*exit0[^ ]*: scheduling restart' "$logfile"
	assert_stack_alive
}
restart_never_no_restart_cleanup()
{
	cleanup_common
}

# ===================================================================
# Restart policy: restart=on-failure ignores clean exit
# ===================================================================

atf_test_case restart_on_failure_ignores_clean cleanup
restart_on_failure_ignores_clean_head()
{
	atf_set "descr" "restart=on-failure does not restart on exit(0)"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
restart_on_failure_ignores_clean_body()
{
	prepare_paths
	make_fixture_svc system clean-exit 'restart = "on-failure";' \
	    lifecycle-exit "${WORK}/clean.pid" 0

	start_stack
	if ! wait_for_file clean.pid; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi
	sleep 1
	atf_check -s exit:0 -o ignore \
	    grep 'service [^ ]*clean-exit[^ ]*: exited status 0' "$logfile"
	atf_check -s not-exit:0 \
	    grep 'service [^ ]*clean-exit[^ ]*: restarting\|service [^ ]*clean-exit[^ ]*: scheduling restart' "$logfile"
	assert_stack_alive
}
restart_on_failure_ignores_clean_cleanup()
{
	cleanup_common
}

# ===================================================================
# Restart policy: restart=on-failure restarts on error
# ===================================================================

atf_test_case restart_on_failure_restarts_on_error cleanup
restart_on_failure_restarts_on_error_head()
{
	atf_set "descr" "restart=on-failure restarts after nonzero exit"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
restart_on_failure_restarts_on_error_body()
{
	prepare_paths
	make_fixture_svc system fail-once 'restart = "on-failure";' \
	    lifecycle-restart-once "${WORK}/fail-once.ran" \
	    "${WORK}/fail-once-restarted.pid" 1 pid

	start_stack
	if ! sh -c "i=0; while [ ! -s fail-once-restarted.pid ] && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; test -s fail-once-restarted.pid"; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not restart"
	fi
	atf_check -s exit:0 -o ignore \
	    grep 'service [^ ]*fail-once[^ ]*: exited status 1' "$logfile"
	assert_stack_alive
}
restart_on_failure_restarts_on_error_cleanup()
{
	if [ -f fail-once-restarted.pid ]; then
		kill "$(cat fail-once-restarted.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# ===================================================================
# Restart policy: restart=always restarts on clean exit
# ===================================================================

atf_test_case restart_always_restarts_clean cleanup
restart_always_restarts_clean_head()
{
	atf_set "descr" "restart=always restarts even after exit(0)"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
restart_always_restarts_clean_body()
{
	prepare_paths
	make_fixture_svc system exit0-always 'restart = "always";' \
	    lifecycle-restart-once "${WORK}/exit0-always.ran" \
	    "${WORK}/exit0-always-restarted.pid" 0 pid

	start_stack
	if ! sh -c "i=0; while [ ! -s exit0-always-restarted.pid ] && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; test -s exit0-always-restarted.pid"; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not restart"
	fi
	assert_stack_alive
}
restart_always_restarts_clean_cleanup()
{
	if [ -f exit0-always-restarted.pid ]; then
		kill "$(cat exit0-always-restarted.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# ===================================================================
# Circuit breaker: fast-crashing service gets disabled
# ===================================================================

atf_test_case circuit_breaker_disables cleanup
circuit_breaker_disables_head()
{
	atf_set "descr" "crashing restart=always service is disabled by circuit breaker"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
circuit_breaker_disables_body()
{
	prepare_paths
	make_fixture_svc system crash 'restart = "always"; max_failures = 3;' \
	    lifecycle-exit "${WORK}/crash.pid" 1

	start_stack
	if ! sh -c "i=0; while ! grep -q 'service [^ ]*crash[^ ]*: started pid' '$logfile' && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service [^ ]*crash[^ ]*: started pid' '$logfile'"; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while ! grep -q 'service [^ ]*crash[^ ]*: failed .* disabling' '$logfile' && [ \$i -lt 1800 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service [^ ]*crash[^ ]*: failed .* disabling' '$logfile'"
	assert_stack_alive
}
circuit_breaker_disables_cleanup()
{
	cleanup_common
}

# ===================================================================
# Shutdown: SIGTERM-ignoring service gets SIGKILL after timeout
# ===================================================================

atf_test_case shutdown_kills_sigterm_ignorer cleanup
shutdown_kills_sigterm_ignorer_head()
{
	atf_set "descr" "shutdown kills a service that ignores SIGTERM"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
shutdown_kills_sigterm_ignorer_body()
{
	local svc_pid

	prepare_paths
	make_fixture_svc system ignore-term 'stop_timeout = 1;' \
	    lifecycle-ignore-term "${WORK}/ignore-term.pid"

	start_stack
	if ! wait_for_file ignore-term.pid; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi
	svc_pid=$(cat ignore-term.pid)

	capd_capsule_ctl "$sockpath" shutdown >/dev/null ||
	    atf_fail "Capsule shutdown request failed"
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=
	wait_for_pid_exit "$svc_pid" || {
		cat "$logfile" 2>/dev/null
		atf_fail "SIGTERM-ignoring service survived shutdown"
	}
}
shutdown_kills_sigterm_ignorer_cleanup()
{
	if [ -f ignore-term.pid ]; then
		kill -KILL "$(cat ignore-term.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# ===================================================================
# Shutdown: child subtree is cleaned up
# ===================================================================

atf_test_case shutdown_kills_subtree cleanup
shutdown_kills_subtree_head()
{
	atf_set "descr" "shutdown cleans up child processes spawned by a service"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
shutdown_kills_subtree_body()
{
	local child_pid

	prepare_paths
	make_fixture_svc system subtree 'stop_timeout = 1;' \
	    lifecycle-subtree "${WORK}/subtree-parent.pid" \
	    "${WORK}/subtree-child.pid"

	start_stack
	if ! wait_for_file subtree-child.pid; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi
	child_pid=$(cat subtree-child.pid)

	capd_capsule_ctl "$sockpath" shutdown >/dev/null ||
	    atf_fail "Capsule shutdown request failed"
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=
	wait_for_pid_exit "$child_pid" || {
		cat "$logfile" 2>/dev/null
		atf_fail "service child survived shutdown"
	}
	wait_for_pid_exit "$(cat subtree-parent.pid)" || {
		cat "$logfile" 2>/dev/null
		atf_fail "service parent survived shutdown"
	}
}
shutdown_kills_subtree_cleanup()
{
	if [ -f subtree-child.pid ]; then
		kill -KILL "$(cat subtree-child.pid)" 2>/dev/null || true
	fi
	if [ -f subtree-parent.pid ]; then
		kill -KILL "$(cat subtree-parent.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# ===================================================================
# Managed quiesce: admission closes before the provider acknowledges drain
# ===================================================================

atf_test_case managed_quiesce_roundtrip cleanup
managed_quiesce_roundtrip_head()
{
	atf_set "descr" "switchboard requests managed quiesce and waits for the provider result before termination"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
managed_quiesce_roundtrip_body()
{
	require_ambient_control
	find_capd_service_fixture
	prepare_paths
	make_svc_bin system org.test.quiesce \
	    "activation { boot = true; ipc = [\"org.test.quiesce\"]; }
stop_timeout = 5;
arguments = [\"quiesce\", \"org.test.quiesce\", \"$(pwd)/quiesce.ready\", \"$(pwd)/quiesce.result\"];" \
	    "$capd_service_fixture"
	write_config
	start_stack
	wait_for_file quiesce.ready || atf_fail "quiesce provider did not become ready"
	atf_check -s exit:0 -o match:"stopping" \
	    switchboardctl stop org.test.quiesce/quiesce
	wait_for_file quiesce.result || {
		cat "$logfile" 2>/dev/null
		atf_fail "provider did not complete managed quiesce"
	}
	atf_check -s exit:0 -o inline:"admission=closed
result=complete
" cat quiesce.result
	atf_check -s exit:0 -o ignore grep "service org.test.quiesce/quiesce: stopping" "$logfile"
	assert_stack_alive
}
managed_quiesce_roundtrip_cleanup()
{
	cleanup_common
	rm -f quiesce.ready quiesce.result
}

# ===================================================================
# Private worker channels: explicit, linear authority handoff
# ===================================================================

atf_test_case private_worker_channel cleanup
private_worker_channel_head()
{
	atf_set "descr" "libservice creates a private worker channel whose endpoints survive only the intended fork and cannot be delegated"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
private_worker_channel_body()
{
	find_capd_service_fixture
	prepare_paths
	make_svc_bin system worker-channel \
	    'restart = "never"; arguments = ["worker-channel", "worker-channel.out"];' \
	    "$capd_service_fixture"
	write_config
	start_stack
	if ! wait_for_file worker-channel.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "worker-channel fixture did not complete"
	fi
	atf_check -s exit:0 -o inline:"pair=private
provider_in_child=closed
worker_in_child=open
transfer=none
payload=worker
" cat worker-channel.out
	assert_stack_alive
}
private_worker_channel_cleanup()
{
	cleanup_common
	rm -f worker-channel.out
}

# ===================================================================
# Service environment is minimal
# ===================================================================

atf_test_case service_environment_minimal cleanup
service_environment_minimal_head()
{
	atf_set "descr" "service child receives minimal environment"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
service_environment_minimal_body()
{
	prepare_paths
	make_fixture_svc system env-probe '' \
	    lifecycle-environment "${WORK}/env-probe.out"

	export SHOULD_NOT_LEAK=secret
	start_stack
	unset SHOULD_NOT_LEAK
	if ! wait_for_file env-probe.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	atf_check -s exit:0 -o match:"^PATH=/sbin:/bin:/usr/sbin:/usr/bin$" \
	    grep "^PATH=" env-probe.out
	atf_check -s exit:0 -o match:"^SERVICE_BOOTSTRAP_FD=5$" \
	    grep "^SERVICE_BOOTSTRAP_FD=" env-probe.out
	atf_check -s not-exit:0 grep "^CAPSULE_" env-probe.out
	atf_check -s not-exit:0 grep "^SWITCHBOARD_COMPONENT_FDS=" env-probe.out
	atf_check -s not-exit:0 grep "SHOULD_NOT_LEAK" env-probe.out
	assert_stack_alive
}
service_environment_minimal_cleanup()
{
	cleanup_common
}

# ===================================================================
# Descriptor limits: switchboard raises the inherited ceiling
# ===================================================================

atf_test_case service_descriptor_limit_inheritance cleanup
service_descriptor_limit_inheritance_head()
{
	atf_set "descr" \
	    "switchboard raises its descriptor limit; children inherit it and may lower it"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
service_descriptor_limit_inheritance_body()
{
	require_ambient_control
	prepare_paths
	make_fixture_svc system fd-limit '' \
	    lifecycle-rlimit "${WORK}/fd-limit.out"

	start_stack
	if ! wait_for_file fd-limit.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not report its descriptor limits"
	fi
	i=0
	while [ "$(wc -l < fd-limit.out)" -lt 2 ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	[ "$(wc -l < fd-limit.out)" -eq 2 ] ||
	    atf_fail "service did not finish reporting descriptor limits"
	atf_check -s exit:0 -o save:fd-status.out \
	    switchboardctl status

	inherited=$(sed -n '1p' fd-limit.out)
	lowered=$(sed -n '2p' fd-limit.out)
	reported=$(sed -n \
	    's/.*fd-budget: soft=\([0-9][0-9]*\).*/\1/p' fd-status.out)
	kernel_max=$(sysctl -n kern.maxfilesperproc)

	[ -n "$reported" ] || atf_fail "status omitted descriptor budget"
	[ "$inherited" = "$reported" ] ||
	    atf_fail "child inherited $inherited descriptors; switchboard reports $reported"
	[ "$inherited" -ge "$kernel_max" ] ||
	    atf_fail "switchboard limit $inherited is below kernel maximum $kernel_max"
	[ "$lowered" = 256 ] ||
	    atf_fail "child could not lower its soft descriptor limit: $lowered"
	assert_stack_alive
}
service_descriptor_limit_inheritance_cleanup()
{
	cleanup_common
	rm -f fd-status.out
}

# ===================================================================
# Credential dropping: user= runs as that user
# ===================================================================

atf_test_case service_runs_as_user cleanup
service_runs_as_user_head()
{
	atf_set "descr" "service with user= runs as that user"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
service_runs_as_user_body()
{
	prepare_paths
	make_fixture_svc system whoami 'user = "nobody"; group = "nogroup";' \
	    lifecycle-identity "${WORK}/whoami-svc.out"
	touch whoami-svc.out
	chmod 666 whoami-svc.out

	start_stack
	if ! sh -c "i=0; while [ ! -s whoami-svc.out ] && [ \$i -lt 100 ]; do i=\$((i + 1)); sleep 0.1; done; test -s whoami-svc.out"; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not write output"
	fi
	expected_uid=$(id -u nobody)
	expected_gid=$(pw groupshow nogroup | cut -d: -f3)
	[ "$(head -1 whoami-svc.out)" = "$expected_uid" ] ||
	    atf_fail "service did not run as nobody"
	[ "$(tail -1 whoami-svc.out)" = "$expected_gid" ] ||
	    atf_fail "service did not run with group nogroup"
	assert_stack_alive
}
service_runs_as_user_cleanup()
{
	cleanup_common
}

# ===================================================================
# Authenticated reload: new manifests are forwarded to switchboard
# ===================================================================

atf_test_case control_reload cleanup
control_reload_head()
{
	atf_set "descr" "Capsule control reload triggers manifest reload in switchboard"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
control_reload_body()
{
	start_stack

	# Add a new bundle after startup.
	make_fixture_svc system new-svc '' \
	    lifecycle-hold "${WORK}/new-svc.pid" - running

	# Use Capsule's authenticated control endpoint; ambient SIGHUP is shielded.
	reload_stack

	if ! wait_for_file new-svc.pid; then
		cat "$logfile" 2>/dev/null
		atf_fail "new service did not start after reload"
	fi
	assert_stack_alive
}
control_reload_cleanup()
{
	if [ -f new-svc.pid ]; then
		kill "$(cat new-svc.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# ===================================================================
# Restart backoff: fast-crashing service gets delayed restart
# ===================================================================

atf_test_case restart_backoff cleanup
restart_backoff_head()
{
	atf_set "descr" "fast-crashing service gets delayed restart (backoff)"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
restart_backoff_body()
{
	prepare_paths
	make_fixture_svc system fastcrash 'restart = "always";' \
	    lifecycle-exit "${WORK}/fastcrash.pid" 1

	start_stack
	if ! sh -c "i=0; while ! grep -q 'service [^ ]*fastcrash[^ ]*: started pid' '$logfile' && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service [^ ]*fastcrash[^ ]*: started pid' '$logfile'"; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while ! grep -q 'scheduling restart' '$logfile' && [ \$i -lt 100 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'scheduling restart' '$logfile'"
	assert_stack_alive
}
restart_backoff_cleanup()
{
	cleanup_common
}

# ===================================================================
# Explicit withdrawal: a ready provider withdraws one claimed name
# ===================================================================

atf_test_case svc_unregister_explicit cleanup
svc_unregister_explicit_head()
{
	atf_set "descr" "a ready provider can explicitly withdraw one claimed name via SVC_OP_NAME_WITHDRAW"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
svc_unregister_explicit_body()
{
	find_capd_service_fixture

	find_switchboard
	prepare_paths
	make_svc_bin system org.test.unreg.svc \
	    "activation { boot = true; ipc = [\"org.test.unreg.svc\"]; }
arguments = [\"unregister\", \"org.test.unreg.svc\", \"$(pwd)/unreg-register.out\", \"$(pwd)/unreg-result.out\"];" \
	    "$capd_service_fixture"
	write_config

	start_stack
	if ! wait_for_file unreg-register.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not register"
	fi
	atf_check -s exit:0 -o match:"register_status=0" \
	    cat unreg-register.out

	if ! wait_for_file unreg-result.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not unregister"
	fi
	atf_check -s exit:0 -o match:"unregister_status=0" \
	    cat unreg-result.out

	# Verify switchboard logged the explicit lifecycle transition.
	atf_check -s exit:0 -o ignore \
	    grep "org.test.unreg.svc.*withdrawn\|withdrawn.*org.test.unreg.svc" "$logfile"
	assert_stack_alive
}
svc_unregister_explicit_cleanup()
{
	cleanup_common
	rm -f unreg_svc unreg_svc.c unreg-register.out unreg-result.out
}

# ===================================================================
# Claim protocol state machine
# ===================================================================

atf_test_case svc_name_claim_state_machine cleanup
svc_name_claim_state_machine_head()
{
	atf_set "descr" \
	    "name claims enforce manifest authority, duplicate state, withdrawal, and re-claim before READY"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
svc_name_claim_state_machine_body()
{
	find_capd_service_fixture

	prepare_paths
	make_svc_bin system org.test.claim.svc \
	    "activation { boot = true; ipc = [\"org.test.claim.svc\"]; }
arguments = [\"claim-protocol\", \"org.test.claim.svc\", \"$(pwd)/claim-state.out\"];" \
	    "$capd_service_fixture"
	write_config

	start_stack
	if ! wait_for_file claim-state.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "claim protocol fixture did not complete"
	fi
	atf_check -s exit:0 -o inline:"unauthorized=EACCES
first=ok
duplicate=EALREADY
withdraw=ok
repeated_withdraw=ENOENT
reclaim=ok
" cat claim-state.out
	assert_stack_alive
}
svc_name_claim_state_machine_cleanup()
{
	cleanup_common
	rm -f claim_svc claim_svc.c claim-state.out
}

# ===================================================================
# Withdrawal races an in-flight activation
# ===================================================================

atf_test_case svc_withdraw_cancels_activation cleanup
svc_withdraw_cancels_activation_head()
{
	atf_set "descr" \
	    "withdrawing an activating name fails queued lookups and rejects the late result"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
svc_withdraw_cancels_activation_body()
{
	local client_bundle i

	find_capd_service_fixture
	prepare_paths
	make_svc_bin system org.test.cancel.svc \
	    "activation { boot = true; ipc = [\"org.test.cancel.svc\"]; }
arguments = [\"cancel-activation\", \"org.test.cancel.svc\",
    \"$(pwd)/cancel-provider.ready\", \"$(pwd)/cancel-provider.trigger\",
    \"$(pwd)/cancel-provider.result\"];" \
	    "$capd_service_fixture"
	# compat-lookup reads "<flattened-runtime-label>.target"; the runtime
	# label is org.test.cancel-client/cancel-client.
	printf '%s\n' "org.test.cancel.svc" > \
	    org.test.cancel-client.cancel-client.target
	client_bundle=$(make_svc_bin system cancel-client \
	    'restart = "never"; arguments = ["compat-lookup"];' \
	    "$capd_service_fixture")
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${client_bundle}/Units/cancel-client.unit/Unit.ucl"
	write_config

	start_stack
	wait_for_file cancel-provider.ready ||
	    atf_fail "provider did not complete check-in"
	i=0
	while ! grep -q "activation of endpoint 'org.test.cancel.svc' requested" \
	    "$logfile" 2>/dev/null && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ "$i" -ge 100 ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "lookup did not trigger endpoint activation"
	fi
	touch cancel-provider.trigger
	wait_for_file cancel-provider.result ||
	    atf_fail "provider did not report activation cancellation"
	wait_for_file org.test.cancel-client.cancel-client.result ||
	    atf_fail "queued client did not receive cancellation"
	atf_check -s exit:0 -o inline:"withdraw=ok
pending=ECANCELED
late_result=EPROTO
" cat cancel-provider.result
	atf_check -s exit:0 -o match:'^rc=1$' cat org.test.cancel-client.cancel-client.result
	atf_check -s exit:0 -o ignore \
	    grep "activation of endpoint 'org.test.cancel.svc'.*Operation canceled" \
	    "$logfile"
	assert_stack_alive
}
svc_withdraw_cancels_activation_cleanup()
{
	cleanup_common
	rm -f cancel-client.target org.test.cancel-client.cancel-client.result \
	    cancel-provider.ready cancel-provider.trigger \
	    cancel-provider.result
}

# ===================================================================
# Process-descriptor capability-mode readiness
# ===================================================================

atf_test_case capmode_is_authoritative_readiness cleanup
capmode_is_authoritative_readiness_head()
{
	atf_set "descr" \
	    "endpoint publication requires both READY and verified capability-mode entry"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
capmode_is_authoritative_readiness_body()
{
	require_ambient_control
	local i pid

	find_capd_service_fixture
	prepare_paths
	make_svc_bin system org.test.capmode.gate \
	    'arguments = ["readiness-gate", "protocol-ready.out", "capmode-ready.out"];' \
	    "$capd_service_fixture"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${APPS_DIR}/org.test.capmode.gate.cap/Units/gate.unit/Unit.ucl"
	write_config
	start_stack

	if ! wait_for_file protocol-ready.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "fixture did not send the legacy READY message"
	fi
	atf_check -s exit:0 -o match:"org.test.capmode.gate.*starting" \
	    switchboardctl status
	atf_check -s exit:0 -o not-match:"org.test.capmode.gate.*running" \
	    switchboardctl status

	pid=$(sed -n 's/^pid=\([0-9][0-9]*\).*/\1/p' protocol-ready.out)
	[ -n "$pid" ] || atf_fail "fixture did not report its pid"
	kill -USR1 "$pid"
	if ! wait_for_file capmode-ready.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "fixture did not enter capability mode"
	fi
	i=0
	while [ "$i" -lt 100 ]; do
		if switchboardctl status |
		    grep -q "org.test.capmode.gate.*running"; then
			break
		fi
		i=$((i + 1))
		sleep 0.1
	done
	[ "$i" -lt 100 ] ||
	    atf_fail "NOTE_CAPMODE did not promote the service to RUNNING"
	atf_check -s exit:0 -o match:"capability sandbox entered" \
	    grep "capability sandbox entered" "$logfile"
}
capmode_is_authoritative_readiness_cleanup()
{
	cleanup_common
	rm -f protocol-ready.out capmode-ready.out
}

# ===================================================================
# Provider-driven idle shutdown: stop after timeout, relaunch on demand
# ===================================================================

atf_test_case idle_stop_and_relaunch cleanup
idle_stop_and_relaunch_head()
{
	atf_set "descr" "a provider that opts into idle shutdown is stopped after the timeout, keeps its name reservation, and is relaunched by the next lookup"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
idle_stop_and_relaunch_body()
{
	require_ambient_control
	local pid1 pid2

	find_capd_service_fixture
	prepare_paths
	make_svc_bin system org.test.idle.svc \
	    "activation { boot = true; ipc = [\"org.test.idle.svc\"]; }
arguments = [\"idle-provider\", \"org.test.idle.svc\", \"1\", \"$(pwd)/idlep\"];" \
	    "$capd_service_fixture"
	write_config
	start_stack
	if ! wait_for_file idlep.launch1; then
		cat "$logfile" 2>/dev/null
		atf_fail "idle provider did not become ready"
	fi
	pid1=$(sed -n 's/^pid=//p' idlep.launch1)
	[ -n "$pid1" ] || atf_fail "first launch did not record a pid"

	# switchboard must idle-stop it, keeping reservations for on-demand relaunch.
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while ! grep -q 'org.test.idle.svc.*idle timeout, stopping' '$logfile' && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'idle timeout, stopping' '$logfile'"
	# It must not still be running, and must not have been removed entirely.
	atf_check -s exit:0 -o not-match:"org.test.idle.svc.*running" \
	    switchboardctl status
	atf_check -s exit:0 -o match:"org.test.idle.svc" \
	    switchboardctl status

	# A lookup relaunches it on demand and succeeds.
	if ! run_lookup_client org.test.idle.svc 15; then
		cat "$logfile" 2>/dev/null
		atf_fail "on-demand lookup of the idle-stopped provider failed"
	fi
	if ! wait_for_file idlep.launch2; then
		cat "$logfile" 2>/dev/null
		atf_fail "provider was not relaunched on demand"
	fi
	pid2=$(sed -n 's/^pid=//p' idlep.launch2)
	[ -n "$pid2" ] && [ "$pid2" != "$pid1" ] ||
	    atf_fail "relaunch pid ($pid2) did not differ from first pid ($pid1)"
	assert_stack_alive
}
idle_stop_and_relaunch_cleanup()
{
	cleanup_common
	rm -f idlep.count idlep.launch1 idlep.launch2
}

# ===================================================================
# Demand before the idle timeout keeps the provider running
# ===================================================================

atf_test_case idle_demand_cancels_stop cleanup
idle_demand_cancels_stop_head()
{
	atf_set "descr" "a lookup before the idle timeout cancels the pending idle stop; the provider keeps running"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
idle_demand_cancels_stop_body()
{
	require_ambient_control
	find_capd_service_fixture
	prepare_paths
	make_svc_bin system org.test.idle.demand \
	    "activation { boot = true; ipc = [\"org.test.idle.demand\"]; }
arguments = [\"idle-provider\", \"org.test.idle.demand\", \"5\", \"$(pwd)/idled\"];" \
	    "$capd_service_fixture"
	write_config
	start_stack
	if ! wait_for_file idled.launch1; then
		cat "$logfile" 2>/dev/null
		atf_fail "idle provider did not become ready"
	fi

	# Create demand well inside the 5s window; the naming broker cancels the
	# idle timer.
	if ! run_lookup_client org.test.idle.demand 10; then
		cat "$logfile" 2>/dev/null
		atf_fail "lookup that should keep the provider alive failed"
	fi

	# Wait past the original timeout and confirm it never idle-stopped or
	# relaunched.
	sleep 6
	atf_check -s not-exit:0 \
	    grep 'org.test.idle.demand.*idle timeout, stopping' "$logfile"
	atf_check -s exit:0 -o match:"org.test.idle.demand.*running" \
	    switchboardctl status
	[ ! -f idled.launch2 ] ||
	    atf_fail "provider was relaunched despite demand keeping it alive"
	assert_stack_alive
}
idle_demand_cancels_stop_cleanup()
{
	cleanup_common
	rm -f idled.count idled.launch1 idled.launch2
}

# ===================================================================
# Provider cancels its own pending idle stop with seconds == 0
# ===================================================================

atf_test_case idle_cancel_keeps_running cleanup
idle_cancel_keeps_running_head()
{
	atf_set "descr" "service_idle_shutdown(ctx, 0) clears a pending idle stop so the provider keeps running"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
idle_cancel_keeps_running_body()
{
	require_ambient_control
	find_capd_service_fixture
	prepare_paths
	make_svc_bin system org.test.idle.cancel \
	    "activation { boot = true; ipc = [\"org.test.idle.cancel\"]; }
arguments = [\"idle-cancel\", \"org.test.idle.cancel\", \"1\", \"$(pwd)/idlec.ready\"];" \
	    "$capd_service_fixture"
	write_config
	start_stack
	if ! wait_for_file idlec.ready; then
		cat "$logfile" 2>/dev/null
		atf_fail "idle-cancel provider did not become ready"
	fi

	# Past the armed (then cancelled) 1s timeout: it must still be running.
	sleep 3
	atf_check -s not-exit:0 \
	    grep 'org.test.idle.cancel.*idle timeout, stopping' "$logfile"
	atf_check -s exit:0 -o match:"org.test.idle.cancel.*running" \
	    switchboardctl status
	assert_stack_alive
}
idle_cancel_keeps_running_cleanup()
{
	cleanup_common
	rm -f idlec.ready
}

# Control-request input validation over the capability plane: switchboard must
# reject a request with a nonzero reserved flags field or an embedded NUL in the
# text payload (EINVAL=22).  capd_protocol_fixture crafts the malformed request
# and sends it over system.switchboard; the reply status is the rejection.  Skips
# when this harness has no ambient control channel (control is also validated by
# the VM boot smoke test).
atf_test_case sctl_rejects_malformed_requests cleanup
sctl_rejects_malformed_requests_head()
{
	atf_set "descr" \
	    "Control protocol rejects unknown flags and embedded NUL labels"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
sctl_rejects_malformed_requests_body()
{
	start_stack
	require_ambient_control
	for kind in flags nul; do
		atf_check -s exit:0 -o match:"status=22" \
		    "$(atf_get_srcdir)/capd_protocol_fixture" \
		    control-invalid "$kind"
	done
	assert_stack_alive
}
sctl_rejects_malformed_requests_cleanup()
{
	cleanup_common
}

# ===================================================================
# Liveness watchdog: a heartbeating unit is left running
# ===================================================================

atf_test_case watchdog_heartbeat_keeps_alive cleanup
watchdog_heartbeat_keeps_alive_head()
{
	atf_set "descr" "a unit that heartbeats within its watchdog interval is never restarted"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
watchdog_heartbeat_keeps_alive_body()
{
	find_capd_service_fixture
	prepare_paths
	# A generous interval versus the ~0.5s heartbeat cadence keeps the margin
	# wide enough for the emulated launch latency; the wedge tests use a tight
	# interval where the expiry is the intended outcome.
	make_svc_bin system org.test.wd.hold \
	    "activation { boot = true; }
watchdog { interval = 8; }
restart = \"always\";
arguments = [\"watchdog-hold\", \"org.test.wd.hold\", \"$(pwd)/wdh.ready\"];" \
	    "$capd_service_fixture"
	write_config
	start_stack
	if ! wait_for_file wdh.ready; then
		cat "$logfile" 2>/dev/null
		atf_fail "watchdog provider did not become ready"
	fi
	# Wait well past the 8s interval; a heartbeating unit must not expire.
	sleep 12
	# No watchdog expiry, and the unit was launched exactly once (never
	# killed and relaunched) — proof the heartbeats kept resetting the timer.
	atf_check -s not-exit:0 -o ignore -e ignore \
	    grep 'org.test.wd.hold.*watchdog expired' "$logfile"
	launches=$(grep -c 'org.test.wd.hold.*started pid' "$logfile")
	[ "$launches" = "1" ] ||
	    atf_fail "heartbeating unit was (re)launched $launches times, expected 1"
	assert_stack_alive
}
watchdog_heartbeat_keeps_alive_cleanup()
{
	cleanup_common
	rm -f wdh.ready
}

# ===================================================================
# Liveness watchdog: a wedged unit (stops heartbeating) is restarted
# ===================================================================

atf_test_case watchdog_restarts_wedged cleanup
watchdog_restarts_wedged_head()
{
	atf_set "descr" "a unit that stops heartbeating is killed by the watchdog and relaunched by its restart policy"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
watchdog_restarts_wedged_body()
{
	local pid1 pid2

	find_capd_service_fixture
	prepare_paths
	make_svc_bin system org.test.wd.wedge \
	    "activation { boot = true; }
watchdog { interval = 2; }
restart = \"always\";
arguments = [\"watchdog-wedge\", \"org.test.wd.wedge\", \"$(pwd)/wdw\"];" \
	    "$capd_service_fixture"
	write_config
	start_stack
	if ! wait_for_file wdw.launch1; then
		cat "$logfile" 2>/dev/null
		atf_fail "watchdog provider did not become ready"
	fi
	pid1=$(sed -n 's/^pid=//p' wdw.launch1)
	[ -n "$pid1" ] || atf_fail "first launch did not record a pid"

	# The first instance never heartbeats: the watchdog must fire.
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while ! grep -q 'org.test.wd.wedge.*watchdog expired' '$logfile' && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'watchdog expired' '$logfile'"

	# The restart policy must relaunch it; the recovered instance heartbeats.
	if ! sh -c "i=0; while [ ! -s wdw.launch2 ] && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; test -s wdw.launch2"; then
		cat "$logfile" 2>/dev/null
		atf_fail "wedged unit was not restarted after watchdog expiry"
	fi
	pid2=$(sed -n 's/^pid=//p' wdw.launch2)
	[ -n "$pid2" ] && [ "$pid2" != "$pid1" ] ||
	    atf_fail "relaunch pid ($pid2) did not differ from first pid ($pid1)"
	assert_stack_alive
}
watchdog_restarts_wedged_cleanup()
{
	cleanup_common
	rm -f wdw.count wdw.launch1 wdw.launch2
}

# ===================================================================
# Liveness watchdog: end-user (USER-domain) units are watched too
# ===================================================================

atf_test_case watchdog_user_unit_restarts cleanup
watchdog_user_unit_restarts_head()
{
	atf_set "descr" "a wedged USER-domain unit is restarted by the watchdog, proving the feature serves end-user applications"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
watchdog_user_unit_restarts_body()
{
	find_capd_service_fixture
	prepare_paths
	make_svc_bin user org.test.wd.userapp \
	    "activation { boot = true; }
watchdog { interval = 2; }
restart = \"always\";
arguments = [\"watchdog-wedge\", \"org.test.wd.userapp\", \"$(pwd)/wdu\"];" \
	    "$capd_service_fixture"
	write_config
	start_stack
	if ! wait_for_file wdu.launch1; then
		cat "$logfile" 2>/dev/null
		atf_fail "user watchdog unit did not become ready"
	fi
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while ! grep -q 'org.test.wd.userapp.*watchdog expired' '$logfile' && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'watchdog expired' '$logfile'"
	if ! sh -c "i=0; while [ ! -s wdu.launch2 ] && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; test -s wdu.launch2"; then
		cat "$logfile" 2>/dev/null
		atf_fail "wedged user unit was not restarted after watchdog expiry"
	fi
	assert_stack_alive
}
watchdog_user_unit_restarts_cleanup()
{
	cleanup_common
	rm -f wdu.count wdu.launch1 wdu.launch2
}

atf_init_test_cases()
{
	# Restart policies
	atf_add_test_case restart_never_no_restart
	atf_add_test_case restart_on_failure_ignores_clean
	atf_add_test_case restart_on_failure_restarts_on_error
	atf_add_test_case restart_always_restarts_clean
	atf_add_test_case circuit_breaker_disables
	atf_add_test_case restart_backoff

	# Shutdown
	atf_add_test_case shutdown_kills_sigterm_ignorer
	atf_add_test_case shutdown_kills_subtree
	atf_add_test_case managed_quiesce_roundtrip
	atf_add_test_case private_worker_channel

	# Service contracts
	atf_add_test_case service_environment_minimal
	atf_add_test_case service_descriptor_limit_inheritance
	atf_add_test_case service_runs_as_user

	# Reload
	atf_add_test_case control_reload

	# Naming protocol
	atf_add_test_case svc_unregister_explicit
	atf_add_test_case svc_name_claim_state_machine
	atf_add_test_case svc_withdraw_cancels_activation
	atf_add_test_case sctl_rejects_malformed_requests
	atf_add_test_case capmode_is_authoritative_readiness

	# Provider-driven idle shutdown
	atf_add_test_case idle_stop_and_relaunch
	atf_add_test_case idle_demand_cancels_stop
	atf_add_test_case idle_cancel_keeps_running

	# Liveness watchdog (system + user domains)
	atf_add_test_case watchdog_heartbeat_keeps_alive
	atf_add_test_case watchdog_restarts_wedged
	atf_add_test_case watchdog_user_unit_restarts
}
