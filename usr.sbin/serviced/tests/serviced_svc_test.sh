#
# SPDX-License-Identifier: BSD-2-Clause
#
# Service lifecycle tests for serviced.
#
# Ported from authorityd_stress_test.sh and authorityd_svc_test.sh for the
# two-daemon architecture (authorityd + serviced).  These tests verify
# restart policies, shutdown sequencing, credential dropping,
# environment contracts, and dependency ordering.
#

_helpers="$(dirname "$0")/test_helpers.sh"
if [ ! -f "$_helpers" ]; then
	_helpers="/usr/src/usr.sbin/serviced/tests/test_helpers.sh"
fi
. "$_helpers"

assert_stack_alive()
{
	if ! capd_guardian_is_running; then
		cat "$logfile" 2>/dev/null
		atf_fail "authorityd exited unexpectedly"
	fi
	atf_check -s exit:0 -o match:"running" \
	    authorityctl -s "$sockpath" status
}

# ===================================================================
# Restart policy: restart=never
# ===================================================================

atf_test_case restart_never_no_restart cleanup
restart_never_no_restart_head()
{
	atf_set "descr" "restart=never service stays stopped after exit"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
restart_never_no_restart_body()
{
	prepare_paths
	make_svc system exit0 'restart = "never";' \
	    '#!/bin/sh' \
	    "echo \$\$ > ${WORK}/exit0.pid" \
	    'exit 0'

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
	require_authority_stack_kmods
}
restart_on_failure_ignores_clean_body()
{
	prepare_paths
	make_svc system clean-exit 'restart = "on-failure";' \
	    '#!/bin/sh' \
	    "echo \$\$ > ${WORK}/clean.pid" \
	    'exit 0'

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
	require_authority_stack_kmods
}
restart_on_failure_restarts_on_error_body()
{
	prepare_paths
	make_svc system fail-once 'restart = "on-failure";' \
	    '#!/bin/sh' \
	    "if [ ! -f ${WORK}/fail-once.ran ]; then" \
	    "    touch ${WORK}/fail-once.ran" \
	    '    exit 1' \
	    'fi' \
	    "echo \$\$ > ${WORK}/fail-once-restarted.pid" \
	    'sleep 60'

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
	require_authority_stack_kmods
}
restart_always_restarts_clean_body()
{
	prepare_paths
	make_svc system exit0-always 'restart = "always";' \
	    '#!/bin/sh' \
	    "if [ ! -f ${WORK}/exit0-always.ran ]; then" \
	    "    touch ${WORK}/exit0-always.ran" \
	    '    exit 0' \
	    'fi' \
	    "echo \$\$ > ${WORK}/exit0-always-restarted.pid" \
	    'sleep 60'

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
	require_authority_stack_kmods
}
circuit_breaker_disables_body()
{
	prepare_paths
	make_svc system crash 'restart = "always"; max_failures = 3;' \
	    '#!/bin/sh' \
	    'exit 1'

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
	require_authority_stack_kmods
}
shutdown_kills_sigterm_ignorer_body()
{
	local svc_pid

	prepare_paths
	make_svc system ignore-term 'stop_timeout = 1;' \
	    '#!/bin/sh' \
	    "echo \$\$ > ${WORK}/ignore-term.pid" \
	    'trap "" TERM' \
	    'while :; do sleep 1; done'

	start_stack
	if ! wait_for_file ignore-term.pid; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi
	svc_pid=$(cat ignore-term.pid)

	atf_check -s exit:0 -o ignore authorityctl -s "$sockpath" shutdown
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=
	atf_check -s not-exit:0 -e ignore kill -0 "$svc_pid"
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
	require_authority_stack_kmods
}
shutdown_kills_subtree_body()
{
	local child_pid

	prepare_paths
	make_svc system subtree 'stop_timeout = 1;' \
	    '#!/bin/sh' \
	    'sleep 60 &' \
	    "echo \$! > ${WORK}/subtree-child.pid" \
	    "echo \$\$ > ${WORK}/subtree-parent.pid" \
	    'wait'

	start_stack
	if ! wait_for_file subtree-child.pid; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi
	child_pid=$(cat subtree-child.pid)

	atf_check -s exit:0 -o ignore authorityctl -s "$sockpath" shutdown
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=
	atf_check -s not-exit:0 -e ignore kill -0 "$child_pid"
	atf_check -s not-exit:0 -e ignore kill -0 "$(cat subtree-parent.pid)"
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
	atf_set "descr" "serviced requests managed quiesce and waits for the provider result before termination"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
managed_quiesce_roundtrip_body()
{
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
	    servicectl -s "${CTL_SOCK}" stop org.test.quiesce/quiesce
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
	require_authority_stack_kmods
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
	require_authority_stack_kmods
}
service_environment_minimal_body()
{
	prepare_paths
	make_svc system env-probe '' \
	    '#!/bin/sh' \
	    "env | sort > ${WORK}/env-probe.out" \
	    'sleep 20'

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
	atf_check -s not-exit:0 grep "^AUTHORITYD_" env-probe.out
	atf_check -s not-exit:0 grep "^SERVICED_COMPONENT_FDS=" env-probe.out
	atf_check -s not-exit:0 grep "SHOULD_NOT_LEAK" env-probe.out
	assert_stack_alive
}
service_environment_minimal_cleanup()
{
	cleanup_common
}

# ===================================================================
# Descriptor limits: serviced raises the inherited ceiling
# ===================================================================

atf_test_case service_descriptor_limit_inheritance cleanup
service_descriptor_limit_inheritance_head()
{
	atf_set "descr" \
	    "serviced raises its descriptor limit; children inherit it and may lower it"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
service_descriptor_limit_inheritance_body()
{
	prepare_paths
	make_svc system fd-limit '' \
	    '#!/bin/sh' \
	    "ulimit -n > ${WORK}/fd-limit.out" \
	    'ulimit -S -n 256' \
	    "ulimit -n >> ${WORK}/fd-limit.out" \
	    'sleep 20'

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
	    servicectl -s "${CTL_SOCK}" status

	inherited=$(sed -n '1p' fd-limit.out)
	lowered=$(sed -n '2p' fd-limit.out)
	reported=$(sed -n \
	    's/.*fd-budget: soft=\([0-9][0-9]*\).*/\1/p' fd-status.out)
	kernel_max=$(sysctl -n kern.maxfilesperproc)

	[ -n "$reported" ] || atf_fail "status omitted descriptor budget"
	[ "$inherited" = "$reported" ] ||
	    atf_fail "child inherited $inherited descriptors; serviced reports $reported"
	[ "$inherited" -ge "$kernel_max" ] ||
	    atf_fail "serviced limit $inherited is below kernel maximum $kernel_max"
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
	require_authority_stack_kmods
}
service_runs_as_user_body()
{
	prepare_paths
	make_svc system whoami 'user = "nobody"; group = "nogroup";' \
	    '#!/bin/sh' \
	    "id -un > ${WORK}/whoami-svc.out" \
	    "id -gn >> ${WORK}/whoami-svc.out" \
	    'sleep 60'
	touch whoami-svc.out
	chmod 666 whoami-svc.out

	start_stack
	if ! sh -c "i=0; while [ ! -s whoami-svc.out ] && [ \$i -lt 100 ]; do i=\$((i + 1)); sleep 0.1; done; test -s whoami-svc.out"; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not write output"
	fi
	atf_check -s exit:0 -o match:"nobody" head -1 whoami-svc.out
	atf_check -s exit:0 -o match:"nogroup" tail -1 whoami-svc.out
	assert_stack_alive
}
service_runs_as_user_cleanup()
{
	cleanup_common
}

# ===================================================================
# Authenticated reload: new manifests are forwarded to serviced
# ===================================================================

atf_test_case control_reload cleanup
control_reload_head()
{
	atf_set "descr" "Authority control reload triggers manifest reload in serviced"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
control_reload_body()
{
	start_stack

	# Add a new bundle after startup.
	make_svc system new-svc '' \
	    '#!/bin/sh' \
	    "echo \$\$ > ${WORK}/new-svc.pid" \
	    'sleep 60'

	# Use Authority's authenticated control endpoint; ambient SIGHUP is shielded.
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
	require_authority_stack_kmods
}
restart_backoff_body()
{
	prepare_paths
	make_svc system fastcrash 'restart = "always";' \
	    '#!/bin/sh' \
	    'exit 1'

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
	require_authority_stack_kmods
}
svc_unregister_explicit_body()
{
	find_capd_service_fixture

	find_serviced
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

	# Verify serviced logged the explicit lifecycle transition.
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
	require_authority_stack_kmods
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
	require_authority_stack_kmods
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
	require_authority_stack_kmods
}
capmode_is_authoritative_readiness_body()
{
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
	    servicectl -s "${CTL_SOCK}" status
	atf_check -s exit:0 -o not-match:"org.test.capmode.gate.*running" \
	    servicectl -s "${CTL_SOCK}" status

	pid=$(sed -n 's/^pid=\([0-9][0-9]*\).*/\1/p' protocol-ready.out)
	[ -n "$pid" ] || atf_fail "fixture did not report its pid"
	kill -USR1 "$pid"
	if ! wait_for_file capmode-ready.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "fixture did not enter capability mode"
	fi
	i=0
	while [ "$i" -lt 100 ]; do
		if servicectl -s "${CTL_SOCK}" status |
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
# Control-socket authorization: unprivileged peer denied privileged op
# ===================================================================

atf_test_case sctl_privilege_denied cleanup
sctl_privilege_denied_head()
{
	atf_set "descr" "unprivileged peer cannot run a privileged control op (reload); control socket is root-owned and not world-accessible"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
sctl_privilege_denied_body()
{
	prepare_paths
	start_stack

	# Wait for serviced to create its control socket.
	i=0
	while [ ! -S "${CTL_SOCK}" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -S "${CTL_SOCK}" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "serviced did not create control socket"
	fi

	# Reliable core assertions: the control socket is owned by root and
	# grants no access to "other" (world).  serviced binds it 0770.
	atf_check -s exit:0 -o match:"^root$" \
	    stat -f "%Su" "${CTL_SOCK}"
	atf_check -s exit:0 -o match:"^770$" \
	    stat -f "%Lp" "${CTL_SOCK}"

	# Best-effort live denial: allow nobody to reach the socket, then
	# attempt a privileged op as nobody.  It must be denied — either the
	# kernel refuses the connect or serviced returns EPERM.  It must never
	# report success (status=0).
	chmod 0777 "${WORK}" 2>/dev/null || true
	chmod 0777 "${CTL_SOCK}" 2>/dev/null || true

	atf_check -s exit:0 "$(atf_get_srcdir)/capd_protocol_fixture" \
	    control-deny "${CTL_SOCK}" sctl-deny.out
	atf_check -s exit:0 -o match:"status=" cat sctl-deny.out
	atf_check -s exit:0 -o not-match:"status=0$" cat sctl-deny.out
	assert_stack_alive
}
sctl_privilege_denied_cleanup()
{
	cleanup_common
	rm -f sctl-deny.out
}

atf_test_case sctl_rejects_malformed_requests cleanup
sctl_rejects_malformed_requests_head()
{
	atf_set "descr" \
	    "Control protocol rejects unknown flags and embedded NUL labels"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
sctl_rejects_malformed_requests_body()
{
	start_stack
	for kind in flags nul; do
		atf_check -s exit:0 -o match:"status=22" \
		    "$(atf_get_srcdir)/capd_protocol_fixture" \
		    control-invalid "${CTL_SOCK}" "$kind"
	done
	assert_stack_alive
}
sctl_rejects_malformed_requests_cleanup()
{
	cleanup_common
}

# ===================================================================
# Provider-driven idle shutdown: stop after timeout, relaunch on demand
# ===================================================================

atf_test_case idle_stop_and_relaunch cleanup
idle_stop_and_relaunch_head()
{
	atf_set "descr" "a provider that opts into idle shutdown is stopped after the timeout, keeps its name reservation, and is relaunched by the next lookup"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
idle_stop_and_relaunch_body()
{
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

	# serviced must idle-stop it, keeping reservations for on-demand relaunch.
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while ! grep -q 'org.test.idle.svc.*idle timeout, stopping' '$logfile' && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'idle timeout, stopping' '$logfile'"
	# It must not still be running, and must not have been removed entirely.
	atf_check -s exit:0 -o not-match:"org.test.idle.svc.*running" \
	    servicectl -s "${CTL_SOCK}" status
	atf_check -s exit:0 -o match:"org.test.idle.svc" \
	    servicectl -s "${CTL_SOCK}" status

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
	require_authority_stack_kmods
}
idle_demand_cancels_stop_body()
{
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
	    servicectl -s "${CTL_SOCK}" status
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
	require_authority_stack_kmods
}
idle_cancel_keeps_running_body()
{
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
	    servicectl -s "${CTL_SOCK}" status
	assert_stack_alive
}
idle_cancel_keeps_running_cleanup()
{
	cleanup_common
	rm -f idlec.ready
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
	atf_add_test_case capmode_is_authoritative_readiness

	# Control-socket authorization
	atf_add_test_case sctl_privilege_denied
	atf_add_test_case sctl_rejects_malformed_requests

	# Provider-driven idle shutdown
	atf_add_test_case idle_stop_and_relaunch
	atf_add_test_case idle_demand_cancels_stop
	atf_add_test_case idle_cancel_keeps_running
}
