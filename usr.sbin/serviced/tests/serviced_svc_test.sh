#
# SPDX-License-Identifier: BSD-2-Clause
#
# Service lifecycle tests for serviced.
#
# Ported from oracled_stress_test.sh and oracled_svc_test.sh for the
# two-daemon architecture (oracled + serviced).  These tests verify
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
		atf_fail "oracled exited unexpectedly"
	fi
	atf_check -s exit:0 -o match:"running" \
	    oraclectl -s "$sockpath" status
}

# ===================================================================
# Restart policy: restart=never
# ===================================================================

atf_test_case restart_never_no_restart cleanup
restart_never_no_restart_head()
{
	atf_set "descr" "restart=never service stays stopped after exit"
	atf_set "require.user" "root"
	require_oracle_stack_kmods
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
	    grep 'service exit0: exited status 0' "$logfile"
	atf_check -s not-exit:0 \
	    grep 'service exit0: restarting\|service exit0: scheduling restart' "$logfile"
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
	require_oracle_stack_kmods
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
	    grep 'service clean-exit: exited status 0' "$logfile"
	atf_check -s not-exit:0 \
	    grep 'service clean-exit: restarting\|service clean-exit: scheduling restart' "$logfile"
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
	require_oracle_stack_kmods
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
	    grep 'service fail-once: exited status 1' "$logfile"
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
	require_oracle_stack_kmods
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
	require_oracle_stack_kmods
}
circuit_breaker_disables_body()
{
	prepare_paths
	make_svc system crash 'restart = "always"; max_failures = 3;' \
	    '#!/bin/sh' \
	    'exit 1'

	start_stack
	if ! sh -c "i=0; while ! grep -q 'service crash: started pid' '$logfile' && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service crash: started pid' '$logfile'"; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while ! grep -q 'service crash: failed .* disabling' '$logfile' && [ \$i -lt 1800 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service crash: failed .* disabling' '$logfile'"
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
	require_oracle_stack_kmods
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

	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" shutdown
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
	require_oracle_stack_kmods
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

	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" shutdown
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
# Service environment is minimal
# ===================================================================

atf_test_case service_environment_minimal cleanup
service_environment_minimal_head()
{
	atf_set "descr" "service child receives minimal environment"
	atf_set "require.user" "root"
	require_oracle_stack_kmods
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
	atf_check -s not-exit:0 grep "^ORACLED_" env-probe.out
	atf_check -s not-exit:0 grep "^SERVICED_COMPONENT_FDS=" env-probe.out
	atf_check -s not-exit:0 grep "SHOULD_NOT_LEAK" env-probe.out
	assert_stack_alive
}
service_environment_minimal_cleanup()
{
	cleanup_common
}

# ===================================================================
# Credential dropping: user= runs as that user
# ===================================================================

atf_test_case service_runs_as_user cleanup
service_runs_as_user_head()
{
	atf_set "descr" "service with user= runs as that user"
	atf_set "require.user" "root"
	require_oracle_stack_kmods
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
# Dependency ordering: provider starts before consumer
# ===================================================================

atf_test_case dependency_order cleanup
dependency_order_head()
{
	atf_set "descr" "services start in dependency order"
	atf_set "require.user" "root"
	require_oracle_stack_kmods
}
dependency_order_body()
{
	prepare_paths
	# NOTE: in the .cap model the runtime label == provides[0], so the
	# provider's provided name and its log label are the same token.  The
	# original manifest used label="provider" (for the log assertion) plus a
	# distinct provides=["provider-api"] (for the dependency edge); those two
	# namespaces are now collapsed.  We keep the label "provider"/"consumer"
	# so the existing 'service provider:'/'service consumer:' greps match, and
	# point the requires at "provider" so the dependency actually resolves.
	make_svc system provider '' \
	    '#!/bin/sh' \
	    'exit 0'
	make_svc system consumer 'requires = ["provider"];' \
	    '#!/bin/sh' \
	    'exit 0'

	start_stack

	# Wait for both to appear in log.
	if ! sh -c "i=0; while ! grep -q 'service consumer' '$logfile' && [ \$i -lt 100 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service consumer' '$logfile'"; then
		cat "$logfile" 2>/dev/null
		atf_fail "services did not start"
	fi

	provider_line=$(grep -n "service provider: started" "$logfile" | head -1 | cut -d: -f1)
	consumer_line=$(grep -n "service consumer: started" "$logfile" | head -1 | cut -d: -f1)
	if [ -z "$provider_line" ] || [ -z "$consumer_line" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "missing start log lines"
	fi
	if [ "$consumer_line" -le "$provider_line" ]; then
		cat "$logfile"
		atf_fail "consumer started before provider"
	fi
	assert_stack_alive
}
dependency_order_cleanup()
{
	cleanup_common
}

# ===================================================================
# Authenticated reload: new manifests are forwarded to serviced
# ===================================================================

atf_test_case control_reload cleanup
control_reload_head()
{
	atf_set "descr" "Oracle control reload triggers manifest reload in serviced"
	atf_set "require.user" "root"
	require_oracle_stack_kmods
}
control_reload_body()
{
	start_stack

	# Add a new bundle after startup.
	make_svc system new-svc '' \
	    '#!/bin/sh' \
	    "echo \$\$ > ${WORK}/new-svc.pid" \
	    'sleep 60'

	# Use Oracle's authenticated control endpoint; ambient SIGHUP is shielded.
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
	require_oracle_stack_kmods
}
restart_backoff_body()
{
	prepare_paths
	make_svc system fastcrash 'restart = "always";' \
	    '#!/bin/sh' \
	    'exit 1'

	start_stack
	if ! sh -c "i=0; while ! grep -q 'service fastcrash: started pid' '$logfile' && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service fastcrash: started pid' '$logfile'"; then
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
# Explicit unregister: service unregisters its own name
# ===================================================================

atf_test_case svc_unregister_explicit cleanup
svc_unregister_explicit_head()
{
	atf_set "descr" "service can explicitly unregister a name via SVC_OP_UNREGISTER"
	atf_set "require.user" "root"
	require_oracle_stack_kmods
}
svc_unregister_explicit_body()
{
	find_capd_service_fixture

	find_serviced
	prepare_paths
	make_svc_bin system org.test.unreg.svc \
	    "arguments = [\"unregister\", \"org.test.unreg.svc\", \"$(pwd)/unreg-register.out\", \"$(pwd)/unreg-result.out\"];" \
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

	# Verify serviced logged the unregistration.
	atf_check -s exit:0 -o ignore \
	    grep "org.test.unreg.svc.*unregistered\|unregistered.*org.test.unreg.svc" "$logfile"
	assert_stack_alive
}
svc_unregister_explicit_cleanup()
{
	cleanup_common
	rm -f unreg_svc unreg_svc.c unreg-register.out unreg-result.out
}

# ===================================================================
# Process-descriptor capability-mode readiness
# ===================================================================

atf_test_case capmode_is_authoritative_readiness cleanup
capmode_is_authoritative_readiness_head()
{
	atf_set "descr" "READY is advisory; verified NOTE_CAPMODE is the RUNNING boundary"
	atf_set "require.user" "root"
	require_oracle_stack_kmods
}
capmode_is_authoritative_readiness_body()
{
	local i pid

	find_capd_service_fixture
	prepare_paths
	make_svc_bin system org.test.capmode.gate \
	    'arguments = ["readiness-gate", "protocol-ready.out", "capmode-ready.out"];' \
	    "$capd_service_fixture"
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
	require_oracle_stack_kmods
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

	# Service contracts
	atf_add_test_case service_environment_minimal
	atf_add_test_case service_runs_as_user

	# Dependencies
	atf_add_test_case dependency_order

	# Reload
	atf_add_test_case control_reload

	# Naming protocol
	atf_add_test_case svc_unregister_explicit
	atf_add_test_case capmode_is_authoritative_readiness

	# Control-socket authorization
	atf_add_test_case sctl_privilege_denied
}
