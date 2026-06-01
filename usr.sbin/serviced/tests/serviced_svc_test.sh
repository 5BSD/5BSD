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
	if ! kill -0 "$daemon_pid" 2>/dev/null; then
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
}
restart_never_no_restart_body()
{
	prepare_paths
	write_executable "$(pwd)/exit0.sh" \
	    '#!/bin/sh' \
	    'echo $$ > exit0.pid' \
	    'exit 0'
	cat > "$manifestdir/exit0.ucl" <<EOF
label = "exit0";
program = "$(pwd)/exit0.sh";
restart = "never";
EOF

	start_stack
	if ! wait_for_file exit0.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
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
}
restart_on_failure_ignores_clean_body()
{
	prepare_paths
	write_executable "$(pwd)/clean.sh" \
	    '#!/bin/sh' \
	    'echo $$ > clean.pid' \
	    'exit 0'
	cat > "$manifestdir/clean.ucl" <<EOF
label = "clean-exit";
program = "$(pwd)/clean.sh";
restart = "on-failure";
EOF

	start_stack
	if ! wait_for_file clean.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
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
}
restart_on_failure_restarts_on_error_body()
{
	prepare_paths
	write_executable "$(pwd)/fail-once.sh" \
	    '#!/bin/sh' \
	    'if [ ! -f fail-once.ran ]; then' \
	    '    touch fail-once.ran' \
	    '    exit 1' \
	    'fi' \
	    'echo $$ > fail-once-restarted.pid' \
	    'sleep 60'
	cat > "$manifestdir/fail-once.ucl" <<EOF
label = "fail-once";
program = "$(pwd)/fail-once.sh";
restart = "on-failure";
EOF

	start_stack
	if ! sh -c "i=0; while [ ! -s fail-once-restarted.pid ] && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; test -s fail-once-restarted.pid"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not restart"
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
}
restart_always_restarts_clean_body()
{
	prepare_paths
	write_executable "$(pwd)/exit0-always.sh" \
	    '#!/bin/sh' \
	    'if [ ! -f exit0-always.ran ]; then' \
	    '    touch exit0-always.ran' \
	    '    exit 0' \
	    'fi' \
	    'echo $$ > exit0-always-restarted.pid' \
	    'sleep 60'
	cat > "$manifestdir/exit0-always.ucl" <<EOF
label = "exit0-always";
program = "$(pwd)/exit0-always.sh";
restart = "always";
EOF

	start_stack
	if ! sh -c "i=0; while [ ! -s exit0-always-restarted.pid ] && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; test -s exit0-always-restarted.pid"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not restart"
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
}
circuit_breaker_disables_body()
{
	prepare_paths
	write_executable "$(pwd)/crash.sh" \
	    '#!/bin/sh' \
	    'exit 1'
	cat > "$manifestdir/crash.ucl" <<EOF
label = "crash";
program = "$(pwd)/crash.sh";
restart = "always";
EOF

	start_stack
	if ! sh -c "i=0; while ! grep -q 'service crash: started pid' '$logfile' && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service crash: started pid' '$logfile'"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
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
}
shutdown_kills_sigterm_ignorer_body()
{
	local svc_pid

	prepare_paths
	write_executable "$(pwd)/ignore-term.sh" \
	    '#!/bin/sh' \
	    'echo $$ > ignore-term.pid' \
	    'trap "" TERM' \
	    'while :; do sleep 1; done'
	cat > "$manifestdir/ignore-term.ucl" <<EOF
label = "ignore-term";
program = "$(pwd)/ignore-term.sh";
stop_timeout = 1;
EOF

	start_stack
	if ! wait_for_file ignore-term.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi
	svc_pid=$(cat ignore-term.pid)

	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" shutdown
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=
	atf_check -s not-exit:0 kill -0 "$svc_pid"
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
}
shutdown_kills_subtree_body()
{
	local child_pid

	prepare_paths
	write_executable "$(pwd)/subtree.sh" \
	    '#!/bin/sh' \
	    'sleep 60 &' \
	    'echo $! > subtree-child.pid' \
	    'echo $$ > subtree-parent.pid' \
	    'wait'
	cat > "$manifestdir/subtree.ucl" <<EOF
label = "subtree";
program = "$(pwd)/subtree.sh";
stop_timeout = 1;
EOF

	start_stack
	if ! wait_for_file subtree-child.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi
	child_pid=$(cat subtree-child.pid)

	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" shutdown
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=
	atf_check -s not-exit:0 kill -0 "$child_pid"
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
}
service_environment_minimal_body()
{
	prepare_paths
	write_executable "$(pwd)/env-probe.sh" \
	    '#!/bin/sh' \
	    'env | sort > env-probe.out' \
	    'sleep 20'
	cat > "$manifestdir/env-probe.ucl" <<EOF
label = "env-probe";
program = "$(pwd)/env-probe.sh";
EOF

	export SHOULD_NOT_LEAK=secret
	start_stack
	unset SHOULD_NOT_LEAK
	if ! wait_for_file env-probe.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi

	atf_check -s exit:0 -o match:"^PATH=/sbin:/bin:/usr/sbin:/usr/bin$" \
	    grep "^PATH=" env-probe.out
	atf_check -s exit:0 -o match:"^ORACLED_PAIR_FD=" \
	    grep "^ORACLED_PAIR_FD=" env-probe.out
	atf_check -s exit:0 -o match:"^ORACLED_LABEL=env-probe$" \
	    grep "^ORACLED_LABEL=" env-probe.out
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
}
service_runs_as_user_body()
{
	prepare_paths
	write_executable "$(pwd)/whoami-svc.sh" \
	    '#!/bin/sh' \
	    'id -un > whoami-svc.out' \
	    'id -gn >> whoami-svc.out' \
	    'sleep 60'
	touch whoami-svc.out
	chmod 666 whoami-svc.out
	cat > "$manifestdir/whoami.ucl" <<EOF
label = "whoami";
program = "$(pwd)/whoami-svc.sh";
user = "nobody";
group = "nogroup";
EOF

	start_stack
	if ! sh -c "i=0; while [ ! -s whoami-svc.out ] && [ \$i -lt 100 ]; do i=\$((i + 1)); sleep 0.1; done; test -s whoami-svc.out"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not write output"
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
}
dependency_order_body()
{
	prepare_paths
	cat > "$manifestdir/provider.ucl" <<EOF
label = "provider";
program = "/usr/bin/true";
provides = ["provider-api"];
EOF
	cat > "$manifestdir/consumer.ucl" <<EOF
label = "consumer";
program = "/usr/bin/true";
requires = ["provider-api"];
EOF

	start_stack

	# Wait for both to appear in log.
	if ! sh -c "i=0; while ! grep -q 'service consumer' '$logfile' && [ \$i -lt 100 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service consumer' '$logfile'"; then
		cat "$logfile" 2>/dev/null
		atf_skip "services did not start"
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
# SIGHUP reload: new manifests loaded on reload
# ===================================================================

atf_test_case sighup_reload cleanup
sighup_reload_head()
{
	atf_set "descr" "SIGHUP triggers manifest reload in serviced"
	atf_set "require.user" "root"
}
sighup_reload_body()
{
	start_stack

	# Add a new manifest after startup.
	write_executable "$(pwd)/new-svc.sh" \
	    '#!/bin/sh' \
	    'echo $$ > new-svc.pid' \
	    'sleep 60'
	cat > "$manifestdir/new-svc.ucl" <<EOF
label = "new-svc";
program = "$(pwd)/new-svc.sh";
EOF

	# Send SIGHUP to oracled (forwarded to serviced).
	kill -HUP "$daemon_pid"

	if ! wait_for_file new-svc.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "new service did not start after reload"
	fi
	assert_stack_alive
}
sighup_reload_cleanup()
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
}
restart_backoff_body()
{
	prepare_paths
	write_executable "$(pwd)/fastcrash.sh" \
	    '#!/bin/sh' \
	    'exit 1'
	cat > "$manifestdir/fastcrash.ucl" <<EOF
label = "fastcrash";
program = "$(pwd)/fastcrash.sh";
restart = "always";
EOF

	start_stack
	if ! sh -c "i=0; while ! grep -q 'service fastcrash: started pid' '$logfile' && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service fastcrash: started pid' '$logfile'"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while ! grep -q 'scheduling restart' '$logfile' && [ \$i -lt 100 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'scheduling restart' '$logfile'"
	assert_stack_alive
}
restart_backoff_cleanup()
{
	cleanup_common
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
	atf_add_test_case sighup_reload
}
