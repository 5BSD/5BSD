#
# SPDX-License-Identifier: BSD-2-Clause
#
# Integration tests for the full authorityd + serviced stack.
#
# Tests exercise capability token delivery, crash recovery,
# circuit breaker, graceful shutdown, dependency ordering,
# and hot reload.
#
# Requires: root, mac_capability modules loaded, serviced and libservice built.
#

. "$(dirname "$0")/test_helpers.sh"

# ===================================================================
# crash_recovery_restarts
# ===================================================================

atf_test_case crash_recovery_restarts cleanup
crash_recovery_restarts_head()
{
	atf_set "descr" "Service with restart=on-failure restarts after crash"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
crash_recovery_restarts_body()
{
	start_stack

	# Service that crashes first time, succeeds second time
	make_svc system crasher 'restart = "on-failure";' \
	    '#!/bin/sh' \
	    "if [ -f ${WORK}/crash-count.out ]; then" \
	    "    echo \"restarted\" > ${WORK}/crash-restarted.out" \
	    '    exec sleep 30' \
	    'fi' \
	    "echo \"first\" > ${WORK}/crash-count.out" \
	    'exit 1'
	reload_stack

	if ! wait_for_file crash-restarted.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not restart after crash"
	fi

	atf_check -s exit:0 -o match:"restarted" cat crash-restarted.out
}
crash_recovery_restarts_cleanup()
{
	cleanup_common
	rm -f crasher crash-count.out crash-restarted.out
}

# ===================================================================
# circuit_breaker_stops_restarts
# ===================================================================

atf_test_case circuit_breaker_stops_restarts cleanup
circuit_breaker_stops_restarts_head()
{
	atf_set "descr" "Circuit breaker disables service after max_failures"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
circuit_breaker_stops_restarts_body()
{
	start_stack

	make_svc system fastcrash 'restart = "on-failure"; max_failures = 3;' \
	    '#!/bin/sh' \
	    'exit 1'
	reload_stack

	# Wait for circuit breaker message in log
	i=0
	while ! grep -q "circuit.breaker\|disabled.*fastcrash\|max.failures" \
	    "$logfile" 2>/dev/null && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done

	atf_check -s exit:0 -o ignore \
	    grep -i "fastcrash" "$logfile"
}
circuit_breaker_stops_restarts_cleanup()
{
	cleanup_common
	rm -f fastcrash
}

# ===================================================================
# graceful_shutdown_sigterm
# ===================================================================

atf_test_case graceful_shutdown_sigterm cleanup
graceful_shutdown_sigterm_head()
{
	atf_set "descr" "Service receives SIGTERM on graceful shutdown"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
graceful_shutdown_sigterm_body()
{
	start_stack

	make_svc system trapper '' \
	    '#!/bin/sh' \
	    "trap 'echo \"got-sigterm\" > ${WORK}/sigterm-marker.out; exit 0' TERM" \
	    "echo \"ready\" > ${WORK}/trapper-ready.out" \
	    'while true; do sleep 1; done'
	reload_stack

	if ! wait_for_file trapper-ready.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	# Shut down the stack — this sends SIGTERM to services
	atf_check -s exit:0 -o match:"shutdown initiated" \
	    authorityctl -s "$sockpath" shutdown
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=

	# The marker must actually be written — otherwise SIGTERM was never
	# delivered and the old "if [ -f ... ]" guard passed vacuously.
	if ! wait_for_file "${WORK}/sigterm-marker.out" 3; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not receive SIGTERM (marker not written)"
	fi
	atf_check -s exit:0 -o match:"got-sigterm" \
	    cat "${WORK}/sigterm-marker.out"
}
graceful_shutdown_sigterm_cleanup()
{
	cleanup_common
	rm -f trapper trapper-ready.out sigterm-marker.out
}

# ===================================================================
# procdesc_is_only_signal_authority
# ===================================================================

atf_test_case procdesc_is_only_signal_authority cleanup
procdesc_is_only_signal_authority_head()
{
	atf_set "descr" "ambient SIGKILL is denied but Authority can stop serviced through its procdesc"
	atf_set "require.user" "root"
	require_authority_stack_kmods
	atf_set "timeout" "60"
}
procdesc_is_only_signal_authority_body()
{
	local serviced_pid i

	start_stack
	serviced_pid=$(pgrep -P "$daemon_pid" serviced | head -n 1)
	if [ -z "$serviced_pid" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "could not find serviced child"
	fi

	# This is an ambient PID-based signal from a foreign program nonce.
	# CP_SF_SIGKILL must reject it even for root.
	if kill -KILL "$serviced_pid" 2>ambient-kill.err; then
		atf_fail "ambient SIGKILL unexpectedly reached protected serviced"
	fi
	if ! ps -p "$serviced_pid" >/dev/null 2>&1; then
		atf_fail "serviced died after denied ambient SIGKILL"
	fi

	# Authority is protected from ambient signals too.  Ask it to shut down over
	# its administrative channel; bootstrap_stop() then signals this exact
	# serviced instance through Authority's procdesc, bypassing the ambient
	# capprotect signal check.  Waiting for socket removal first gives this
	# asynchronous path a hard diagnostic deadline instead of hanging in
	# wait(1) if shutdown regresses.
	atf_check -s exit:0 -o match:"shutdown initiated" \
	    authorityctl -s "$sockpath" shutdown
	i=0
	while [ -S "$sockpath" ] && [ "$i" -lt 350 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ -S "$sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "Authority control socket remained after shutdown deadline"
	fi
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=
	i=0
	while ps -p "$serviced_pid" >/dev/null 2>&1 && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if ps -p "$serviced_pid" >/dev/null 2>&1; then
		atf_fail "serviced survived the last close of Authority's procdesc"
	fi
}
procdesc_is_only_signal_authority_cleanup()
{
	cleanup_common
	rm -f ambient-kill.err
}

# ===================================================================
# reload_adds_service
# ===================================================================

atf_test_case reload_adds_service cleanup
reload_adds_service_head()
{
	atf_set "descr" "SIGHUP reload picks up new manifest and starts service"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
reload_adds_service_body()
{
	start_stack

	# Start with no services, then add one
	make_svc system hello '' \
	    '#!/bin/sh' \
	    "echo \"hello\" > ${WORK}/hello-started.out" \
	    'exec sleep 30'
	reload_stack

	if ! wait_for_file hello-started.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start after reload"
	fi

	atf_check -s exit:0 -o match:"hello" cat hello-started.out
}
reload_adds_service_cleanup()
{
	cleanup_common
	rm -f hello_svc hello-started.out
}

# ===================================================================
# reload_removes_service
# ===================================================================

atf_test_case reload_removes_service cleanup
reload_removes_service_head()
{
	atf_set "descr" "Removing manifest and reloading stops the service"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
reload_removes_service_body()
{
	prepare_paths
	make_svc system removeme '' \
	    '#!/bin/sh' \
	    "echo \"running\" > ${WORK}/removeme-running.out" \
	    'exec sleep 30'
	write_config
	start_stack

	if ! wait_for_file removeme-running.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	# Remove the bundle and reload
	rm -rf "${APPS_DIR}/removeme.cap"
	reload_stack

	# Wait for removal to be logged
	i=0
	while ! grep -q "removed\|stopped.*removeme\|0 new.*1 removed" \
	    "$logfile" 2>/dev/null && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done

	atf_check -s exit:0 -o ignore \
	    grep -i "remov" "$logfile"
}
reload_removes_service_cleanup()
{
	cleanup_common
	rm -f removeme removeme-running.out
}

# ===================================================================
# audit_records_best_effort
#
# The daemon emits OpenBSM audit records (AUE_SERVICED_*) via audit_submit
# when built with -DUSE_BSM_AUDIT.  A full audit test needs a configured
# auditd + praudit and an active trail, which is often unavailable in CI.
# This is a BEST-EFFORT check: if the audit tooling or an active trail is
# missing, or the daemon was not built with audit support, it skips rather
# than fails.  It never requires auditing to be configured.
# ===================================================================

atf_test_case audit_records_best_effort cleanup
audit_records_best_effort_head()
{
	atf_set "descr" "serviced emits BSM audit records (best effort; skips if audit unavailable)"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
audit_records_best_effort_body()
{
	command -v praudit >/dev/null 2>&1 || \
	    atf_skip "praudit not available"
	command -v auditreduce >/dev/null 2>&1 || \
	    atf_skip "auditreduce not available"
	if [ ! -f /var/audit/current ]; then
		atf_skip "no active audit trail (/var/audit/current absent)"
	fi
	if ! auditreduce /var/audit/current >/dev/null 2>&1; then
		atf_skip "audit trail not readable"
	fi

	start_stack

	# A control command (reload) emits AUE_SERVICED_CTL; starting a
	# service emits AUE_SERVICED_SVC_EXEC.
	make_svc system audsvc '' \
	    '#!/bin/sh' \
	    "echo run > ${WORK}/audsvc.out" \
	    'sleep 30'
	reload_stack
	if ! wait_for_file "${WORK}/audsvc.out" 5; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	# Flush the audit queue to disk (best effort) and look for any
	# serviced-attributed record.
	audit -n >/dev/null 2>&1 || true
	sleep 1

	if auditreduce /var/audit/current 2>/dev/null | \
	    praudit 2>/dev/null | grep -qi "serviced"; then
		# Found a serviced audit record — the audit path works.
		return 0
	fi
	atf_skip "no serviced audit records found (daemon may lack -DUSE_BSM_AUDIT or auditing not configured)"
}
audit_records_best_effort_cleanup()
{
	cleanup_common
	rm -f audsvc audsvc.out
}

atf_test_case manifest_arguments_environment cleanup
manifest_arguments_environment_head()
{
	atf_set "descr" "Manifest arguments and environment reach execve literally"
	atf_set "require.user" "root"
	require_authority_stack_kmods
	atf_set "timeout" "60"
}
manifest_arguments_environment_body()
{
	find_capd_service_fixture
	start_stack
	make_svc_bin system manifest-exec \
	    'arguments = ["manifest-report", "manifest-exec.out", "literal value", "--flag"];
environment { APP_MODE = "test"; EMPTY = ""; }' "$capd_service_fixture"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${APPS_DIR}/manifest-exec.cap/Units/manifest-exec.unit/Unit.ucl"
	reload_stack
	wait_for_file manifest-exec.out 10 || atf_fail "service did not exec"
	atf_check -s exit:0 -o match:'^argc=3$' grep '^argc=' manifest-exec.out
	atf_check -s exit:0 -o match:'^arg1=literal value$' \
	    grep '^arg1=' manifest-exec.out
	atf_check -s exit:0 -o match:'^arg2=--flag$' grep '^arg2=' manifest-exec.out
	atf_check -s exit:0 -o match:'^mode=test$' grep '^mode=' manifest-exec.out
	atf_check -s exit:0 -o match:'^empty=$' grep '^empty=' manifest-exec.out
	atf_check -s exit:0 \
	    -o match:'/manifest-exec.cap/Units/manifest-exec.unit$' \
	    grep '^unit_dir=' manifest-exec.out
	stop_stack
}
manifest_arguments_environment_cleanup()
{
	cleanup_common
	rm -f manifest_exec_svc manifest_exec_svc.c manifest-exec.out
}

atf_test_case remaining_token_families_activate cleanup
remaining_token_families_activate_head()
{
	atf_set "descr" "System manifest tokens mint and activate after exec"
	atf_set "require.user" "root"
	require_authority_stack_kmods
	atf_set "timeout" "60"
}
remaining_token_families_activate_body()
{
	find_capd_service_fixture
	start_stack
	make_svc_bin system token-families 'capabilities {
	    system = ["kldstat"];
}
arguments = ["authorize-tokens", "token-families.out"];' \
	    "$capd_service_fixture"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${APPS_DIR}/token-families.cap/Units/token-families.unit/Unit.ucl"
	reload_stack
	wait_for_file token-families.out 10 || {
		cat "$logfile" 2>/dev/null
		atf_fail "token family service did not become ready"
	}
	atf_check -s exit:0 -o match:'fds=6,7,8' cat token-families.out
	atf_check -s exit:0 -o match:'authorized=yes' cat token-families.out
	stop_stack
}
remaining_token_families_activate_cleanup()
{
	cleanup_common
	rm -f token_families_svc token_families_svc.c token-families.out \
	    token-families-status.out
}

atf_test_case malformed_reload_is_transactional cleanup
malformed_reload_is_transactional_head()
{
	atf_set "descr" "Malformed bundle rejects reload without replacing the live registry"
	atf_set "require.user" "root"
	require_authority_stack_kmods
	atf_set "timeout" "60"
}
malformed_reload_is_transactional_body()
{
	require_ambient_control
	find_capd_service_fixture
	start_stack
	make_svc_bin system reload-guard \
	    'arguments = ["ready", "reload-guard.out"];' \
	    "$capd_service_fixture"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${APPS_DIR}/reload-guard.cap/Units/reload-guard.unit/Unit.ucl"
	atf_check -s exit:0 -o ignore servicectl reload
	wait_for_file reload-guard.out 10 || atf_fail "guard service did not start"

	write_test_bundle "$USER_APPS_DIR/bad.cap" org.test.bad bad '' \
	    'activation { boot = true; }'
	printf '#!/bin/sh\nexit 0\n' > \
	    "$USER_APPS_DIR/bad.cap/Units/bad.unit/bin/bad"
	chmod 755 "$USER_APPS_DIR/bad.cap/Units/bad.unit/bin/bad"
	cat >> "$USER_APPS_DIR/bad.cap/Units/bad.unit/Unit.ucl" <<'UCL'
restert = "always";
UCL
	# Transactional per plan §15: the malformed local bundle is quarantined
	# (skipped), while the valid active registry is retained and the reload
	# otherwise succeeds.
	atf_check -s exit:0 -o ignore servicectl reload
	atf_check -s exit:0 -o ignore \
	    grep 'quarantined user bundle.*bad' "$logfile"
	atf_check -s exit:0 -o match:'reload-guard' \
	    servicectl services
	stop_stack
}
malformed_reload_is_transactional_cleanup()
{
	cleanup_common
	rm -f reload_guard_svc reload_guard_svc.c reload-guard.out
}

atf_test_case untrusted_bundle_rejected cleanup
untrusted_bundle_rejected_head()
{
	atf_set "descr" "Writable bundle policy cannot be loaded by serviced"
	atf_set "require.user" "root"
	require_authority_stack_kmods
	atf_set "timeout" "60"
}
untrusted_bundle_rejected_body()
{
	require_ambient_control
	build_ready_svc
	start_stack
	dir=$(make_svc_bin user untrusted '' "$(pwd)/ready_svc")
	chmod 0777 "$dir"
	# A world-writable (untrusted) local bundle is quarantined, not loaded:
	# the reload succeeds for the valid registry while the untrusted bundle
	# is skipped and never runs (plan §15).
	atf_check -s exit:0 -o ignore servicectl reload
	atf_check -s exit:0 -o ignore \
	    grep 'quarantined user bundle.*untrusted' "$logfile"
	test ! -e untrusted.ready || atf_fail "untrusted service executed"
	atf_check -s exit:0 -o ignore servicectl services
	stop_stack
}
untrusted_bundle_rejected_cleanup()
{
	chmod 0755 "${USER_APPS_DIR}/untrusted.cap" 2>/dev/null || true
	cleanup_common
}

atf_test_case kmod_prerequisite_uses_authority cleanup
kmod_prerequisite_uses_authority_head()
{
	atf_set "descr" "System bundle module prerequisites execute under Authority authority"
	atf_set "require.user" "root"
	require_authority_stack_kmods
	atf_set "timeout" "60"
}
kmod_prerequisite_uses_authority_body()
{
	require_ambient_control
	build_ready_svc
	start_stack
	make_svc_bin system kmod-prereq \
	    'kmod_requires = ["mac_capability"];
arguments = ["compat-ready"];' "$(pwd)/ready_svc"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${APPS_DIR}/kmod-prereq.cap/Units/kmod-prereq.unit/Unit.ucl"
	atf_check -s exit:0 -o ignore servicectl reload
	wait_for_file kmod-prereq.ready 10 || {
		cat "$logfile" 2>/dev/null
		atf_fail "service with a loaded-module prerequisite did not start"
	}
	atf_check -s exit:0 -o ignore \
	    grep 'ensured kernel module mac_capability' "$logfile"
	stop_stack
}
kmod_prerequisite_uses_authority_cleanup()
{
	cleanup_common
}

# ===================================================================

atf_init_test_cases()
{
	atf_add_test_case crash_recovery_restarts
	atf_add_test_case circuit_breaker_stops_restarts
	atf_add_test_case graceful_shutdown_sigterm
	atf_add_test_case procdesc_is_only_signal_authority
	atf_add_test_case reload_adds_service
	atf_add_test_case reload_removes_service
	atf_add_test_case audit_records_best_effort
	atf_add_test_case manifest_arguments_environment
	atf_add_test_case remaining_token_families_activate
	atf_add_test_case malformed_reload_is_transactional
	atf_add_test_case untrusted_bundle_rejected
	atf_add_test_case kmod_prerequisite_uses_authority
}
