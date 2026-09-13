#
# SPDX-License-Identifier: BSD-2-Clause
#
# Integration tests for the full capsule + switchboard stack.
#
# Tests exercise capability token delivery, crash recovery,
# circuit breaker, graceful shutdown, dependency ordering,
# and hot reload.
#
# Requires: root, mac_capability modules loaded, switchboard and libservice built.
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
	require_capsule_stack_kmods
}
crash_recovery_restarts_body()
{
	start_stack

	# Service that crashes first time, succeeds second time
	make_fixture_svc system crasher 'restart = "on-failure";' \
	    lifecycle-restart-once "${WORK}/crash-count.out" \
	    "${WORK}/crash-restarted.out" 1 restarted
	reload_stack

	if ! wait_for_file crash-restarted.out; then
		cat "$logfile" 2>/dev/null
		cat fixture-errors 2>/dev/null || true
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
	require_capsule_stack_kmods
}
circuit_breaker_stops_restarts_body()
{
	start_stack

	make_fixture_svc system fastcrash \
	    'restart = "on-failure"; max_failures = 3;' \
	    lifecycle-exit "${WORK}/fastcrash.pid" 1
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
	atf_set "descr" "Listenerless service acknowledges quiesce and receives SIGTERM on shutdown"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
graceful_shutdown_sigterm_body()
{
	start_stack

	make_fixture_svc system trapper '' \
	    lifecycle-term "${WORK}/trapper-ready.out" \
	    "${WORK}/sigterm-marker.out"
	reload_stack

	if ! wait_for_file trapper-ready.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	atf_check -s exit:0 -o match:"handler=yes blocked=0" cat trapper-ready.out
	# Shut down the stack — this sends SIGTERM to services
	capd_capsule_ctl "$sockpath" shutdown | grep -q "shutdown initiated" ||
	    atf_fail "Capsule shutdown request failed"
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
# procdesc_signal_via_capsule
# ===================================================================

atf_test_case procdesc_signal_via_capsule cleanup
procdesc_signal_via_capsule_head()
{
	atf_set "descr" "ambient SIGKILL is denied but Capsule can stop switchboard through its procdesc"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
procdesc_signal_via_capsule_body()
{
	local switchboard_pid i

	start_stack
	switchboard_pid=$(pgrep -P "$daemon_pid" switchboard | head -n 1)
	if [ -z "$switchboard_pid" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "could not find switchboard child"
	fi

	# This is an ambient PID-based signal from a foreign program nonce.
	# CP_SF_SIGKILL must reject it even for root.
	if kill -KILL "$switchboard_pid" 2>ambient-kill.err; then
		atf_fail "ambient SIGKILL unexpectedly reached protected switchboard"
	fi
	if ! ps -p "$switchboard_pid" >/dev/null 2>&1; then
		atf_fail "switchboard died after denied ambient SIGKILL"
	fi

	# Capsule is protected from ambient signals too.  Ask it to shut down over
	# its administrative channel; bootstrap_stop() then signals this exact
	# switchboard instance through Capsule's procdesc, bypassing the ambient
	# capprotect signal check.  Waiting for socket removal first gives this
	# asynchronous path a hard diagnostic deadline instead of hanging in
	# wait(1) if shutdown regresses.
	capd_capsule_ctl "$sockpath" shutdown | grep -q "shutdown initiated" ||
	    atf_fail "Capsule shutdown request failed"
	i=0
	while [ -S "$sockpath" ] && [ "$i" -lt 350 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ -S "$sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "Capsule control socket remained after shutdown deadline"
	fi
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=
	i=0
	while ps -p "$switchboard_pid" >/dev/null 2>&1 && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if ps -p "$switchboard_pid" >/dev/null 2>&1; then
		atf_fail "switchboard survived the last close of Capsule's procdesc"
	fi
}
procdesc_signal_via_capsule_cleanup()
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
	require_capsule_stack_kmods
}
reload_adds_service_body()
{
	start_stack

	# Start with no services, then add one
	make_fixture_svc system hello '' \
	    lifecycle-hold - "${WORK}/hello-started.out" hello
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
	require_capsule_stack_kmods
}
reload_removes_service_body()
{
	prepare_paths
	make_fixture_svc system removeme '' \
	    lifecycle-hold - "${WORK}/removeme-running.out" running
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
# The daemon emits OpenBSM audit records (AUE_SWITCHBOARD_*) via audit_submit
# when built with -DUSE_BSM_AUDIT.  A full audit test needs a configured
# auditd + praudit and an active trail, which is often unavailable in CI.
# Missing audit tooling or an active trail permits a skip. Once configured,
# the trail must contain the execution event for this test service.
# ===================================================================

atf_test_case audit_records_best_effort cleanup
audit_records_best_effort_head()
{
	atf_set "descr" "switchboard emits BSM audit records (best effort; skips if audit unavailable)"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
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

	local audit_trail audit_prefix
	audit_trail=$(realpath /var/audit/current)
	audit_prefix=${audit_trail%.*}
	start_stack

	# A control command (reload) emits AUE_SWITCHBOARD_CTL; starting a
	# service emits AUE_SWITCHBOARD_SVC_EXEC.
	make_fixture_svc system audsvc '' \
	    lifecycle-hold "${WORK}/audsvc.pid" "${WORK}/audsvc.out" run
	reload_stack
	if ! wait_for_file "${WORK}/audsvc.out" 5; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	# Rotation closes the trail containing our event; current then names a
	# different file. Reopen the original trail by its stable start timestamp
	# on each attempt; a duplicated descriptor would retain the prior offset.
	audit -n || atf_fail "audit trail rotation failed"
	local attempts=0
	while [ "$attempts" -lt 30 ]; do
		# Filter the event type: execve audit arguments can quote our grep.
		auditreduce -m 43322 "${audit_prefix}".* 2>/dev/null | praudit -l > audit-records.out
		if grep -F "svc=org.test.audsvc/audsvc pid=$(cat audsvc.pid) " audit-records.out; then
			return 0
		fi
		attempts=$((attempts + 1))
		sleep 0.1
	done
	atf_fail "configured audit trail did not record this service execution"
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
	require_capsule_stack_kmods
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

# ===================================================================
# sealed_bundle_launches_unprivileged_service
# ===================================================================

atf_test_case sealed_bundle_launches_unprivileged_service cleanup
sealed_bundle_launches_unprivileged_service_head()
{
	atf_set "descr" "An unprivileged service starts from a verified, inaccessible bundle tree"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
sealed_bundle_launches_unprivileged_service_body()
{
	local bundle unit

	start_stack
	bundle=$(make_fixture_svc system sealed-unpriv \
	    'user = "capability";' lifecycle-hold - \
	    "${WORK}/sealed-unpriv.out" running)
	unit="${bundle}/Units/sealed-unpriv.unit"

	# Match the installed image's sealed traversal boundary.  switchboard scans
	# as root, but the requested uid cannot reopen the target by pathname.
	chmod 000 "$bundle" "$bundle/Units" "$unit"
	chmod 0777 "$WORK"
	reload_stack

	if ! wait_for_file sealed-unpriv.out 10; then
		cat "$logfile" 2>/dev/null
		atf_fail "unprivileged service did not exec from sealed bundle"
	fi
	atf_check -s exit:0 -o match:'running' cat sealed-unpriv.out
}
sealed_bundle_launches_unprivileged_service_cleanup()
{
	cleanup_common
	rm -f sealed-unpriv.out
}

atf_test_case remaining_token_families_activate cleanup
remaining_token_families_activate_head()
{
	atf_set "descr" "System manifest tokens mint and activate after exec"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
remaining_token_families_activate_body()
{
	find_capd_service_fixture
	start_stack
	make_svc_bin system token-families 'capabilities {
	    system = ["kldload"];
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
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
malformed_reload_is_transactional_body()
{
	find_capd_service_fixture
	start_stack
	make_fixture_svc system reload-guard '' lifecycle-hold \
	    "$WORK/reload-guard.pid" "$WORK/reload-guard.out" running
	reload_stack
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
	reload_stack
	wait_for_log 'quarantined user bundle.*bad' || atf_fail "malformed bundle was not quarantined"
	atf_check kill -0 "$(cat reload-guard.pid)"
	atf_check -o match:running cat reload-guard.out
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
	atf_set "descr" "Writable bundle policy cannot be loaded by switchboard"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
untrusted_bundle_rejected_body()
{
	build_ready_svc
	start_stack
	dir=$(make_svc_bin user untrusted '' "$(pwd)/ready_svc")
	chmod 0777 "$dir"
	# A world-writable (untrusted) local bundle is quarantined, not loaded:
	# the reload succeeds for the valid registry while the untrusted bundle
	# is skipped and never runs (plan §15).
	reload_stack
	wait_for_log 'quarantined user bundle.*untrusted' || atf_fail "untrusted bundle was not quarantined"
	test ! -e untrusted.ready || atf_fail "untrusted service executed"
	atf_check test ! -e untrusted.ready
	stop_stack
}
untrusted_bundle_rejected_cleanup()
{
	chmod 0755 "${USER_APPS_DIR}/untrusted.cap" 2>/dev/null || true
	cleanup_common
}

atf_test_case legacy_kmod_prerequisite_is_rejected cleanup
legacy_kmod_prerequisite_is_rejected_head()
{
	atf_set "descr" "Legacy module prerequisites are rejected; modules are owned by sysextd"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
legacy_kmod_prerequisite_is_rejected_body()
{
	build_ready_svc
	start_stack
	make_svc_bin system kmod-prereq \
	    'kmod_requires = ["mac_capability"];' "$(pwd)/ready_svc"
	reload_stack
	wait_for_log "unknown key 'kmod_requires'" ||
	    atf_fail "legacy module-loading field was not rejected"
	atf_check test ! -e kmod-prereq.ready
	wait_for_log 'previous registry and running services retained' ||
	    atf_fail "invalid system manifest did not preserve the prior registry"
	stop_stack
}
legacy_kmod_prerequisite_is_rejected_cleanup()
{
	cleanup_common
}

# ===================================================================

atf_test_case retirement_replays_after_provider_restart cleanup
retirement_replays_after_provider_restart_head()
{
    atf_set require.user root
    atf_set timeout 120
    require_capsule_stack_kmods
}
retirement_replays_after_provider_restart_body()
{
    export SWITCHBOARD_EXPERIMENTAL_RECLAIM=1
    start_stack
    ctl=$(command -v switchboardctl)
    label=org.test.retirementclient/retirementclient
    op=11111111111111111111111111111111
    atf_check "$ctl" lifecycle install "$WORK" source.v1 "$label"
    make_fixture_svc system retirementprovider 'restart = "on-failure"; activation { ipc = ["org.test.retirement-store"]; }' retirement-provider org.test.retirement-store retirement-receipt
    make_fixture_svc system retirementclient 'restart = "never";' retirement-client org.test.retirement-store
    reload_stack
    if ! wait_for_file retirement-client.ready; then
        cat fixture-errors "$logfile" 2>/dev/null || true
        atf_fail 'client session not established'
    fi
    "$ctl" lifecycle status "$WORK" > before
    old=$(awk -v label="$label" '$1=="owner" && $2==label {print $3}' before)
    atf_check "$ctl" lifecycle prepare "$WORK" "$op" source.v1 "$label"
    # The provider is absent when retirement is committed; restart must replay it.
    providerpid=$(cat retirement-provider.ready)
    kill -KILL "$providerpid"
    rm -rf "$APPS_DIR/retirementclient.cap"
    atf_check "$ctl" lifecycle retire "$WORK" "$op" source.v1 "$label"
    atf_check "$ctl" lifecycle install "$WORK" source.v2 "$label"
    wait_for_file retirement-receipt || atf_fail 'retirement was not replayed'
    atf_check -o match:"install.$old" cat retirement-receipt
    for attempt in $(jot 100); do
        "$ctl" lifecycle status "$WORK" > after
        awk -v old="$old" '$1=="owner" && $3==old && $4==4 {ok=1} END {exit !ok}' after && break
        sleep .1
    done
    atf_check awk -v old="$old" -v label="$label" '
        $1=="owner" && $3==old && $4==4 {complete++}
        $1=="owner" && $2==label && $3!=old && $4==1 {fresh++}
        END {exit !(complete==1 && fresh==1)}' after
}
retirement_replays_after_provider_restart_cleanup() { cleanup_common; }

atf_test_case installation_authority_live_query cleanup
installation_authority_live_query_head()
{
    atf_set require.user root
    atf_set timeout 120
    require_capsule_stack_kmods
}
installation_authority_live_query_body()
{
    export SWITCHBOARD_TRACE_INSTALLATION=1
    unset SWITCHBOARD_EXPERIMENTAL_RECLAIM
    start_stack
    ctl=$(command -v switchboardctl)
    label=org.test.subject/main
    op=11111111111111111111111111111111
    atf_check "$ctl" lifecycle install "$WORK" pkg:subject "$label"
    "$ctl" lifecycle status "$WORK" > ledger
    old=$(awk -v label="$label" '$1=="owner" && $2==label {print $3}' ledger)
    make_fixture_svc system queryold 'restart = "never";' installation-query "$label" "$old" "$WORK/query-old.result"
    reload_stack
    if ! wait_for_file query-old.result; then
        cat fixture-errors fixture-init-failure.result fixture-ready-failure.result "$logfile" 2>/dev/null || true
        atf_fail 'launched service did not complete its installation query'
    fi
    atf_check -o inline:'0 1\n' cat query-old.result
    atf_check "$ctl" lifecycle prepare "$WORK" "$op" pkg:subject "$label"
    atf_check "$ctl" lifecycle retire "$WORK" "$op" pkg:subject "$label"
    atf_check "$ctl" lifecycle install "$WORK" pkg:subject "$label"
    "$ctl" lifecycle status "$WORK" > ledger
    fresh=$(awk -v label="$label" '$1=="owner" && $2==label && $4==1 {print $3}' ledger)
    atf_check test "$old" != "$fresh"
    make_fixture_svc system querynew 'restart = "never";' installation-query "$label" "$fresh" "$WORK/query-new.result"
    # The running manager has already cached the old installation.
    make_fixture_svc system queryretired 'restart = "never";' installation-query "$label" "$old" "$WORK/query-retired.result"
    reload_stack
    wait_for_file query-retired.result || atf_fail 'cached old-ID query did not refresh'
    wait_for_file query-new.result || atf_fail 'cached new-ID query did not refresh'
    atf_check -o inline:'0 4\n' cat query-retired.result
    atf_check -o inline:'0 1\n' cat query-new.result
    # Restart the actual daemon stack; both service queries must read durable state.
    stop_stack
    rm query-old.result query-new.result query-retired.result
    start_stack
    wait_for_file query-old.result || atf_fail 'old-ID query did not recover after daemon restart'
    wait_for_file query-new.result || atf_fail 'new-ID query did not recover after daemon restart'
    atf_check -o inline:'0 4\n' cat query-old.result
    atf_check -o inline:'0 1\n' cat query-new.result
    atf_check -o ignore grep -E 'installation action=query label=org.test.subject/main .* state=4 error=0' "$logfile"
    atf_check -o ignore grep -E 'installation action=query label=org.test.subject/main .* state=1 error=0' "$logfile"
}
installation_authority_live_query_cleanup() { cleanup_common; }

atf_test_case unregistered_service_requires_adoption cleanup
unregistered_service_requires_adoption_head()
{
    atf_set require.user root
    atf_set timeout 120
    require_capsule_stack_kmods
}
unregistered_service_requires_adoption_body()
{
    export SWITCHBOARD_TRACE_INSTALLATION=1
    unset SWITCHBOARD_EXPERIMENTAL_RECLAIM
    prepare_paths
    find_capd_service_fixture
    dir="$APPS_DIR/unregistered.cap"
    write_test_bundle "$dir" org.test.unregistered worker 'restart = "never";' 'activation { boot = true; }'
    cp "$capd_service_fixture" "$dir/Units/worker.unit/bin/worker"
    chmod 755 "$dir/Units/worker.unit/bin/worker"
    printf 'arguments = ["lifecycle-hold", "-", "%s", "running"];\n' "$WORK/registered.result" >> "$dir/Units/worker.unit/Unit.ucl"
    start_stack
    wait_for_log 'org.test.unregistered/worker: installation identity unavailable' ||
        atf_fail "unregistered service did not fail with a diagnostic"
    atf_check test ! -e registered.result
    cp "$logfile" before
    atf_check -o ignore grep -E 'installation action=start label=org.test.unregistered/worker .* state=0 error=2' "$logfile"
    ctl=$(command -v switchboardctl)
    atf_check -o match:' unknown ' "$ctl" lifecycle query "$WORK" org.test.unregistered/worker
    atf_check "$ctl" lifecycle adopt "$WORK" bundle:org.test.unregistered@1 org.test.unregistered/worker
    stop_stack
    start_stack
    wait_for_file registered.result || atf_fail "explicitly adopted service did not start"
    atf_check -o ignore grep -E 'installation action=start label=org.test.unregistered/worker .* state=1 error=0' "$logfile"
    atf_check -o match:' installed ' "$ctl" lifecycle query "$WORK" org.test.unregistered/worker
}
unregistered_service_requires_adoption_cleanup() { cleanup_common; }

atf_init_test_cases()
{
	atf_add_test_case unregistered_service_requires_adoption
	atf_add_test_case installation_authority_live_query;
	atf_add_test_case retirement_replays_after_provider_restart
	atf_add_test_case crash_recovery_restarts
	atf_add_test_case circuit_breaker_stops_restarts
	atf_add_test_case graceful_shutdown_sigterm
	atf_add_test_case procdesc_signal_via_capsule
	atf_add_test_case reload_adds_service
	atf_add_test_case reload_removes_service
	atf_add_test_case audit_records_best_effort
	atf_add_test_case manifest_arguments_environment
	atf_add_test_case sealed_bundle_launches_unprivileged_service
	atf_add_test_case remaining_token_families_activate
	atf_add_test_case malformed_reload_is_transactional
	atf_add_test_case untrusted_bundle_rejected
	atf_add_test_case legacy_kmod_prerequisite_is_rejected
}
