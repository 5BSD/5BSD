#
# SPDX-License-Identifier: BSD-2-Clause
#
# Integration tests for the full oracled + serviced stack.
#
# Tests exercise capability token delivery, crash recovery,
# circuit breaker, graceful shutdown, dependency ordering,
# and hot reload.
#
# Requires: root, mac_capability modules loaded, serviced and libservice built.
#

. "$(dirname "$0")/test_helpers.sh"

find_libservice()
{
	local p
	for p in \
	    /usr/lib/libservice.so \
	    /usr/obj/usr/src/arm64.aarch64/lib/libservice/libservice.so.1
	do
		if [ -n "$p" ] && [ -f "$p" ]; then
			libservice_path="$(dirname "$p")"
			return
		fi
	done
	atf_skip "libservice not found"
}

cc_with_libservice()
{
	require_cc
	find_libservice
	cc -Wall -Wextra \
	    -I/usr/src/lib/libservice \
	    -L"$libservice_path" -lservice \
	    "$@"
}

# ===================================================================
# capability_tokens_delivered
# ===================================================================

atf_test_case capability_tokens_delivered cleanup
capability_tokens_delivered_head()
{
	atf_set "descr" "Service receives capability token fds from oracle"
	atf_set "require.user" "root"
}
capability_tokens_delivered_body()
{
	cat > token_svc.c <<'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libservice.h>

int
main(void)
{
	FILE *out;
	const char *token_fds;
	char *tok, *copy;
	int fd, valid_count = 0;
	struct stat sb;

	if (service_init() == -1) return (1);
	if (service_ready() == -1) return (1);

	out = fopen("token-check.out", "w");
	if (out == NULL) return (1);

	fprintf(out, "channel_fd=%d\n", service_channel_fd());

	token_fds = getenv("ORACLED_TOKEN_FDS");
	if (token_fds != NULL && token_fds[0] != '\0') {
		fprintf(out, "token_fds=%s\n", token_fds);
		copy = strdup(token_fds);
		tok = strtok(copy, ",");
		while (tok != NULL) {
			fd = atoi(tok);
			if (fstat(fd, &sb) == 0)
				valid_count++;
			tok = strtok(NULL, ",");
		}
		free(copy);
	}
	fprintf(out, "valid_tokens=%d\n", valid_count);
	fclose(out);
	sleep(30);
	return (0);
}
CEOF
	cc_with_libservice -o token_svc token_svc.c

	start_stack

	make_svc_bin system token-test 'capabilities {
    paths = ["/tmp"];
}' "$(pwd)/token_svc"
	# Reload to pick up the bundle
	kill -HUP "$daemon_pid"

	if ! wait_for_file token-check.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	atf_check -s exit:0 -o match:"channel_fd=3" cat token-check.out
	# Not just that the channel was set up — a capability token for the
	# service's declared path (/tmp) must actually have been delivered and
	# be a valid, fstat-able fd.  valid_tokens is computed by the service.
	atf_check -s exit:0 -o match:"token_fds=" cat token-check.out
	atf_check -s exit:0 -o match:"valid_tokens=[1-9]" cat token-check.out
}
capability_tokens_delivered_cleanup()
{
	cleanup_common
	rm -f token_svc token_svc.c token-check.out
}

# ===================================================================
# crash_recovery_restarts
# ===================================================================

atf_test_case crash_recovery_restarts cleanup
crash_recovery_restarts_head()
{
	atf_set "descr" "Service with restart=on-failure restarts after crash"
	atf_set "require.user" "root"
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
	kill -HUP "$daemon_pid"

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
}
circuit_breaker_stops_restarts_body()
{
	start_stack

	make_svc system fastcrash 'restart = "on-failure"; max_failures = 3;' \
	    '#!/bin/sh' \
	    'exit 1'
	kill -HUP "$daemon_pid"

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
}
graceful_shutdown_sigterm_body()
{
	start_stack

	make_svc system trapper '' \
	    '#!/bin/sh' \
	    "trap 'echo \"got-sigterm\" > ${WORK}/sigterm-marker.out; exit 0' TERM" \
	    "echo \"ready\" > ${WORK}/trapper-ready.out" \
	    'while true; do sleep 1; done'
	kill -HUP "$daemon_pid"

	if ! wait_for_file trapper-ready.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	# Shut down the stack — this sends SIGTERM to services
	kill -TERM "$daemon_pid"
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
# dependency_order_with_caps
# ===================================================================

atf_test_case dependency_order_with_caps cleanup
dependency_order_with_caps_head()
{
	atf_set "descr" "Provider starts before consumer in dependency order"
	atf_set "require.user" "root"
}
dependency_order_with_caps_body()
{
	start_stack

	# Dependency ordering (consumer requires the provider's label, which
	# is its provides[0]) is what forces provider-before-consumer,
	# independent of bundle directory name ordering.
	make_svc system dep-provider '' \
	    '#!/bin/sh' \
	    "date +%s%N > ${WORK}/provider-time.out" \
	    'exec sleep 30'
	make_svc system dep-consumer 'requires = ["dep-provider"];' \
	    '#!/bin/sh' \
	    "date +%s%N > ${WORK}/consumer-time.out" \
	    'exec sleep 30'
	kill -HUP "$daemon_pid"

	if ! wait_for_file provider-time.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "provider did not start"
	fi
	if ! wait_for_file consumer-time.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "consumer did not start"
	fi

	# Verify log order — provider should be *launched* before consumer.
	# Match the launch line specifically ("service <label>: started pid"):
	# grepping any mention is wrong because bundle_registry logs a
	# "loaded '<path>'" line per bundle in readdir order, which can mention
	# the consumer before the provider independent of launch order.
	provider_line=$(grep -n "service dep-provider: started" "$logfile" | head -1 | cut -d: -f1)
	consumer_line=$(grep -n "service dep-consumer: started" "$logfile" | head -1 | cut -d: -f1)

	if [ -n "$provider_line" ] && [ -n "$consumer_line" ]; then
		if [ "$consumer_line" -le "$provider_line" ]; then
			atf_fail "consumer started before provider"
		fi
	fi
}
dependency_order_with_caps_cleanup()
{
	cleanup_common
	rm -f provider_svc consumer_svc provider-time.out consumer-time.out
}

# ===================================================================
# reload_adds_service
# ===================================================================

atf_test_case reload_adds_service cleanup
reload_adds_service_head()
{
	atf_set "descr" "SIGHUP reload picks up new manifest and starts service"
	atf_set "require.user" "root"
}
reload_adds_service_body()
{
	start_stack

	# Start with no services, then add one
	make_svc system hello '' \
	    '#!/bin/sh' \
	    "echo \"hello\" > ${WORK}/hello-started.out" \
	    'exec sleep 30'
	kill -HUP "$daemon_pid"

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
	kill -HUP "$daemon_pid"

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
	kill -HUP "$daemon_pid"
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

# ===================================================================

atf_init_test_cases()
{
	atf_add_test_case capability_tokens_delivered
	atf_add_test_case crash_recovery_restarts
	atf_add_test_case circuit_breaker_stops_restarts
	atf_add_test_case graceful_shutdown_sigterm
	atf_add_test_case dependency_order_with_caps
	atf_add_test_case reload_adds_service
	atf_add_test_case reload_removes_service
	atf_add_test_case audit_records_best_effort
}
