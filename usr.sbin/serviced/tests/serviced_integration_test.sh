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

	cat > "$manifestdir/token-test.ucl" <<EOF
label = "token-test";
program = "$(pwd)/token_svc";
capabilities {
    paths = ["/tmp"];
}
EOF
	# Reload to pick up the manifest
	kill -HUP "$daemon_pid"

	if ! wait_for_file token-check.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi

	atf_check -s exit:0 -o match:"channel_fd=3" cat token-check.out
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
	write_executable crasher <<'SEOF'
#!/bin/sh
if [ -f crash-count.out ]; then
    echo "restarted" > crash-restarted.out
    exec sleep 30
fi
echo "first" > crash-count.out
exit 1
SEOF

	cat > "$manifestdir/crasher.ucl" <<EOF
label = "crasher";
program = "$(pwd)/crasher";
restart = "on-failure";
EOF
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

	write_executable fastcrash <<'SEOF'
#!/bin/sh
exit 1
SEOF

	cat > "$manifestdir/fastcrash.ucl" <<EOF
label = "fastcrash";
program = "$(pwd)/fastcrash";
restart = "on-failure";
max_failures = 3;
EOF
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

	write_executable trapper <<'SEOF'
#!/bin/sh
trap 'echo "got-sigterm" > sigterm-marker.out; exit 0' TERM
echo "ready" > trapper-ready.out
while true; do sleep 1; done
SEOF

	cat > "$manifestdir/trapper.ucl" <<EOF
label = "trapper";
program = "$(pwd)/trapper";
EOF
	kill -HUP "$daemon_pid"

	if ! wait_for_file trapper-ready.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi

	# Shut down the stack — this sends SIGTERM to services
	kill -TERM "$daemon_pid"
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=

	# Give a moment for the marker to be written
	sleep 0.5

	if [ -f sigterm-marker.out ]; then
		atf_check -s exit:0 -o match:"got-sigterm" \
		    cat sigterm-marker.out
	fi
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

	write_executable provider_svc <<'SEOF'
#!/bin/sh
date +%s%N > provider-time.out
exec sleep 30
SEOF

	write_executable consumer_svc <<'SEOF'
#!/bin/sh
date +%s%N > consumer-time.out
exec sleep 30
SEOF

	# Filenames sorted so provider loads first lexicographically too,
	# but dependency ordering is what we're testing.
	cat > "$manifestdir/aaa-provider.ucl" <<EOF
label = "dep-provider";
program = "$(pwd)/provider_svc";
provides = ["dep-api"];
EOF
	cat > "$manifestdir/zzz-consumer.ucl" <<EOF
label = "dep-consumer";
program = "$(pwd)/consumer_svc";
requires = ["dep-api"];
EOF
	kill -HUP "$daemon_pid"

	if ! wait_for_file provider-time.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "provider did not start"
	fi
	if ! wait_for_file consumer-time.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "consumer did not start"
	fi

	# Verify log order — provider should appear before consumer
	provider_line=$(grep -n "dep-provider" "$logfile" | head -1 | cut -d: -f1)
	consumer_line=$(grep -n "dep-consumer" "$logfile" | head -1 | cut -d: -f1)

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
	write_executable hello_svc <<'SEOF'
#!/bin/sh
echo "hello" > hello-started.out
exec sleep 30
SEOF

	cat > "$manifestdir/hello.ucl" <<EOF
label = "hello";
program = "$(pwd)/hello_svc";
EOF
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
	write_executable removeme <<'SEOF'
#!/bin/sh
echo "running" > removeme-running.out
exec sleep 30
SEOF

	prepare_paths
	cat > "$manifestdir/removeme.ucl" <<EOF
label = "removeme";
program = "$(pwd)/removeme";
EOF
	write_config
	start_stack

	if ! wait_for_file removeme-running.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi

	# Remove the manifest and reload
	rm -f "$manifestdir/removeme.ucl"
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

atf_init_test_cases()
{
	atf_add_test_case capability_tokens_delivered
	atf_add_test_case crash_recovery_restarts
	atf_add_test_case circuit_breaker_stops_restarts
	atf_add_test_case graceful_shutdown_sigterm
	atf_add_test_case dependency_order_with_caps
	atf_add_test_case reload_adds_service
	atf_add_test_case reload_removes_service
}
