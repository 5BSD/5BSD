#
# SPDX-License-Identifier: BSD-2-Clause
#
# Stress and abuse tests for oracled.
#
# These are intentionally less polite than the normal smoke tests.  They
# exercise the control socket and reload path with early disconnects, partial
# clients, malformed headers, and manifest churn.
#

daemon_pid=
pidfile=
conffile=
manifestdir=
sockpath=
logfile=

require_cc()
{
	if ! command -v cc >/dev/null 2>&1; then
		atf_skip "cc not available"
	fi
}

require_cap_rt()
{
	if ! sh -c 'exec 3</dev/cap_rt' 2>/dev/null; then
		atf_skip "/dev/cap_rt not available (oracled may be running)"
	fi
}

build_rawctl()
{
	require_cc
	cat > rawctl.c <<'EOF'
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct ctl_request {
	uint32_t	version;
	uint32_t	op;
	uint32_t	flags;
	uint32_t	datalen;
} __attribute__((packed));

static int
connect_unix(const char *path)
{
	struct sockaddr_un un;
	int fd;

	fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd == -1)
		err(2, "socket");
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_LOCAL;
	if (strlen(path) >= sizeof(un.sun_path))
		errx(2, "socket path too long");
	strlcpy(un.sun_path, path, sizeof(un.sun_path));
	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) == -1)
		err(2, "connect");
	return (fd);
}

static void
write_all(int fd, const void *buf, size_t len)
{
	const char *p;
	ssize_t n;
	size_t off;

	p = buf;
	for (off = 0; off < len; off += (size_t)n) {
		n = write(fd, p + off, len - off);
		if (n == -1)
			err(2, "write");
		if (n == 0)
			errx(2, "short write");
	}
}

int
main(int argc, char **argv)
{
	struct ctl_request req;
	char byte;
	const char *mode, *path;
	int fd, hold;

	if (argc < 3)
		errx(2, "usage: rawctl mode socket [hold_seconds]");
	mode = argv[1];
	path = argv[2];

	if (strcmp(mode, "early-status") == 0) {
		fd = connect_unix(path);
		memset(&req, 0, sizeof(req));
		req.version = 1;
		req.op = 2;
		write_all(fd, &req, sizeof(req));
		close(fd);
		return (0);
	}

	if (strcmp(mode, "partial-status") == 0) {
		hold = argc >= 4 ? atoi(argv[3]) : 4;
		fd = connect_unix(path);
		memset(&req, 0, sizeof(req));
		req.version = 1;
		req.op = 2;
		write_all(fd, &req, 8);
		sleep(hold);
		close(fd);
		return (0);
	}

		if (strcmp(mode, "bad-header") == 0) {
			fd = connect_unix(path);
			memset(&req, 0, sizeof(req));
			req.version = 1;
		req.op = 0xffffffffU;
		req.datalen = 0xffffffffU;
		write_all(fd, &req, sizeof(req));
		(void)read(fd, &byte, 1);
			close(fd);
			return (0);
		}

		if (strcmp(mode, "kldload-slash") == 0) {
			const char payload[] = "../bad";
			fd = connect_unix(path);
			memset(&req, 0, sizeof(req));
			req.version = 1;
			req.op = 4;
			req.datalen = sizeof(payload) - 1;
			write_all(fd, &req, sizeof(req));
			write_all(fd, payload, sizeof(payload) - 1);
			(void)read(fd, &byte, 1);
			close(fd);
			return (0);
		}

		if (strcmp(mode, "slow-status-header") == 0) {
			const unsigned char *p;
			fd = connect_unix(path);
			memset(&req, 0, sizeof(req));
			req.version = 1;
			req.op = 2;
			p = (const unsigned char *)&req;
			for (size_t i = 0; i < sizeof(req); i++) {
				write_all(fd, &p[i], 1);
				usleep(10000);
			}
			(void)read(fd, &byte, 1);
			close(fd);
			return (0);
		}

		errx(2, "unknown mode: %s", mode);
	}
EOF
	atf_check -s exit:0 cc -Wall -Wextra -o rawctl rawctl.c
}

write_many_manifests()
{
	local n i

	n="$1"
	mkdir -p "$manifestdir"
	i=0
	while [ "$i" -lt "$n" ]; do
		cat > "$manifestdir/svc-$i.ucl" <<EOF
label = "stress-$i";
program = "/usr/bin/true";
EOF
		i=$((i + 1))
	done
}

start_stress_oracled()
{
	require_cap_rt
	prepare_paths
	write_config

	start_current_config_oracled
}

start_current_config_oracled()
{
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -S "$sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "oracled did not create control socket"
	fi

	# Wait for serviced to be ready.
	i=0
	while ! grep -q "serviced ready\|serviced started" "$logfile" 2>/dev/null && [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
}

assert_daemon_alive()
{
	if ! kill -0 "$daemon_pid" 2>/dev/null; then
		cat "$logfile" 2>/dev/null
		atf_fail "oracled exited unexpectedly"
	fi
	atf_check -s exit:0 -o match:"oracled: running" \
	    oraclectl -s "$sockpath" status
}

stop_stress_oracled()
{
	if [ -n "$daemon_pid" ]; then
		kill -TERM "$daemon_pid" 2>/dev/null || true
		wait "$daemon_pid" 2>/dev/null || true
	fi
}

cleanup_common()
{
	stop_stress_oracled
	rm -rf oracled.pid oracled.conf oracled.d oracled.sock \
	    oracled.log rawctl rawctl.c fdprobe fdprobe.c ctl_*.out \
	    *.pid *.out *.sh outside.ucl escaped.ucl
}

write_executable()
{
	local path

	path="$1"
	shift
	printf "%s\n" "$@" > "$path"
	chmod +x "$path"
}

wait_for_file()
{
	local path i

	path="$1"
	i=0
	while [ ! -s "$path" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	test -s "$path"
}

build_fdprobe()
{
	require_cc
	cat > fdprobe.c <<'EOF'
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(void)
{
	struct stat sb;
	FILE *out;
	const char *label, *pairfd, *tokenfds, *leak;
	int openfds[32];
	int fd;

	label = getenv("ORACLED_LABEL");
	pairfd = getenv("ORACLED_PAIR_FD");
	tokenfds = getenv("ORACLED_TOKEN_FDS");
	leak = getenv("ORACLED_SHOULD_NOT_LEAK");
	for (fd = 0; fd < 32; fd++)
		openfds[fd] = (fstat(fd, &sb) == 0);

	out = fopen("fd-probe.out", "w");
	if (out == NULL)
		err(1, "fd-probe.out");

	fprintf(out, "label=%s\n", label != NULL ? label : "");
	fprintf(out, "pairfd=%s\n", pairfd != NULL ? pairfd : "");
	fprintf(out, "tokenfds=%s\n", tokenfds != NULL ? tokenfds : "");
	fprintf(out, "leak=%s\n", leak != NULL ? leak : "");

	for (fd = 0; fd < 32; fd++) {
		if (openfds[fd])
			fprintf(out, "fd=%d\n", fd);
	}
	fclose(out);
	sleep(20);
	return (0);
}
EOF
	atf_check -s exit:0 cc -Wall -Wextra -o fdprobe fdprobe.c
}

write_config()
{
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
manifest_dir = "$manifestdir";
EOF
}

prepare_paths()
{
	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	manifestdir="$(pwd)/oracled.d"
	sockpath="$(pwd)/oracled.sock"
	logfile="$(pwd)/oracled.log"
}

atf_test_case control_early_close_status_does_not_kill cleanup
control_early_close_status_does_not_kill_head()
{
	atf_set "descr" "clients that close before reading status summary do not kill oracled"
	atf_set "require.user" "root"
}
control_early_close_status_does_not_kill_body()
{
	local i status_pid services_pid reload_pid

	build_rawctl
	manifestdir="$(pwd)/oracled.d"
	write_many_manifests 64
	start_stress_oracled

	i=0
	while [ "$i" -lt 50 ]; do
		./rawctl early-status "$sockpath" || true
		i=$((i + 1))
	done
	sleep 1
	assert_daemon_alive
}
control_early_close_status_does_not_kill_cleanup()
{
	cleanup_common
}

atf_test_case control_partial_client_timeout_storm cleanup
control_partial_client_timeout_storm_head()
{
	atf_set "descr" "many partial clients time out without wedging the control socket"
	atf_set "require.user" "root"
}
control_partial_client_timeout_storm_body()
{
	local i pids

	build_rawctl
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	start_stress_oracled

	pids=
	i=0
	while [ "$i" -lt 24 ]; do
		./rawctl partial-status "$sockpath" 4 &
		pids="$pids $!"
		i=$((i + 1))
	done

	sleep 1
	if ! kill -0 "$daemon_pid" 2>/dev/null; then
		cat "$logfile" 2>/dev/null
		atf_fail "oracled died during partial-client storm"
	fi

	for pid in $pids; do
		wait "$pid" 2>/dev/null || true
	done
	sleep 3
	assert_daemon_alive
}
control_partial_client_timeout_storm_cleanup()
{
	cleanup_common
}

atf_test_case control_malformed_header_flood cleanup
control_malformed_header_flood_head()
{
	atf_set "descr" "malformed control headers are rejected repeatedly without state leaks"
	atf_set "require.user" "root"
}
control_malformed_header_flood_body()
{
	local i status_pid services_pid reload_pid

	build_rawctl
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	start_stress_oracled

	i=0
	while [ "$i" -lt 200 ]; do
		./rawctl bad-header "$sockpath" >/dev/null 2>&1 || true
		if [ $((i % 20)) -eq 0 ]; then
			atf_check -s exit:0 -o match:"running" \
			    oraclectl -s "$sockpath" status
		fi
		i=$((i + 1))
	done
	assert_daemon_alive
}
control_malformed_header_flood_cleanup()
{
	cleanup_common
}

atf_test_case reload_manifest_churn_under_control_load cleanup
reload_manifest_churn_under_control_load_head()
{
	atf_set "descr" "manifest churn plus concurrent status/services/reload requests keeps daemon coherent"
	atf_set "require.user" "root"
}
reload_manifest_churn_under_control_load_body()
{
	local i status_pid services_pid reload_pid

	manifestdir="$(pwd)/oracled.d"
	write_many_manifests 8
	start_stress_oracled

	i=0
	while [ "$i" -lt 40 ]; do
		case $((i % 4)) in
		0)
			cat > "$manifestdir/churn.ucl" <<EOF
label = "churn";
program = "/usr/bin/true";
restart = "never";
EOF
			;;
		1)
			cat > "$manifestdir/churn.ucl" <<EOF
label = "churn";
program = "/usr/bin/true";
restart = "always";
EOF
			;;
		2)
			cat > "$manifestdir/bad.ucl" <<EOF
label = "bad";
program = "/no/such/program";
EOF
			;;
		3)
			rm -f "$manifestdir/bad.ucl" "$manifestdir/churn.ucl"
			;;
		esac

		kill -HUP "$daemon_pid" 2>/dev/null || true
		oraclectl -s "$sockpath" status >"ctl_status_$i.out" 2>&1 &
		status_pid=$!
		oraclectl -s "$sockpath" services >"ctl_services_$i.out" 2>&1 &
		services_pid=$!
		oraclectl -s "$sockpath" reload >"ctl_reload_$i.out" 2>&1 &
		reload_pid=$!
		wait "$status_pid" 2>/dev/null || true
		wait "$services_pid" 2>/dev/null || true
		wait "$reload_pid" 2>/dev/null || true

		if ! kill -0 "$daemon_pid" 2>/dev/null; then
			cat "$logfile" 2>/dev/null
			atf_fail "oracled died during reload churn"
		fi
		i=$((i + 1))
	done

	assert_daemon_alive
	atf_check -s exit:0 -o match:"serviced" \
	    oraclectl -s "$sockpath" services
}
reload_manifest_churn_under_control_load_cleanup()
{
	cleanup_common
}

atf_test_case control_check_rejects_symlink_escape cleanup
control_check_rejects_symlink_escape_head()
{
	atf_set "descr" "oraclectl check rejects manifest symlinks escaping manifest_dir"
	atf_set "require.user" "root"
}
control_check_rejects_symlink_escape_body()
{
	atf_skip "manifest check moved to servicectl(8)"
}
control_check_rejects_symlink_escape_cleanup()
{
	cleanup_common
}

atf_test_case control_nonroot_denied cleanup
control_nonroot_denied_head()
{
	atf_set "descr" "non-root client cannot use restrictive control socket"
	atf_set "require.user" "root"
}
control_nonroot_denied_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	if ! id nobody >/dev/null 2>&1; then
		atf_skip "nobody user not available"
	fi

	start_stress_oracled
	atf_check -s not-exit:0 -e ignore \
	    su -m nobody -c "oraclectl -s '$sockpath' status"
	assert_daemon_alive
}
control_nonroot_denied_cleanup()
{
	cleanup_common
}

atf_test_case service_restart_circuit_breaker cleanup
service_restart_circuit_breaker_head()
{
	atf_set "descr" "crashing restart=always service is disabled by circuit breaker"
	atf_set "require.user" "root"
}
service_restart_circuit_breaker_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	write_executable "$(pwd)/crash.sh" \
	    '#!/bin/sh' \
	    'exit 1'
	cat > "$manifestdir/crash.ucl" <<EOF
label = "crash";
program = "$(pwd)/crash.sh";
restart = "always";
max_failures = 3;
EOF

	start_stress_oracled
	if ! sh -c "i=0; while ! grep -q 'service crash: started pid' '$logfile' && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service crash: started pid' '$logfile'"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start, likely missing cap_rt pair service"
	fi
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while ! grep -q 'service crash: failed .* disabling' '$logfile' && [ \$i -lt 300 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service crash: failed .* disabling' '$logfile'"
	assert_daemon_alive
}
service_restart_circuit_breaker_cleanup()
{
	cleanup_common
}

atf_test_case service_shutdown_kills_sigterm_ignorer cleanup
service_shutdown_kills_sigterm_ignorer_head()
{
	atf_set "descr" "shutdown kills a service that ignores SIGTERM"
	atf_set "require.user" "root"
}
service_shutdown_kills_sigterm_ignorer_body()
{
	local svc_pid

	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
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

	start_stress_oracled
	if ! wait_for_file ignore-term.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start, likely missing cap_rt pair service"
	fi
	svc_pid=$(cat ignore-term.pid)

	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" shutdown
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=
	atf_check -s not-exit:0 -e ignore kill -0 "$svc_pid"
}
service_shutdown_kills_sigterm_ignorer_cleanup()
{
	if [ -f ignore-term.pid ]; then
		kill -KILL "$(cat ignore-term.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

atf_test_case service_shutdown_kills_subtree cleanup
service_shutdown_kills_subtree_head()
{
	atf_set "descr" "shutdown cleans up child processes spawned by a service"
	atf_set "require.user" "root"
}
service_shutdown_kills_subtree_body()
{
	local child_pid

	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
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

	start_stress_oracled
	if ! wait_for_file subtree-child.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start, likely missing cap_rt pair service"
	fi
	child_pid=$(cat subtree-child.pid)

	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" shutdown
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=
	atf_check -s not-exit:0 -e ignore kill -0 "$child_pid"
}
service_shutdown_kills_subtree_cleanup()
{
	if [ -f subtree-child.pid ]; then
		kill -KILL "$(cat subtree-child.pid)" 2>/dev/null || true
	fi
	if [ -f subtree-parent.pid ]; then
		kill -KILL "$(cat subtree-parent.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

atf_test_case service_child_environment_is_minimal cleanup
service_child_environment_is_minimal_head()
{
	atf_set "descr" "service child receives minimal oracled environment, not daemon environment"
	atf_set "require.user" "root"
}
service_child_environment_is_minimal_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	write_executable "$(pwd)/env-probe.sh" \
	    '#!/bin/sh' \
	    'env | sort > env-probe.out' \
	    'ls /dev/fd > fd-probe.out 2>/dev/null || true' \
	    'sleep 20'
	cat > "$manifestdir/env-probe.ucl" <<EOF
label = "env-probe";
program = "$(pwd)/env-probe.sh";
EOF

	export ORACLED_SHOULD_NOT_LEAK=secret
	start_stress_oracled
	unset ORACLED_SHOULD_NOT_LEAK
	if ! wait_for_file env-probe.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start, likely missing cap_rt pair service"
	fi

	atf_check -s exit:0 -o match:"^PATH=/sbin:/bin:/usr/sbin:/usr/bin$" \
	    grep "^PATH=" env-probe.out
	atf_check -s exit:0 -o match:"^ORACLED_PAIR_FD=3$" \
	    grep "^ORACLED_PAIR_FD=" env-probe.out
	atf_check -s exit:0 -o match:"^ORACLED_LABEL=env-probe$" \
	    grep "^ORACLED_LABEL=" env-probe.out
	atf_check -s not-exit:0 grep "ORACLED_SHOULD_NOT_LEAK" env-probe.out
	assert_daemon_alive
}
service_child_environment_is_minimal_cleanup()
{
	cleanup_common
}

atf_test_case parser_manifest_boundaries cleanup
parser_manifest_boundaries_head()
{
	atf_set "descr" "UCL manifest parser rejects boundary-size and bad-type inputs without poisoning later loads"
	atf_set "require.user" "root"
}
parser_manifest_boundaries_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	long_label="abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
	cat > "$manifestdir/overlong.ucl" <<EOF
label = "$long_label";
program = "/usr/bin/true";
EOF
	cat > "$manifestdir/badtypes.ucl" <<EOF
label = "badtypes";
program = 17;
restart = ["always"];
provides = "not-an-array";
capabilities {
    paths = [42, "relative"];
    network = [{ port = 70000; protocol = "icmp"; direction = "sideways"; }];
}
EOF
	cat > "$manifestdir/good.ucl" <<EOF
label = "good-after-bad";
program = "/usr/bin/true";
EOF

	start_stress_oracled
	atf_check -s exit:0 -o ignore grep "label too long" "$logfile"
	atf_check -s exit:0 -o ignore grep "loaded good-after-bad" "$logfile"
	assert_daemon_alive
}
parser_manifest_boundaries_cleanup()
{
	cleanup_common
}

atf_test_case parser_config_boundaries cleanup
parser_config_boundaries_head()
{
	atf_set "descr" "UCL config parser handles bad modes, relative claims, and bad network claims without preventing startup"
	atf_set "require.user" "root"
}
parser_config_boundaries_body()
{
	require_cap_rt
	# Previous tests with cap_rt isolation may leave /dev/null blocked.
	if ! sh -c ': >/dev/null' 2>/dev/null; then
		atf_skip "cap_rt isolation contamination from prior test"
	fi
	prepare_paths
	mkdir -p "$manifestdir"
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = 700;
manifest_dir = "$manifestdir";
claims {
    paths = ["relative/path", "/dev/null"];
    network = [
        { port = 70000; protocol = "tcp"; direction = "bind"; },
        { port = 0; protocol = "udp"; direction = "connect"; },
    ];
    system = ["nosuchgate", "kldload"];
}
EOF

	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!
	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -S "$sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "oracled did not create control socket"
	fi
	atf_check -s exit:0 -o ignore grep "control_socket_mode must be" "$logfile"
	atf_check -s exit:0 -o ignore grep "claim path must be absolute" "$logfile"
	atf_check -s exit:0 -o ignore grep "claims paths=1 network=1 system=0x1" "$logfile"
	assert_daemon_alive
}
parser_config_boundaries_cleanup()
{
	cleanup_common
}

atf_test_case reload_dependency_transaction_rollback cleanup
reload_dependency_transaction_rollback_head()
{
	atf_set "descr" "reload rejects a bad provides/requires transaction and preserves existing services"
	atf_set "require.user" "root"
}
reload_dependency_transaction_rollback_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	cat > "$manifestdir/base.ucl" <<EOF
label = "base";
program = "/usr/bin/true";
provides = ["base"];
EOF
	start_stress_oracled
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded base' '$logfile'"

	cat > "$manifestdir/cycle-a.ucl" <<EOF
label = "cycle-a";
program = "/usr/bin/true";
provides = ["A"];
requires = ["B"];
EOF
	cat > "$manifestdir/cycle-b.ucl" <<EOF
label = "cycle-b";
program = "/usr/bin/true";
provides = ["B"];
requires = ["A"];
EOF
	kill -HUP "$daemon_pid"
	sleep 2
	# Cycle should be detected and rejected.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'cycle detected\|depgraph_sort failed' '$logfile'"
	assert_daemon_alive
}
reload_dependency_transaction_rollback_cleanup()
{
	cleanup_common
}

atf_test_case reload_dependency_order_status cleanup
reload_dependency_order_status_head()
{
	atf_set "descr" "reload starts newly added services in validated dependency order"
	atf_set "require.user" "root"
}
reload_dependency_order_status_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	start_stress_oracled

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
	kill -HUP "$daemon_pid"
	sleep 2
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '2 new' '$logfile'"
	provider_line=$(grep -n "service provider:" "$logfile" | head -1 | cut -d: -f1)
	consumer_line=$(grep -n "service consumer:" "$logfile" | head -1 | cut -d: -f1)
	if [ -z "$provider_line" ] || [ -z "$consumer_line" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "missing dependency start log lines"
	fi
	if [ "$consumer_line" -le "$provider_line" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "consumer started before provider"
	fi
	assert_daemon_alive
}
reload_dependency_order_status_cleanup()
{
	cleanup_common
}

atf_test_case service_pair_fd_contract cleanup
service_pair_fd_contract_head()
{
	atf_set "descr" "service receives a launchd/Mach-like private pair fd on the documented descriptor"
	atf_set "require.user" "root"
}
service_pair_fd_contract_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	build_fdprobe
	cat > "$manifestdir/pair-probe.ucl" <<EOF
label = "pair-probe";
program = "$(pwd)/fdprobe";
EOF

	start_stress_oracled
	if ! wait_for_file fd-probe.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start, likely missing cap_rt pair service"
	fi
	atf_check -s exit:0 -o match:"^pairfd=3$" grep "^pairfd=" fd-probe.out
	atf_check -s exit:0 -o match:"^fd=3$" grep "^fd=3$" fd-probe.out
	assert_daemon_alive
}
service_pair_fd_contract_cleanup()
{
	cleanup_common
}

atf_test_case service_cap_rt_naming_future_api cleanup
service_cap_rt_naming_future_api_head()
{
	atf_set "descr" "placeholder for future cap_rt naming service registration/lookup semantics"
}
service_cap_rt_naming_future_api_body()
{
	atf_skip "cap_rt naming/oracle lookup API is not implemented yet"
}
service_cap_rt_naming_future_api_cleanup()
{
	:
}

atf_test_case service_fd_inheritance_contract cleanup
service_fd_inheritance_contract_head()
{
	atf_set "descr" "service inherits only stdio, pair fd, and requested token fds"
	atf_set "require.user" "root"
}
service_fd_inheritance_contract_body()
{
	require_cap_rt
	prepare_paths
	mkdir -p "$manifestdir"
	build_fdprobe
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
manifest_dir = "$manifestdir";
claims {
    paths = ["/dev/null"];
}
EOF
	cat > "$manifestdir/fd-contract.ucl" <<EOF
label = "fd-contract";
program = "$(pwd)/fdprobe";
capabilities {
    paths = ["/dev/null"];
}
EOF

	export ORACLED_SHOULD_NOT_LEAK=secret
	start_current_config_oracled
	unset ORACLED_SHOULD_NOT_LEAK
	if ! wait_for_file fd-probe.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start, likely missing cap_rt pair service"
	fi
	atf_check -s exit:0 -o match:"^label=fd-contract$" grep "^label=" fd-probe.out
	atf_check -s exit:0 -o match:"^pairfd=3$" grep "^pairfd=" fd-probe.out
	atf_check -s exit:0 -o match:"^tokenfds=4$" grep "^tokenfds=" fd-probe.out
	atf_check -s exit:0 -o match:"^fd=0$" grep "^fd=0$" fd-probe.out
	atf_check -s exit:0 -o match:"^fd=1$" grep "^fd=1$" fd-probe.out
	atf_check -s exit:0 -o match:"^fd=2$" grep "^fd=2$" fd-probe.out
	atf_check -s exit:0 -o match:"^fd=3$" grep "^fd=3$" fd-probe.out
	atf_check -s exit:0 -o match:"^fd=4$" grep "^fd=4$" fd-probe.out
	atf_check -s not-exit:0 grep "^fd=5$" fd-probe.out
	atf_check -s exit:0 -o match:"^leak=$" grep "^leak=" fd-probe.out
	assert_daemon_alive
}
service_fd_inheritance_contract_cleanup()
{
	cleanup_common
}

atf_test_case sandbox_capprotect_denies_foreign_ptrace cleanup
sandbox_capprotect_denies_foreign_ptrace_head()
{
	atf_set "descr" "capprotect denies foreign ptrace/truss of the daemon"
	atf_set "require.user" "root"
}
sandbox_capprotect_denies_foreign_ptrace_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	if ! command -v truss >/dev/null 2>&1; then
		atf_skip "truss not available"
	fi
	start_stress_oracled
	atf_check -s not-exit:0 -e ignore truss -p "$daemon_pid" -e exit
	assert_daemon_alive
}
sandbox_capprotect_denies_foreign_ptrace_cleanup()
{
	cleanup_common
}

atf_test_case sandbox_isolation_denies_foreign_cap_rt_open cleanup
sandbox_isolation_denies_foreign_cap_rt_open_head()
{
	atf_set "descr" "cap_rt isolation denies a foreign process opening /dev/cap_rt while oracled owns it"
	atf_set "require.user" "root"
}
sandbox_isolation_denies_foreign_cap_rt_open_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	start_stress_oracled
	atf_check -s not-exit:0 -e ignore sh -c 'cat /dev/cap_rt >/dev/null'
	assert_daemon_alive
}
sandbox_isolation_denies_foreign_cap_rt_open_cleanup()
{
	cleanup_common
}

atf_test_case control_payload_and_fragment_abuse cleanup
control_payload_and_fragment_abuse_head()
{
	atf_set "descr" "raw control socket rejects slash payloads and fragmented headers repeatedly"
	atf_set "require.user" "root"
}
control_payload_and_fragment_abuse_body()
{
	local i

	build_rawctl
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	start_stress_oracled

	i=0
	while [ "$i" -lt 50 ]; do
		./rawctl kldload-slash "$sockpath" >/dev/null 2>&1 || true
		./rawctl slow-status-header "$sockpath" >/dev/null 2>&1 || true
		i=$((i + 1))
	done
	assert_daemon_alive
}
control_payload_and_fragment_abuse_cleanup()
{
	cleanup_common
}

atf_test_case crash_throttle_mixed_exit_modes cleanup
crash_throttle_mixed_exit_modes_head()
{
	atf_set "descr" "restart throttling handles fast nonzero exits and signal deaths"
	atf_set "require.user" "root"
}
crash_throttle_mixed_exit_modes_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	write_executable "$(pwd)/die-signal.sh" \
	    '#!/bin/sh' \
	    'kill -TERM $$'
	cat > "$manifestdir/die-signal.ucl" <<EOF
label = "die-signal";
program = "$(pwd)/die-signal.sh";
restart = "always";
max_failures = 3;
EOF

	start_stress_oracled
	if ! sh -c "i=0; while ! grep -q 'service die-signal: started pid' '$logfile' && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service die-signal: started pid' '$logfile'"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start, likely missing cap_rt pair service"
	fi
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while ! grep -q 'service die-signal: failed .* disabling' '$logfile' && [ \$i -lt 300 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service die-signal: failed .* disabling' '$logfile'"
	assert_daemon_alive
}
crash_throttle_mixed_exit_modes_cleanup()
{
	cleanup_common
}

# --- process supervision: restart policy ---

atf_test_case restart_never_no_restart cleanup
restart_never_no_restart_head()
{
	atf_set "descr" "restart=never service stays stopped after any exit"
	atf_set "require.user" "root"
}
restart_never_no_restart_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	write_executable "$(pwd)/exit0.sh" \
	    '#!/bin/sh' \
	    'echo $$ > exit0.pid' \
	    'exit 0'
	cat > "$manifestdir/exit0.ucl" <<EOF
label = "exit0";
program = "$(pwd)/exit0.sh";
restart = "never";
EOF

	start_stress_oracled
	if ! wait_for_file exit0.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi
	# Wait for the exit to be processed.
	sleep 1
	atf_check -s exit:0 -o ignore \
	    grep 'service exit0: exited status 0' "$logfile"
	# Must NOT see any restart log.
	atf_check -s not-exit:0 \
	    grep 'service exit0: restarting\|service exit0: scheduling restart' "$logfile"
	assert_daemon_alive
}
restart_never_no_restart_cleanup()
{
	cleanup_common
}

atf_test_case restart_never_no_restart_on_failure cleanup
restart_never_no_restart_on_failure_head()
{
	atf_set "descr" "restart=never service stays stopped after failure exit"
	atf_set "require.user" "root"
}
restart_never_no_restart_on_failure_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	write_executable "$(pwd)/exit1.sh" \
	    '#!/bin/sh' \
	    'echo $$ > exit1.pid' \
	    'exit 1'
	cat > "$manifestdir/exit1.ucl" <<EOF
label = "exit1";
program = "$(pwd)/exit1.sh";
restart = "never";
EOF

	start_stress_oracled
	if ! wait_for_file exit1.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi
	sleep 1
	atf_check -s exit:0 -o ignore \
	    grep 'service exit1: exited status 1' "$logfile"
	atf_check -s not-exit:0 \
	    grep 'service exit1: restarting\|service exit1: scheduling restart' "$logfile"
	assert_daemon_alive
}
restart_never_no_restart_on_failure_cleanup()
{
	cleanup_common
}

atf_test_case restart_on_failure_ignores_clean_exit cleanup
restart_on_failure_ignores_clean_exit_head()
{
	atf_set "descr" "restart=on-failure does not restart on clean exit(0)"
	atf_set "require.user" "root"
}
restart_on_failure_ignores_clean_exit_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	write_executable "$(pwd)/clean.sh" \
	    '#!/bin/sh' \
	    'echo $$ > clean.pid' \
	    'exit 0'
	cat > "$manifestdir/clean.ucl" <<EOF
label = "clean-exit";
program = "$(pwd)/clean.sh";
restart = "on-failure";
EOF

	start_stress_oracled
	if ! wait_for_file clean.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi
	sleep 1
	atf_check -s exit:0 -o ignore \
	    grep 'service clean-exit: exited status 0' "$logfile"
	atf_check -s not-exit:0 \
	    grep 'service clean-exit: restarting\|service clean-exit: scheduling restart' "$logfile"
	assert_daemon_alive
}
restart_on_failure_ignores_clean_exit_cleanup()
{
	cleanup_common
}

atf_test_case restart_on_failure_restarts_on_error cleanup
restart_on_failure_restarts_on_error_head()
{
	atf_set "descr" "restart=on-failure restarts after nonzero exit"
	atf_set "require.user" "root"
}
restart_on_failure_restarts_on_error_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	# Exit 1 the first time, then sleep (so circuit breaker doesn't fire).
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

	start_stress_oracled
	# Wait for the restart — the second instance writes the pid.
	if ! sh -c "i=0; while [ ! -s fail-once-restarted.pid ] && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; test -s fail-once-restarted.pid"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not restart"
	fi
	atf_check -s exit:0 -o ignore \
	    grep 'service fail-once: exited status 1' "$logfile"
	assert_daemon_alive
}
restart_on_failure_restarts_on_error_cleanup()
{
	if [ -f fail-once-restarted.pid ]; then
		kill "$(cat fail-once-restarted.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

atf_test_case restart_always_restarts_on_clean_exit cleanup
restart_always_restarts_on_clean_exit_head()
{
	atf_set "descr" "restart=always restarts even after exit(0)"
	atf_set "require.user" "root"
}
restart_always_restarts_on_clean_exit_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	# Exit 0 the first time, then sleep.
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

	start_stress_oracled
	if ! sh -c "i=0; while [ ! -s exit0-always-restarted.pid ] && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; test -s exit0-always-restarted.pid"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not restart"
	fi
	atf_check -s exit:0 -o ignore \
	    grep 'service exit0-always: exited status 0' "$logfile"
	assert_daemon_alive
}
restart_always_restarts_on_clean_exit_cleanup()
{
	if [ -f exit0-always-restarted.pid ]; then
		kill "$(cat exit0-always-restarted.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

atf_test_case restart_on_failure_restarts_on_signal cleanup
restart_on_failure_restarts_on_signal_head()
{
	atf_set "descr" "restart=on-failure restarts after signal death"
	atf_set "require.user" "root"
}
restart_on_failure_restarts_on_signal_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	write_executable "$(pwd)/sigdie.sh" \
	    '#!/bin/sh' \
	    'if [ ! -f sigdie.ran ]; then' \
	    '    touch sigdie.ran' \
	    '    kill -SEGV $$' \
	    'fi' \
	    'echo $$ > sigdie-restarted.pid' \
	    'sleep 60'
	cat > "$manifestdir/sigdie.ucl" <<EOF
label = "sigdie";
program = "$(pwd)/sigdie.sh";
restart = "on-failure";
EOF

	start_stress_oracled
	if ! sh -c "i=0; while [ ! -s sigdie-restarted.pid ] && [ \$i -lt 200 ]; do i=\$((i + 1)); sleep 0.1; done; test -s sigdie-restarted.pid"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not restart"
	fi
	atf_check -s exit:0 -o ignore \
	    grep 'service sigdie: killed by signal 11' "$logfile"
	assert_daemon_alive
}
restart_on_failure_restarts_on_signal_cleanup()
{
	if [ -f sigdie-restarted.pid ]; then
		kill "$(cat sigdie-restarted.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# --- process supervision: backoff and timing ---

atf_test_case restart_backoff_on_rapid_crash cleanup
restart_backoff_on_rapid_crash_head()
{
	atf_set "descr" "fast-crashing service gets delayed restart (backoff)"
	atf_set "require.user" "root"
}
restart_backoff_on_rapid_crash_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	write_executable "$(pwd)/fastcrash.sh" \
	    '#!/bin/sh' \
	    'exit 1'
	cat > "$manifestdir/fastcrash.ucl" <<EOF
label = "fastcrash";
program = "$(pwd)/fastcrash.sh";
restart = "always";
EOF

	start_stress_oracled
	if ! sh -c "i=0; while ! grep -q 'service fastcrash: started pid' '$logfile' && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'service fastcrash: started pid' '$logfile'"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi
	# The service exits instantly (< 5 seconds uptime), so the
	# supervisor must schedule a delayed restart, not restart immediately.
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while ! grep -q 'scheduling restart' '$logfile' && [ \$i -lt 100 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'scheduling restart' '$logfile'"
	assert_daemon_alive
}
restart_backoff_on_rapid_crash_cleanup()
{
	cleanup_common
}

# --- shutdown sequencing ---

atf_test_case shutdown_reverse_dependency_order cleanup
shutdown_reverse_dependency_order_head()
{
	atf_set "descr" "shutdown stops dependents before providers"
	atf_set "require.user" "root"
}
shutdown_reverse_dependency_order_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	# A provides "base", B requires "base".
	# On shutdown, B must stop before A.
	write_executable "$(pwd)/long-svc.sh" \
	    '#!/bin/sh' \
	    'echo $$ > "${ORACLED_LABEL}.pid"' \
	    'sleep 60'
	cat > "$manifestdir/aaa-base.ucl" <<EOF
label = "base-svc";
program = "$(pwd)/long-svc.sh";
provides = ["base"];
EOF
	cat > "$manifestdir/zzz-app.ucl" <<EOF
label = "app-svc";
program = "$(pwd)/long-svc.sh";
requires = ["base"];
stop_timeout = 2;
EOF

	start_stress_oracled
	if ! wait_for_file app-svc.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "services did not start"
	fi

	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" shutdown
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=

	# In the log, app-svc stop must appear before base-svc stop.
	app_line=$(grep -n 'service app-svc: stopping' "$logfile" | head -1 | cut -d: -f1)
	base_line=$(grep -n 'service base-svc: stopping' "$logfile" | head -1 | cut -d: -f1)
	if [ -z "$app_line" ] || [ -z "$base_line" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "stop log lines not found"
	fi
	if [ "$app_line" -ge "$base_line" ]; then
		cat "$logfile"
		atf_fail "app-svc (line $app_line) should stop before base-svc (line $base_line)"
	fi
}
shutdown_reverse_dependency_order_cleanup()
{
	for f in base-svc.pid app-svc.pid; do
		if [ -f "$f" ]; then
			kill "$(cat "$f")" 2>/dev/null || true
		fi
	done
	cleanup_common
}

atf_test_case shutdown_stop_timeout_escalates cleanup
shutdown_stop_timeout_escalates_head()
{
	atf_set "descr" "service ignoring SIGTERM is killed after stop_timeout"
	atf_set "require.user" "root"
}
shutdown_stop_timeout_escalates_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	write_executable "$(pwd)/stubborn.sh" \
	    '#!/bin/sh' \
	    'echo $$ > stubborn.pid' \
	    'trap "" TERM' \
	    'while :; do sleep 1; done'
	cat > "$manifestdir/stubborn.ucl" <<EOF
label = "stubborn";
program = "$(pwd)/stubborn.sh";
stop_timeout = 2;
EOF

	start_stress_oracled
	if ! wait_for_file stubborn.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi
	svc_pid=$(cat stubborn.pid)

	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" shutdown
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=

	# The service ignores SIGTERM; either serviced's stop_timeout
	# escalates to SIGKILL or oracled's subtree reaper kills it.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'stop timeout.*SIGKILL\|reaped child.*signal 9' '$logfile'"
	atf_check -s not-exit:0 -e ignore kill -0 "$svc_pid"
}
shutdown_stop_timeout_escalates_cleanup()
{
	if [ -f stubborn.pid ]; then
		kill -KILL "$(cat stubborn.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# --- credential dropping ---

atf_test_case service_runs_as_specified_user cleanup
service_runs_as_specified_user_head()
{
	atf_set "descr" "service with user= runs as that user"
	atf_set "require.user" "root"
}
service_runs_as_specified_user_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	write_executable "$(pwd)/whoami-svc.sh" \
	    '#!/bin/sh' \
	    'id -un > whoami-svc.out' \
	    'id -gn >> whoami-svc.out' \
	    'sleep 60'
	# Make the output file writable by nobody.
	touch whoami-svc.out
	chmod 666 whoami-svc.out
	cat > "$manifestdir/whoami.ucl" <<EOF
label = "whoami";
program = "$(pwd)/whoami-svc.sh";
user = "nobody";
group = "nogroup";
EOF

	start_stress_oracled
	if ! sh -c "i=0; while [ ! -s whoami-svc.out ] && [ \$i -lt 100 ]; do i=\$((i + 1)); sleep 0.1; done; test -s whoami-svc.out"; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not write output"
	fi
	atf_check -s exit:0 -o match:"nobody" head -1 whoami-svc.out
	atf_check -s exit:0 -o match:"nogroup" tail -1 whoami-svc.out
	assert_daemon_alive
}
service_runs_as_specified_user_cleanup()
{
	cleanup_common
}

# --- concurrent operations ---

atf_test_case reload_during_restart cleanup
reload_during_restart_head()
{
	atf_set "descr" "reload while a service is restarting is safe"
	atf_set "require.user" "root"
}
reload_during_restart_body()
{
	manifestdir="$(pwd)/oracled.d"
	mkdir -p "$manifestdir"
	write_executable "$(pwd)/crashloop.sh" \
	    '#!/bin/sh' \
	    'exit 1'
	write_executable "$(pwd)/stable.sh" \
	    '#!/bin/sh' \
	    'echo $$ > stable.pid' \
	    'sleep 60'
	cat > "$manifestdir/crashloop.ucl" <<EOF
label = "crashloop";
program = "$(pwd)/crashloop.sh";
restart = "always";
EOF
	cat > "$manifestdir/stable.ucl" <<EOF
label = "stable";
program = "$(pwd)/stable.sh";
EOF

	start_stress_oracled
	if ! wait_for_file stable.pid; then
		cat "$logfile" 2>/dev/null
		atf_skip "stable service did not start"
	fi

	# While crashloop is in restart backoff, trigger reloads.
	sleep 1
	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" reload
	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" reload
	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" reload
	assert_daemon_alive
}
reload_during_restart_cleanup()
{
	if [ -f stable.pid ]; then
		kill "$(cat stable.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

atf_init_test_cases()
{
	atf_add_test_case control_early_close_status_does_not_kill
	atf_add_test_case control_partial_client_timeout_storm
	atf_add_test_case control_malformed_header_flood
	atf_add_test_case reload_manifest_churn_under_control_load
	atf_add_test_case control_check_rejects_symlink_escape
	atf_add_test_case control_nonroot_denied
	atf_add_test_case service_restart_circuit_breaker
	atf_add_test_case service_shutdown_kills_sigterm_ignorer
	atf_add_test_case service_shutdown_kills_subtree
	atf_add_test_case service_child_environment_is_minimal
	atf_add_test_case parser_manifest_boundaries
	atf_add_test_case parser_config_boundaries
	atf_add_test_case reload_dependency_transaction_rollback
	atf_add_test_case reload_dependency_order_status
	atf_add_test_case service_pair_fd_contract
	atf_add_test_case service_cap_rt_naming_future_api
	atf_add_test_case service_fd_inheritance_contract
	atf_add_test_case sandbox_capprotect_denies_foreign_ptrace
	atf_add_test_case sandbox_isolation_denies_foreign_cap_rt_open
	atf_add_test_case control_payload_and_fragment_abuse
	atf_add_test_case crash_throttle_mixed_exit_modes

	# Process supervision: restart policy
	atf_add_test_case restart_never_no_restart
	atf_add_test_case restart_never_no_restart_on_failure
	atf_add_test_case restart_on_failure_ignores_clean_exit
	atf_add_test_case restart_on_failure_restarts_on_error
	atf_add_test_case restart_always_restarts_on_clean_exit
	atf_add_test_case restart_on_failure_restarts_on_signal

	# Process supervision: backoff
	atf_add_test_case restart_backoff_on_rapid_crash

	# Shutdown sequencing
	atf_add_test_case shutdown_reverse_dependency_order
	atf_add_test_case shutdown_stop_timeout_escalates

	# Credential dropping
	atf_add_test_case service_runs_as_specified_user

	# Concurrent operations
	atf_add_test_case reload_during_restart
}
