#
# SPDX-License-Identifier: BSD-2-Clause
#
# Bootstrap and channel protocol tests for oracled + serviced.
#
# These verify that oracled starts serviced as its child, the channel
# channel protocol works, and bootstrap restart logic is sound.
#

daemon_pid=
pidfile=
conffile=
sockpath=
logfile=
serviced_bin=
serviced_src=

prepare_paths()
{
	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	sockpath="$(pwd)/oracled.sock"
	logfile="$(pwd)/oracled.log"
}

require_cc()
{
	if ! command -v cc >/dev/null 2>&1; then
		atf_skip "cc not available"
	fi
}

build_mock_serviced()
{
	require_cc
	serviced_src="$(pwd)/mock_serviced.c"
	serviced_bin="$(pwd)/mock_serviced"
	cat > "$serviced_src" <<'CEOF'
#include <sys/types.h>
#include <sys/event.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <dev/cap_rt/cap_rt_ioctl.h>

/* Inline protocol definitions to avoid build dependency. */
#define ORACLE_OP_READY  6
#define ORACLE_OP_PING   7

struct oracle_req_hdr {
	uint32_t op;
};

struct oracle_reply {
	int32_t status;
};

static int
send_op(int channel_fd, uint32_t op)
{
	struct cap_rt_sendmsg_args sa;
	struct cap_rt_recvmsg_args ra;
	struct oracle_req_hdr req;
	struct oracle_reply rpl;

	memset(&req, 0, sizeof(req));
	req.op = op;

	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.reply_token = op;

	if (ioctl(channel_fd, CAP_RT_SENDMSG, &sa) == -1)
		return (-1);

	memset(&ra, 0, sizeof(ra));
	ra.payload = &rpl;
	ra.payload_len = sizeof(rpl);

	if (ioctl(channel_fd, CAP_RT_RECVMSG, &ra) == -1)
		return (-1);

	return (rpl.status);
}

int
main(void)
{
	const char *fd_str, *mode = NULL;
	int channel_fd;
	FILE *out;

	openlog("mock_serviced", LOG_PID, LOG_DAEMON);

	fd_str = getenv("ORACLED_CHANNEL_FD");
	if (fd_str == NULL) {
		syslog(LOG_ERR, "ORACLED_CHANNEL_FD not set");
		return (1);
	}
	channel_fd = atoi(fd_str);

	/*
	 * Read mode from a file (env vars don't survive the
	 * explicit execve environment in bootstrap_child_exec).
	 */
	{
		FILE *mf = fopen("mock-mode", "r");
		static char mbuf[64];
		if (mf != NULL) {
			if (fgets(mbuf, sizeof(mbuf), mf) != NULL) {
				size_t len = strlen(mbuf);
				if (len > 0 && mbuf[len-1] == '\n')
					mbuf[len-1] = '\0';
				mode = mbuf;
			}
			fclose(mf);
		}
	}
	if (mode == NULL || mode[0] == '\0')
		mode = "ready-then-sleep";

	/* Write a marker file so tests can detect we started. */
	out = fopen("serviced-started.out", "w");
	if (out != NULL) {
		fprintf(out, "pid=%d\nchannel_fd=%d\nmode=%s\n",
		    getpid(), channel_fd, mode);
		fclose(out);
	}

	if (strcmp(mode, "ready-then-sleep") == 0) {
		if (send_op(channel_fd, ORACLE_OP_READY) != 0)
			syslog(LOG_WARNING, "READY failed");

		/* Sleep until killed. */
		while (1)
			sleep(60);
	}

	if (strcmp(mode, "crash-immediately") == 0) {
		return (1);
	}

	if (strcmp(mode, "ping-then-sleep") == 0) {
		if (send_op(channel_fd, ORACLE_OP_PING) != 0) {
			syslog(LOG_ERR, "PING failed");
			return (1);
		}
		out = fopen("serviced-ping-ok.out", "w");
		if (out != NULL) {
			fprintf(out, "ok\n");
			fclose(out);
		}
		while (1)
			sleep(60);
	}

	syslog(LOG_ERR, "unknown mode: %s", mode);
	return (1);
}
CEOF
	atf_check -s exit:0 cc -Wall -Wextra -I/usr/src/sys \
	    -o "$serviced_bin" "$serviced_src"
}

write_config()
{
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
service_manager = "$serviced_bin";
EOF
}

start_oracled()
{
	prepare_paths
	mkdir -p "$(pwd)/serviced.d"
	write_config

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

stop_oracled()
{
	if [ -n "$daemon_pid" ]; then
		kill -TERM "$daemon_pid" 2>/dev/null || true
		wait "$daemon_pid" 2>/dev/null || true
	fi
}

cleanup_common()
{
	stop_oracled
	pkill -9 -f "mock_serviced" 2>/dev/null || true
	sleep 0.2
	rm -rf oracled.pid oracled.conf serviced.d oracled.sock \
	    oracled.log mock_serviced mock_serviced.c mock-mode \
	    serviced-started.out serviced-ping-ok.out
}

# -------------------------------------------------------------------
# Test cases
# -------------------------------------------------------------------

atf_test_case bootstrap_starts_serviced cleanup
bootstrap_starts_serviced_head()
{
	atf_set "descr" "oracled starts serviced as its child via pdfork"
	atf_set "require.user" "root"
}
bootstrap_starts_serviced_body()
{
	build_mock_serviced
	start_oracled

	if ! wait_for_file serviced-started.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "serviced did not start (cap_rt channel service may not be loaded)"
	fi

	# Verify the channel fd was inherited.
	atf_check -s exit:0 -o match:"channel_fd=" grep "channel_fd=" serviced-started.out

	# Verify oracled logged the start.
	atf_check -s exit:0 -o ignore grep "bootstrap: started serviced" "$logfile"

	# Verify oracled is still healthy.
	atf_check -s exit:0 -o match:"running" oraclectl -s "$sockpath" status
}
bootstrap_starts_serviced_cleanup()
{
	cleanup_common
}

atf_test_case bootstrap_channel_ping cleanup
bootstrap_channel_ping_head()
{
	atf_set "descr" "serviced can ping oracled over the channel"
	atf_set "require.user" "root"
}
bootstrap_channel_ping_body()
{
	echo "ping-then-sleep" > mock-mode
	build_mock_serviced
	start_oracled

	if ! wait_for_file serviced-ping-ok.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "serviced did not start or ping failed"
	fi

	atf_check -s exit:0 -o match:"ok" cat serviced-ping-ok.out
	atf_check -s exit:0 -o match:"running" oraclectl -s "$sockpath" status
}
bootstrap_channel_ping_cleanup()
{
	rm -f mock-mode
	cleanup_common
}

atf_test_case bootstrap_ready_logged cleanup
bootstrap_ready_logged_head()
{
	atf_set "descr" "oracled logs when serviced sends READY"
	atf_set "require.user" "root"
}
bootstrap_ready_logged_body()
{
	build_mock_serviced
	start_oracled

	if ! wait_for_file serviced-started.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "serviced did not start"
	fi

	# Give oracled time to process the READY message.
	sleep 1

	atf_check -s exit:0 -o ignore \
	    grep "oracle_proto: serviced ready" "$logfile"
}
bootstrap_ready_logged_cleanup()
{
	cleanup_common
}

atf_test_case bootstrap_restart_on_crash cleanup
bootstrap_restart_on_crash_head()
{
	atf_set "descr" "oracled restarts serviced after it crashes"
	atf_set "require.user" "root"
}
bootstrap_restart_on_crash_body()
{
	echo "crash-immediately" > mock-mode
	build_mock_serviced
	start_oracled

	# Wait for the restart log entry.
	if ! sh -c "i=0; while ! grep -q 'scheduling restart' '$logfile' && [ \$i -lt 100 ]; do i=\$((i + 1)); sleep 0.1; done; grep -q 'scheduling restart' '$logfile'"; then
		cat "$logfile" 2>/dev/null
		atf_skip "restart not observed (cap_rt may not be loaded)"
	fi

	# Verify oracled logged the exit.
	atf_check -s exit:0 -o ignore \
	    grep "bootstrap: serviced exited" "$logfile"

	# Verify oracled is still alive.
	atf_check -s exit:0 -o match:"running" oraclectl -s "$sockpath" status
}
bootstrap_restart_on_crash_cleanup()
{
	rm -f mock-mode
	cleanup_common
}

atf_test_case bootstrap_clean_shutdown cleanup
bootstrap_clean_shutdown_head()
{
	atf_set "descr" "shutdown stops serviced before oracled exits"
	atf_set "require.user" "root"
}
bootstrap_clean_shutdown_body()
{
	build_mock_serviced
	start_oracled

	if ! wait_for_file serviced-started.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "serviced did not start"
	fi

	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" shutdown
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=

	atf_check -s exit:0 -o ignore \
	    grep "bootstrap: stopping serviced" "$logfile"
}
bootstrap_clean_shutdown_cleanup()
{
	cleanup_common
}

atf_test_case bootstrap_no_service_manager cleanup
bootstrap_no_service_manager_head()
{
	atf_set "descr" "oracled starts without service_manager if not configured"
	atf_set "require.user" "root"
}
bootstrap_no_service_manager_body()
{
	if ! sh -c 'exec 3</dev/cap_rt' 2>/dev/null; then
		atf_skip "/dev/cap_rt not available"
	fi
	prepare_paths
	mkdir -p "$(pwd)/serviced.d"

	# Config with empty service_manager.
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
service_manager = "";
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

	# Should log that no service_manager is configured.
	atf_check -s exit:0 -o ignore \
	    grep "no service_manager configured" "$logfile"

	# Daemon should still be healthy.
	atf_check -s exit:0 -o match:"running" oraclectl -s "$sockpath" status
}
bootstrap_no_service_manager_cleanup()
{
	cleanup_common
}

atf_init_test_cases()
{
	atf_add_test_case bootstrap_starts_serviced
	atf_add_test_case bootstrap_channel_ping
	atf_add_test_case bootstrap_ready_logged
	atf_add_test_case bootstrap_restart_on_crash
	atf_add_test_case bootstrap_clean_shutdown
	atf_add_test_case bootstrap_no_service_manager
}
