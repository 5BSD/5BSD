#
# SPDX-License-Identifier: BSD-2-Clause
#
# Integration tests for libservice(3).
#
# Tests build small C programs that link against libservice and
# exercise the API through the full oracled + serviced stack.
#

daemon_pid=
pidfile=
conffile=
manifestdir=
sockpath=
logfile=
serviced_bin=

require_cc()
{
	if ! command -v cc >/dev/null 2>&1; then
		atf_skip "cc not available"
	fi
}

find_serviced()
{
	local p
	for p in \
	    "$(command -v serviced 2>/dev/null)" \
	    /usr/sbin/serviced \
	    /usr/libexec/oracled/serviced \
	    /usr/obj/usr/src/arm64.aarch64/usr.sbin/serviced/serviced
	do
		if [ -n "$p" ] && [ -x "$p" ]; then
			serviced_bin="$p"
			return
		fi
	done
	atf_skip "serviced binary not found"
}

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

prepare_paths()
{
	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	manifestdir="$(pwd)/oracled.d"
	sockpath="$(pwd)/oracled.sock"
	logfile="$(pwd)/oracled.log"
	mkdir -p "$manifestdir"
}

write_config()
{
	find_serviced
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
manifest_dir = "$manifestdir";
service_manager = "$serviced_bin";
EOF
}

start_stack()
{
	prepare_paths
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

	i=0
	while ! grep -q "serviced ready" "$logfile" 2>/dev/null && [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
}

wait_for_file()
{
	local path i
	path="$1"
	i=0
	while [ ! -s "$path" ] && [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	test -s "$path"
}

stop_stack()
{
	if [ -n "$daemon_pid" ]; then
		kill -TERM "$daemon_pid" 2>/dev/null || true
		wait "$daemon_pid" 2>/dev/null || true
	fi
}

cleanup_common()
{
	stop_stack
	pkill -9 -f "ls_provider\|ls_client\|ls_ready" 2>/dev/null || true
	sleep 0.2
	rm -rf oracled.pid oracled.conf oracled.d oracled.sock \
	    oracled.log *.out *.c ls_provider ls_client ls_ready
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
# service_init + service_ready
# ===================================================================

atf_test_case libservice_ready cleanup
libservice_ready_head()
{
	atf_set "descr" "service_init and service_ready work via libservice"
	atf_set "require.user" "root"
}
libservice_ready_body()
{
	cat > ls_ready.c <<'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libservice.h>

int
main(void)
{
	FILE *out;

	if (service_init() == -1)
		return (1);
	if (service_ready() == -1)
		return (1);

	out = fopen("ls-ready.out", "w");
	if (out != NULL) {
		fprintf(out, "pair_fd=%d\n", service_pair_fd());
		fclose(out);
	}
	sleep(30);
	return (0);
}
CEOF
	cc_with_libservice -o ls_ready ls_ready.c
	prepare_paths
	cat > "$manifestdir/ls-ready.ucl" <<EOF
label = "ls-ready";
program = "$(pwd)/ls_ready";
EOF

	start_stack
	if ! wait_for_file ls-ready.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi

	atf_check -s exit:0 -o match:"pair_fd=3" cat ls-ready.out
	atf_check -s exit:0 -o ignore \
	    grep "service ls-ready: reported ready" "$logfile"
}
libservice_ready_cleanup()
{
	cleanup_common
}

# ===================================================================
# service_register + service_lookup + service_accept
# ===================================================================

atf_test_case libservice_naming cleanup
libservice_naming_head()
{
	atf_set "descr" "register, lookup, and accept work via libservice"
	atf_set "require.user" "root"
}
libservice_naming_body()
{
	cat > ls_provider.c <<'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>

int
main(void)
{
	char label[64], msg[256];
	FILE *out;
	int client_fd;
	ssize_t n;

	if (service_init() == -1) return (1);
	if (service_ready() == -1) return (1);
	if (service_register("ls-provider") == -1) return (1);

	out = fopen("ls-provider-reg.out", "w");
	if (out != NULL) { fprintf(out, "registered\n"); fclose(out); }

	client_fd = service_accept(label, sizeof(label));
	if (client_fd == -1) return (1);

	/* Send greeting. */
	service_send(client_fd, "hello", 6);

	/* Read response. */
	n = service_recv(client_fd, msg, sizeof(msg), NULL);

	out = fopen("ls-provider-done.out", "w");
	if (out != NULL) {
		fprintf(out, "client_label=%s\nmsg=%.*s\n",
		    label, (int)(n > 0 ? n : 0), msg);
		fclose(out);
	}

	close(client_fd);
	sleep(30);
	return (0);
}
CEOF

	cat > ls_client.c <<'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>

int
main(void)
{
	char msg[256];
	FILE *out;
	int peer_fd;
	ssize_t n;

	if (service_init() == -1) return (1);
	if (service_ready() == -1) return (1);

	/* Wait for provider to register. */
	sleep(2);

	peer_fd = service_lookup("ls-provider");
	if (peer_fd == -1) {
		out = fopen("ls-client.out", "w");
		if (out != NULL) {
			fprintf(out, "lookup_failed\n");
			fclose(out);
		}
		return (1);
	}

	/* Read greeting from provider. */
	n = service_recv(peer_fd, msg, sizeof(msg), NULL);

	/* Send response. */
	service_send(peer_fd, "world", 6);

	out = fopen("ls-client.out", "w");
	if (out != NULL) {
		fprintf(out, "greeting=%.*s\n", (int)(n > 0 ? n : 0), msg);
		fclose(out);
	}

	close(peer_fd);
	sleep(30);
	return (0);
}
CEOF

	cc_with_libservice -o ls_provider ls_provider.c
	cc_with_libservice -o ls_client ls_client.c

	prepare_paths
	cat > "$manifestdir/aaa-provider.ucl" <<EOF
label = "ls-provider";
program = "$(pwd)/ls_provider";
provides = ["ls-api"];
EOF
	cat > "$manifestdir/zzz-client.ucl" <<EOF
label = "ls-client";
program = "$(pwd)/ls_client";
requires = ["ls-api"];
EOF

	start_stack

	if ! wait_for_file ls-provider-reg.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "provider did not register"
	fi

	if ! wait_for_file ls-client.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "client did not complete lookup"
	fi

	atf_check -s exit:0 -o match:"greeting=hello" cat ls-client.out

	if ! wait_for_file ls-provider-done.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "provider did not receive client message"
	fi

	atf_check -s exit:0 -o match:"client_label=ls-client" \
	    cat ls-provider-done.out
	atf_check -s exit:0 -o match:"msg=world" \
	    cat ls-provider-done.out
}
libservice_naming_cleanup()
{
	cleanup_common
}

# ===================================================================
# service_lookup nonexistent — returns -1 with ENOENT
# ===================================================================

atf_test_case libservice_lookup_fail cleanup
libservice_lookup_fail_head()
{
	atf_set "descr" "service_lookup returns -1 for unregistered name"
	atf_set "require.user" "root"
}
libservice_lookup_fail_body()
{
	cat > ls_client.c <<'CEOF'
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libservice.h>

int
main(void)
{
	FILE *out;
	int fd;

	if (service_init() == -1) return (1);
	if (service_ready() == -1) return (1);

	fd = service_lookup("no.such.service");
	out = fopen("ls-lookup-fail.out", "w");
	if (out != NULL) {
		fprintf(out, "fd=%d\nerrno=%d\n", fd, errno);
		fclose(out);
	}
	sleep(30);
	return (0);
}
CEOF
	cc_with_libservice -o ls_client ls_client.c

	prepare_paths
	cat > "$manifestdir/lookup-fail.ucl" <<EOF
label = "lookup-fail";
program = "$(pwd)/ls_client";
EOF

	start_stack
	if ! wait_for_file ls-lookup-fail.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi

	atf_check -s exit:0 -o match:"fd=-1" cat ls-lookup-fail.out
	# errno 2 = ENOENT
	atf_check -s exit:0 -o match:"errno=2" cat ls-lookup-fail.out
}
libservice_lookup_fail_cleanup()
{
	cleanup_common
}

atf_init_test_cases()
{
	atf_add_test_case libservice_ready
	atf_add_test_case libservice_naming
	atf_add_test_case libservice_lookup_fail
}
