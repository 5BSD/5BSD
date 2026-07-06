#
# SPDX-License-Identifier: BSD-2-Clause
#
# Integration tests for libservice(3).
#
# Tests build small C programs that link against libservice and exercise
# the API through the full oracled + serviced stack.
#
# serviced loads services only from .cap bundles under the
# SERVICED_BUNDLE_DIR_SYSTEM / SERVICED_BUNDLE_DIR_USER trees (the old flat
# serviced.d + label=/program= UCL manifest model was removed).  Each helper
# program below is cc-compiled and installed as the program of a single .cap
# bundle whose provides[0] is the runtime service label.
#

daemon_pid=
pidfile=
conffile=
sockpath=
logfile=
serviced_bin=
libservice_path=

# Fake bundle trees and control socket, rooted at the test work dir.
export WORK="$(pwd)"
APPS_DIR="${WORK}/Capabilities/System"
USER_APPS_DIR="${WORK}/Capabilities"
CTL_SOCK="${WORK}/serviced.sock"

require_cc()
{
	if ! command -v cc >/dev/null 2>&1; then
		atf_skip "cc not available"
	fi
}

require_mac_capability()
{
	if [ ! -c /dev/mac_capability ]; then
		atf_skip "mac_capability device not available"
	fi
}

find_serviced()
{
	local p _m _p
	# obj dir is ${MACHINE}.${MACHINE_ARCH} (uname -m / uname -p).
	_m=$(uname -m)
	_p=$(uname -p)
	for p in \
	    "$(command -v serviced 2>/dev/null)" \
	    /usr/libexec/serviced \
	    /usr/obj/usr/src/${_m}.${_p}/usr.sbin/serviced/serviced
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
	local p _m _p
	_m=$(uname -m)
	_p=$(uname -p)
	for p in \
	    /usr/lib/libservice.so \
	    /usr/obj/usr/src/${_m}.${_p}/lib/libservice/libservice.so.1
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

prepare_paths()
{
	pidfile="${WORK}/oracled.pid"
	conffile="${WORK}/oracled.conf"
	sockpath="${WORK}/oracled.sock"
	logfile="${WORK}/oracled.log"
	mkdir -p "${APPS_DIR}" "${USER_APPS_DIR}"
}

write_config()
{
	find_serviced
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
service_manager = "$serviced_bin";
serviced_control_socket = "${CTL_SOCK}";
EOF
	# serviced scans these bundle trees instead of the system defaults.
	export SERVICED_BUNDLE_DIR_SYSTEM="${APPS_DIR}"
	export SERVICED_BUNDLE_DIR_USER="${USER_APPS_DIR}"
}

# Install a pre-built binary as the program of a single .cap bundle.
# Usage: install_svc_bin <system|user> <label> <ucl_extra> <binary-path>
install_svc_bin()
{
	local scope="$1" label="$2" extra="$3" bin="$4"
	local base dir
	if [ "$scope" = system ]; then
		base="${APPS_DIR}"
	else
		base="${USER_APPS_DIR}"
	fi
	dir="${base}/${label}.cap"
	mkdir -p "${dir}/etc" "${dir}/bin"
	cp "$bin" "${dir}/bin/${label}"
	chmod 755 "${dir}/bin/${label}"
	cat > "${dir}/etc/${label}.ucl" <<-UCL
	bundle_id = "org.test.${label}";
	version = "1.0";
	author = "test";
	program = "${label}";
	provides = ["${label}"];
	${extra}
	UCL
	echo "${dir}"
}

start_stack()
{
	require_mac_capability
	prepare_paths
	write_config

	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	# Wait for oracled control socket.
	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -S "$sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "oracled did not create control socket"
	fi

	# Wait for serviced to report ready.
	i=0
	while ! grep -q "serviced ready" "$logfile" 2>/dev/null && \
	    [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
}

wait_for_file()
{
	local path max i
	path="$1"
	max=$(( ${2:-15} * 10 ))
	i=0
	while [ ! -s "$path" ] && [ "$i" -lt "$max" ]; do
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
	pkill -9 -f "ls_provider\|ls_client\|ls_ready\|ls_protect" \
	    2>/dev/null || true
	sleep 0.2
	rm -rf oracled.pid oracled.conf oracled.sock serviced.sock \
	    oracled.log Capabilities *.out *.c \
	    ls_provider ls_client ls_ready ls_protect
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
		fprintf(out, "channel_fd=%d\n", service_channel_fd());
		fclose(out);
	}
	sleep(30);
	return (0);
}
CEOF
	cc_with_libservice -o ls_ready ls_ready.c

	prepare_paths
	install_svc_bin system ls-ready '' "$(pwd)/ls_ready" >/dev/null

	start_stack
	if ! wait_for_file ls-ready.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	atf_check -s exit:0 -o match:"channel_fd=3" cat ls-ready.out
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
	# Runtime label == provides[0].  The provider provides (and registers)
	# "ls-provider"; the client requires it so it starts afterwards, and
	# the provider observes the connecting label "ls-client".
	install_svc_bin system ls-provider '' "$(pwd)/ls_provider" >/dev/null
	install_svc_bin system ls-client 'requires = ["ls-provider"];' \
	    "$(pwd)/ls_client" >/dev/null

	start_stack

	if ! wait_for_file ls-provider-reg.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "provider did not register"
	fi

	if ! wait_for_file ls-client.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "client did not complete lookup"
	fi

	atf_check -s exit:0 -o match:"greeting=hello" cat ls-client.out

	if ! wait_for_file ls-provider-done.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "provider did not receive client message"
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
	install_svc_bin system ls-lookupfail '' "$(pwd)/ls_client" >/dev/null

	start_stack
	if ! wait_for_file ls-lookup-fail.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	atf_check -s exit:0 -o match:"fd=-1" cat ls-lookup-fail.out
	# errno 2 = ENOENT
	atf_check -s exit:0 -o match:"errno=2" cat ls-lookup-fail.out
}
libservice_lookup_fail_cleanup()
{
	cleanup_common
}

# ===================================================================
# service_protect — makes process unptraceable
# ===================================================================

atf_test_case service_protect_test cleanup
service_protect_test_head()
{
	atf_set "descr" "service_protect makes the process unptraceable"
	atf_set "require.user" "root"
	atf_set "require.progs" "ktrace"
}
service_protect_test_body()
{
	cat > ls_protect.c <<'CEOF'
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

	/* Apply full protection. */
	if (service_protect(0x3F) == -1) {
		out = fopen("ls-protect.out", "w");
		if (out != NULL) {
			fprintf(out, "protect_failed\n");
			fclose(out);
		}
		sleep(30);
		return (1);
	}

	out = fopen("ls-protect.out", "w");
	if (out != NULL) {
		fprintf(out, "pid=%d\nprotected=yes\n", getpid());
		fclose(out);
	}
	sleep(30);
	return (0);
}
CEOF
	cc_with_libservice -o ls_protect ls_protect.c

	prepare_paths
	install_svc_bin system ls-protect '' "$(pwd)/ls_protect" >/dev/null

	start_stack
	if ! wait_for_file ls-protect.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	# Verify service_protect succeeded.
	atf_check -s exit:0 -o match:"protected=yes" cat ls-protect.out

	# Extract the pid.
	svc_pid=$(grep "^pid=" ls-protect.out | cut -d= -f2)
	if [ -z "$svc_pid" ]; then
		atf_fail "could not determine service pid"
	fi

	# ktrace -p should fail with EPERM on a protected process.
	atf_check -s not-exit:0 -e ignore \
	    ktrace -p "$svc_pid"
}
service_protect_test_cleanup()
{
	pkill -9 -f ls_protect 2>/dev/null || true
	cleanup_common
	rm -f ls_protect ls_protect.c
}

atf_init_test_cases()
{
	atf_add_test_case libservice_ready
	atf_add_test_case libservice_naming
	atf_add_test_case libservice_lookup_fail
	atf_add_test_case service_protect_test
}
