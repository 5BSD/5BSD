#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Integration tests for rebootd — reboot and shutdown manager.
#
# Tests the rebootd wire protocol (rebootd_proto.h) via inline C
# test client services launched by the oracled + serviced stack.
#
# IMPORTANT: No test case exercises actual reboot or shutdown.
#
# Requires: root, cap_rt device, cc(1).
#

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

daemon_pid=
pidfile=
conffile=
manifestdir=
sockpath=
logfile=
serviced_bin=
rebootd_bin=

WORK="$(pwd)"
APPS_DIR="${WORK}/Capabilities/System"
CTL_SOCK="${WORK}/serviced.sock"

find_serviced()
{
	local p
	for p in \
	    "$(command -v serviced 2>/dev/null)" \
	    /usr/libexec/serviced \
	    /usr/obj/usr/src/arm64.aarch64/usr.sbin/serviced/serviced
	do
		if [ -n "$p" ] && [ -x "$p" ]; then
			serviced_bin="$p"
			return
		fi
	done
	atf_skip "serviced binary not found"
}

find_rebootd()
{
	local p
	for p in \
	    "$(command -v rebootd 2>/dev/null)" \
	    /Capabilities/System/Reboot.cap/bin/rebootd \
	    /usr/obj/usr/src/arm64.aarch64/usr.sbin/rebootd/rebootd
	do
		if [ -n "$p" ] && [ -x "$p" ]; then
			rebootd_bin="$p"
			return
		fi
	done
	atf_skip "rebootd binary not found"
}

require_cap_rt()
{
	if [ ! -c /dev/cap_rt ]; then
		atf_skip "cap_rt device not available"
	fi
}

require_cc()
{
	if ! command -v cc >/dev/null 2>&1; then
		atf_skip "cc not available"
	fi
}

prepare_paths()
{
	pidfile="${WORK}/oracled.pid"
	conffile="${WORK}/oracled.conf"
	manifestdir="${WORK}/serviced.d"
	sockpath="${WORK}/oracled.sock"
	logfile="${WORK}/oracled.log"
	mkdir -p "$manifestdir"
	mkdir -p "${APPS_DIR}"
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
	export SERVICED_BUNDLE_DIR_SYSTEM="${APPS_DIR}"
	export SERVICED_BUNDLE_DIR_USER="${WORK}/Capabilities"
}

start_stack()
{
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

	# Wait for serviced to be ready.
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
	pkill -9 -f "serviced.d" 2>/dev/null || true
	sleep 0.2
	rm -rf "${WORK}/oracled.pid" "${WORK}/oracled.conf" \
	    "${WORK}/serviced.d" "${WORK}/oracled.sock" \
	    "${WORK}/oracled.log" "${WORK}/serviced.sock" \
	    "${WORK}/Capabilities" \
	    "${WORK}"/*.out "${WORK}"/*.c "${WORK}"/*.pid \
	    "${WORK}/rebootd_status_client" \
	    "${WORK}/rebootd_perm_client" \
	    "${WORK}/rebootd_unknown_client" \
	    "${WORK}/rebootd_flags_client"
}

# ---------------------------------------------------------------
# Create the rebootd bundle in the test-local Capabilities tree.
# ---------------------------------------------------------------
create_rebootd_bundle()
{
	find_rebootd
	local dir="${APPS_DIR}/Reboot.cap"

	mkdir -p "${dir}/bin"
	mkdir -p "${dir}/etc"

	# Symlink to the real rebootd binary.
	ln -sf "${rebootd_bin}" "${dir}/bin/rebootd"

	cat > "${dir}/etc/rebootd.ucl" <<UCL
bundle_id = "org.5bsd.system.reboot";
program = "rebootd";
provides = ["org.5bsd.system.reboot"];
capabilities {
    system = ["reboot"];
}
UCL
}

# ---------------------------------------------------------------
# Build an inline C test client that connects to rebootd.
#
# Usage: build_rebootd_client <binary_name> <c_body>
#
# The C body is the contents of main() after service_init()
# and service_lookup() have succeeded.  Variables available:
#   peer_fd  — fd connected to rebootd
#   outfile  — path to write result
# ---------------------------------------------------------------
build_rebootd_client()
{
	local name="$1"
	local body="$2"

	cat > "${WORK}/${name}.c" <<CEOF
#include <sys/types.h>
#include <sys/reboot.h>

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

/* Inline protocol definitions from rebootd_proto.h */
#define	REBOOT_OP_REBOOT	1
#define	REBOOT_OP_SHUTDOWN	2
#define	REBOOT_OP_STATUS	3

#define	REBOOT_STATUS_OK	0
#define	REBOOT_STATUS_ERR	1
#define	REBOOT_STATUS_PERM	3
#define	REBOOT_STATUS_PENDING	4

struct reboot_req {
	uint32_t	op;
	uint32_t	flags;
} __packed;

struct reboot_reply {
	int32_t		status;
	uint32_t	_pad;
} __packed;

int
main(void)
{
	const char *outpath;
	int peer_fd;
	FILE *outfile;

	outpath = getenv("TEST_OUTPUT");
	if (outpath == NULL)
		errx(1, "TEST_OUTPUT not set");

	if (service_init() == -1)
		errx(1, "service_init");

	if (service_ready() == -1)
		errx(1, "service_ready");

	peer_fd = service_lookup("org.5bsd.system.reboot");
	if (peer_fd == -1)
		errx(1, "service_lookup");

	outfile = fopen(outpath, "w");
	if (outfile == NULL)
		err(1, "fopen %s", outpath);

	{
		${body}
	}

	fclose(outfile);

	/* Keep process alive so serviced does not restart us. */
	for (;;)
		sleep(60);

	return (0);
}
CEOF

	cc -o "${WORK}/${name}" "${WORK}/${name}.c" \
	    -I/usr/src/lib/libservice \
	    -L/usr/obj/usr/src/arm64.aarch64/lib/libservice \
	    -lservice 2>&1 || \
	    atf_fail "failed to compile ${name}"
}

# ---------------------------------------------------------------
# Create a serviced manifest for a test client binary.
#
# Usage: create_client_manifest <label> <binary> <env_key> <env_val>
# ---------------------------------------------------------------
create_client_manifest()
{
	local label="$1" binary="$2" env_key="$3" env_val="$4"

	cat > "${manifestdir}/${label}.ucl" <<EOF
label = "${label}";
program = "${binary}";
environment {
    ${env_key} = "${env_val}";
}
EOF
}

# ---------------------------------------------------------------
# Test: rebootd_status — STATUS op returns OK
# ---------------------------------------------------------------
atf_test_case rebootd_status cleanup
rebootd_status_head()
{
	atf_set "descr" "STATUS op returns REBOOT_STATUS_OK"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
rebootd_status_body()
{
	require_cap_rt
	require_cc

	build_rebootd_client "rebootd_status_client" '
		struct reboot_req req;
		struct reboot_reply reply;

		memset(&req, 0, sizeof(req));
		req.op = REBOOT_OP_STATUS;
		req.flags = 0;

		if (service_send(peer_fd, &req, sizeof(req)) == -1)
			err(1, "send");

		if (service_recv(peer_fd, &reply, sizeof(reply), NULL) !=
		    (ssize_t)sizeof(reply))
			err(1, "recv");

		fprintf(outfile, "%d\n", reply.status);
	'

	start_stack
	create_rebootd_bundle

	create_client_manifest "test-reboot-status" \
	    "${WORK}/rebootd_status_client" \
	    "TEST_OUTPUT" "${WORK}/status.out"

	# Reload to pick up rebootd bundle + test client.
	kill -HUP "$daemon_pid"

	if ! wait_for_file "${WORK}/status.out" 20; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client did not produce output"
	fi

	# REBOOT_STATUS_OK == 0
	atf_check -s exit:0 -o inline:"0\n" cat "${WORK}/status.out"
}
rebootd_status_cleanup()
{
	cleanup_common
}

# ---------------------------------------------------------------
# Test: rebootd_permission_denied — REBOOT op denied by allow file
# ---------------------------------------------------------------
atf_test_case rebootd_permission_denied cleanup
rebootd_permission_denied_head()
{
	atf_set "descr" "REBOOT op returns PERM when client not in allow file"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
rebootd_permission_denied_body()
{
	require_cap_rt
	require_cc

	build_rebootd_client "rebootd_perm_client" '
		struct reboot_req req;
		struct reboot_reply reply;

		memset(&req, 0, sizeof(req));
		req.op = REBOOT_OP_REBOOT;
		req.flags = 0;

		if (service_send(peer_fd, &req, sizeof(req)) == -1)
			err(1, "send");

		if (service_recv(peer_fd, &reply, sizeof(reply), NULL) !=
		    (ssize_t)sizeof(reply))
			err(1, "recv");

		fprintf(outfile, "%d\n", reply.status);
	'

	start_stack
	create_rebootd_bundle

	# Write an allow file that only permits a label that is NOT ours.
	mkdir -p "${WORK}/rebootd_etc"
	printf "org.5bsd.not.our.service\n" > "${WORK}/rebootd_etc/rebootd.allow"
	export REBOOTD_ALLOW_FILE="${WORK}/rebootd_etc/rebootd.allow"

	create_client_manifest "test-reboot-perm" \
	    "${WORK}/rebootd_perm_client" \
	    "TEST_OUTPUT" "${WORK}/perm.out"

	kill -HUP "$daemon_pid"

	if ! wait_for_file "${WORK}/perm.out" 20; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client did not produce output"
	fi

	# REBOOT_STATUS_PERM == 3
	atf_check -s exit:0 -o inline:"3\n" cat "${WORK}/perm.out"
}
rebootd_permission_denied_cleanup()
{
	cleanup_common
	rm -rf "${WORK}/rebootd_etc"
}

# ---------------------------------------------------------------
# Test: rebootd_unknown_op — unknown op returns ERR
# ---------------------------------------------------------------
atf_test_case rebootd_unknown_op cleanup
rebootd_unknown_op_head()
{
	atf_set "descr" "Unknown op code returns REBOOT_STATUS_ERR"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
rebootd_unknown_op_body()
{
	require_cap_rt
	require_cc

	build_rebootd_client "rebootd_unknown_client" '
		struct reboot_req req;
		struct reboot_reply reply;

		memset(&req, 0, sizeof(req));
		req.op = 99;
		req.flags = 0;

		if (service_send(peer_fd, &req, sizeof(req)) == -1)
			err(1, "send");

		if (service_recv(peer_fd, &reply, sizeof(reply), NULL) !=
		    (ssize_t)sizeof(reply))
			err(1, "recv");

		fprintf(outfile, "%d\n", reply.status);
	'

	start_stack
	create_rebootd_bundle

	create_client_manifest "test-reboot-unknown" \
	    "${WORK}/rebootd_unknown_client" \
	    "TEST_OUTPUT" "${WORK}/unknown.out"

	kill -HUP "$daemon_pid"

	if ! wait_for_file "${WORK}/unknown.out" 20; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client did not produce output"
	fi

	# REBOOT_STATUS_ERR == 1
	atf_check -s exit:0 -o inline:"1\n" cat "${WORK}/unknown.out"
}
rebootd_unknown_op_cleanup()
{
	cleanup_common
}

# ---------------------------------------------------------------
# Test: rebootd_invalid_flags — REBOOT op with bad flags returns ERR
# ---------------------------------------------------------------
atf_test_case rebootd_invalid_flags cleanup
rebootd_invalid_flags_head()
{
	atf_set "descr" "REBOOT op with invalid flags returns REBOOT_STATUS_ERR"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
rebootd_invalid_flags_body()
{
	require_cap_rt
	require_cc

	build_rebootd_client "rebootd_flags_client" '
		struct reboot_req req;
		struct reboot_reply reply;

		memset(&req, 0, sizeof(req));
		req.op = REBOOT_OP_REBOOT;
		req.flags = 0xFFFF;	/* Includes bits outside REBOOT_ALLOWED_FLAGS */

		if (service_send(peer_fd, &req, sizeof(req)) == -1)
			err(1, "send");

		if (service_recv(peer_fd, &reply, sizeof(reply), NULL) !=
		    (ssize_t)sizeof(reply))
			err(1, "recv");

		fprintf(outfile, "%d\n", reply.status);
	'

	start_stack
	create_rebootd_bundle

	# Client must be in the allow file since flag check is AFTER
	# the permission check.
	mkdir -p "${WORK}/rebootd_etc"
	printf "test-reboot-flags\n" > "${WORK}/rebootd_etc/rebootd.allow"
	export REBOOTD_ALLOW_FILE="${WORK}/rebootd_etc/rebootd.allow"

	create_client_manifest "test-reboot-flags" \
	    "${WORK}/rebootd_flags_client" \
	    "TEST_OUTPUT" "${WORK}/flags.out"

	kill -HUP "$daemon_pid"

	if ! wait_for_file "${WORK}/flags.out" 20; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client did not produce output"
	fi

	# REBOOT_STATUS_ERR == 1
	atf_check -s exit:0 -o inline:"1\n" cat "${WORK}/flags.out"
}
rebootd_invalid_flags_cleanup()
{
	cleanup_common
	rm -rf "${WORK}/rebootd_etc"
}

# ---------------------------------------------------------------
atf_init_test_cases()
{
	atf_add_test_case rebootd_status
	atf_add_test_case rebootd_permission_denied
	atf_add_test_case rebootd_unknown_op
	atf_add_test_case rebootd_invalid_flags
}
