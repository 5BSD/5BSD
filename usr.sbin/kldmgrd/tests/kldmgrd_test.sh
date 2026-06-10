#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# ATF tests for kldmgrd — kernel module loading manager.
#
# kldmgrd is a .cap-bundle service that communicates via libservice and
# uses libcapability (cap_daemon_run).  The protocol is defined in
# kldmgrd_proto.h.  Because kldmgrd registers through serviced, these
# tests start the full oracled+serviced stack with kldmgrd installed
# as a system bundle, then launch a test client service that exercises
# the protocol.
#
# Requires: root, cap_rt device available.
#

# ---------------------------------------------------------------
# Helpers — inlined because kldmgrd lives outside the serviced tree.
# ---------------------------------------------------------------

daemon_pid=
pidfile=
conffile=
manifestdir=
sockpath=
logfile=
serviced_bin=
kldmgrd_bin=
WORK=
APPS_DIR=
USER_APPS_DIR=
CTL_SOCK=
saved_allow_file=

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

find_kldmgrd()
{
	local p
	for p in \
	    "$(command -v kldmgrd 2>/dev/null)" \
	    /usr/sbin/kldmgrd \
	    /Capabilities/System/Kldmgr.cap/bin/kldmgrd \
	    /usr/obj/usr/src/arm64.aarch64/usr.sbin/kldmgrd/kldmgrd
	do
		if [ -n "$p" ] && [ -x "$p" ]; then
			kldmgrd_bin="$p"
			return
		fi
	done
	atf_skip "kldmgrd binary not found"
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
	WORK="$(pwd)"
	APPS_DIR="${WORK}/Capabilities/System"
	USER_APPS_DIR="${WORK}/Capabilities"
	CTL_SOCK="${WORK}/serviced.sock"

	pidfile="${WORK}/oracled.pid"
	conffile="${WORK}/oracled.conf"
	manifestdir="${WORK}/serviced.d"
	sockpath="${WORK}/oracled.sock"
	logfile="${WORK}/oracled.log"
	mkdir -p "$manifestdir"
	mkdir -p "${APPS_DIR}" "${USER_APPS_DIR}"
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
serviced_control_socket = "${CTL_SOCK}";
EOF
	export SERVICED_BUNDLE_DIR_SYSTEM="${APPS_DIR}"
	export SERVICED_BUNDLE_DIR_USER="${USER_APPS_DIR}"
}

install_kldmgrd_bundle()
{
	find_kldmgrd
	local dir="${APPS_DIR}/Kldmgr.cap"
	mkdir -p "${dir}/etc" "${dir}/bin"
	cp "${kldmgrd_bin}" "${dir}/bin/kldmgrd"
	chmod 755 "${dir}/bin/kldmgrd"
	cat > "${dir}/etc/kldmgrd.ucl" <<'UCL'
bundle_id = "org.5bsd.system.kldmgr";
version = "1.0";
author = "5BSD";
program = "kldmgrd";
provides = ["org.5bsd.system.kldmgr"];
on_demand = false;
restart = "on-failure";
capabilities {
    system = ["kldload", "kldunload", "kldstat"];
}
UCL
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

wait_for_log()
{
	local pattern i
	pattern="$1"
	i=0
	while ! grep -q "$pattern" "$logfile" 2>/dev/null && [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	grep -q "$pattern" "$logfile" 2>/dev/null
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
	# Restore /etc/kldmgrd.allow if we saved a backup.
	if [ -n "$saved_allow_file" ] && [ -f "${saved_allow_file}" ]; then
		cp "${saved_allow_file}" /etc/kldmgrd.allow
	elif [ -n "$saved_allow_file" ]; then
		rm -f /etc/kldmgrd.allow
	fi
	rm -rf "${WORK:-.}/oracled.pid" "${WORK:-.}/oracled.conf" \
	    "${WORK:-.}/serviced.d" "${WORK:-.}/oracled.sock" \
	    "${WORK:-.}/serviced.sock" "${WORK:-.}/oracled.log" \
	    "${WORK:-.}/Capabilities" \
	    "${WORK:-.}/kldmgr_client" "${WORK:-.}/kldmgr_client.c" \
	    "${WORK:-.}"/*.out "${WORK:-.}"/*.pid \
	    "${WORK:-.}/allow_backup"
}

write_executable()
{
	local path
	path="$1"
	cat > "$path"
	chmod +x "$path"
}

# ---------------------------------------------------------------
# Build the test client service.
#
# This creates a C program that is launched BY serviced as a managed
# service.  It receives ORACLED_PAIR_FD, connects to kldmgrd via
# service_lookup(), sends a request, and writes results to a file.
#
# Usage: build_kldmgr_client
# The resulting binary is at ${WORK}/kldmgr_client.
# ---------------------------------------------------------------

build_kldmgr_client()
{
	require_cc
	cat > "${WORK}/kldmgr_client.c" <<'CEOF'
/*
 * Test client for kldmgrd.
 *
 * Launched as a serviced-managed service.  Reads command from a file
 * ("cmd.in"), executes it against kldmgrd, writes result to "result.out".
 *
 * cmd.in format: <op> [name] [raw_opcode]
 *   op = "list" | "load" | "unload" | "raw"
 *   name = module name (for load/unload) or ignored
 *   raw_opcode = numeric op (for "raw")
 */

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#define	KLDMGR_OP_LOAD		1
#define	KLDMGR_OP_UNLOAD	2
#define	KLDMGR_OP_LIST		3

#define	KLDMGR_NAME_MAX	128
#define	KLDMGR_LIST_MAX	64

struct kldmgr_req {
	uint32_t	op;
	uint32_t	_pad;
	char		name[KLDMGR_NAME_MAX];
} __packed;

struct kldmgr_reply {
	int32_t		status;
	int32_t		id;
} __packed;

struct kldmgr_list_entry {
	int32_t		id;
	char		name[KLDMGR_NAME_MAX];
} __packed;

struct kldmgr_list_reply {
	int32_t		status;
	uint32_t	count;
	/* entries follow */
} __packed;

int
main(void)
{
	FILE *fin, *fout;
	char op[32], name[KLDMGR_NAME_MAX];
	int raw_op, fd;
	struct kldmgr_req req;
	ssize_t n;

	if (service_init() == -1) {
		fprintf(stderr, "service_init failed\n");
		return (1);
	}

	/* Signal readiness to serviced. */
	service_ready();

	/*
	 * Wait for cmd.in to appear.  The test harness creates this
	 * after the stack is up and kldmgrd is registered.
	 */
	for (int i = 0; i < 100; i++) {
		fin = fopen("cmd.in", "r");
		if (fin != NULL)
			break;
		usleep(100000);
	}
	if (fin == NULL) {
		fout = fopen("result.out", "w");
		if (fout) {
			fprintf(fout, "error=cmd.in not found\n");
			fclose(fout);
		}
		return (1);
	}

	memset(op, 0, sizeof(op));
	memset(name, 0, sizeof(name));
	raw_op = 0;
	fscanf(fin, "%31s %127s %d", op, name, &raw_op);
	fclose(fin);

	/* Connect to kldmgrd. */
	fd = service_lookup("org.5bsd.system.kldmgr");
	if (fd < 0) {
		fout = fopen("result.out", "w");
		if (fout) {
			fprintf(fout, "error=service_lookup failed: %s\n",
			    strerror(errno));
			fclose(fout);
		}
		return (1);
	}

	memset(&req, 0, sizeof(req));

	if (strcmp(op, "list") == 0) {
		req.op = KLDMGR_OP_LIST;
	} else if (strcmp(op, "load") == 0) {
		req.op = KLDMGR_OP_LOAD;
		strlcpy(req.name, name, sizeof(req.name));
	} else if (strcmp(op, "unload") == 0) {
		req.op = KLDMGR_OP_UNLOAD;
		strlcpy(req.name, name, sizeof(req.name));
	} else if (strcmp(op, "raw") == 0) {
		req.op = (uint32_t)raw_op;
		strlcpy(req.name, name, sizeof(req.name));
	} else {
		fout = fopen("result.out", "w");
		if (fout) {
			fprintf(fout, "error=unknown op: %s\n", op);
			fclose(fout);
		}
		close(fd);
		return (1);
	}

	if (service_send(fd, &req, sizeof(req)) != 0) {
		fout = fopen("result.out", "w");
		if (fout) {
			fprintf(fout, "error=service_send failed: %s\n",
			    strerror(errno));
			fclose(fout);
		}
		close(fd);
		return (1);
	}

	fout = fopen("result.out", "w");
	if (fout == NULL) {
		close(fd);
		return (1);
	}

	if (strcmp(op, "list") == 0) {
		/*
		 * LIST reply: fixed header + variable entries.
		 * Read the fixed header first, then entries.
		 */
		char buf[sizeof(struct kldmgr_list_reply) +
		    KLDMGR_LIST_MAX * sizeof(struct kldmgr_list_entry)];
		struct kldmgr_list_reply *lr;
		struct kldmgr_list_entry *ent;
		uint32_t i;

		n = service_recv(fd, buf, sizeof(buf), NULL);
		if (n < (ssize_t)sizeof(struct kldmgr_list_reply)) {
			fprintf(fout, "error=short list reply (%zd)\n", n);
			fclose(fout);
			close(fd);
			return (1);
		}

		lr = (struct kldmgr_list_reply *)buf;
		fprintf(fout, "status=%d\n", lr->status);
		fprintf(fout, "count=%u\n", lr->count);

		ent = (struct kldmgr_list_entry *)(buf +
		    sizeof(struct kldmgr_list_reply));
		for (i = 0; i < lr->count &&
		    (ssize_t)(sizeof(*lr) + (i + 1) * sizeof(*ent)) <= n;
		    i++) {
			fprintf(fout, "module.%u.id=%d\n", i, ent[i].id);
			fprintf(fout, "module.%u.name=%s\n", i, ent[i].name);
		}
	} else {
		struct kldmgr_reply reply;

		n = service_recv(fd, &reply, sizeof(reply), NULL);
		if (n < (ssize_t)sizeof(reply)) {
			fprintf(fout, "error=short reply (%zd)\n", n);
			fclose(fout);
			close(fd);
			return (1);
		}

		fprintf(fout, "status=%d\n", reply.status);
		fprintf(fout, "id=%d\n", reply.id);
	}

	fclose(fout);
	close(fd);

	/* Keep running so serviced doesn't restart us. */
	for (;;)
		sleep(60);

	return (0);
}
CEOF
	atf_check -s exit:0 -e ignore cc -Wall \
	    -I/usr/src/sys -I/usr/src/lib/libservice \
	    -I/usr/src/usr.sbin/kldmgrd \
	    -o "${WORK}/kldmgr_client" "${WORK}/kldmgr_client.c" -lservice
}

# Install the test client as a serviced-managed service.
# Args: $1 = label (default "org.test.kldclient")
install_client_bundle()
{
	local label="${1:-org.test.kldclient}"
	local dir="${USER_APPS_DIR}/KldClient.cap"
	mkdir -p "${dir}/etc" "${dir}/bin"
	cp "${WORK}/kldmgr_client" "${dir}/bin/kldmgr_client"
	chmod 755 "${dir}/bin/kldmgr_client"
	cat > "${dir}/etc/kldmgr_client.ucl" <<UCL
bundle_id = "${label}";
version = "1.0";
author = "test";
program = "kldmgr_client";
provides = ["${label}"];
UCL
}

# Set up the allow file to permit a label (or wildcard).
# Saves the original /etc/kldmgrd.allow if it exists.
setup_allow_file()
{
	local content="$1"
	saved_allow_file="${WORK}/allow_backup"
	if [ -f /etc/kldmgrd.allow ]; then
		cp /etc/kldmgrd.allow "${saved_allow_file}"
	else
		# Mark that no original file existed.
		touch "${saved_allow_file}.absent"
		saved_allow_file="${saved_allow_file}.absent"
	fi
	echo "$content" > /etc/kldmgrd.allow
}

# Write a command for the test client and wait for results.
# Args: $1 $2 $3 = op, name, raw_opcode (as for cmd.in)
run_client_op()
{
	rm -f "${WORK}/result.out"
	echo "$@" > "${WORK}/cmd.in"
	wait_for_file "${WORK}/result.out" 20
}

# ===================================================================
# kldmgrd_list
#
# Start stack with kldmgrd bundle.  Client sends LIST, verifies
# response contains count > 0 and at least one known module name
# (the "kernel" entry is always present).
# ===================================================================

atf_test_case kldmgrd_list cleanup
kldmgrd_list_head()
{
	atf_set "descr" "LIST op returns loaded kernel modules"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
kldmgrd_list_body()
{
	require_cap_rt
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle
	setup_allow_file "*"
	write_config
	start_stack

	# Wait for kldmgrd to be registered.
	if ! wait_for_log "kldmgrd.*registered\|org.5bsd.system.kldmgr.*ready"; then
		# Fall back: just wait for the client bundle to start.
		sleep 3
	fi

	run_client_op list

	if [ ! -s "${WORK}/result.out" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client produced no output"
	fi

	# Verify status=0 (OK)
	atf_check -s exit:0 -o ignore grep "^status=0" "${WORK}/result.out"

	# Verify count > 0
	count=$(grep "^count=" "${WORK}/result.out" | head -1 | cut -d= -f2)
	if [ -z "$count" ] || [ "$count" -le 0 ]; then
		cat "${WORK}/result.out"
		atf_fail "expected count > 0, got '${count}'"
	fi

	# The kernel is always loaded as module id 1.
	atf_check -s exit:0 -o ignore grep "name=kernel" "${WORK}/result.out"
}
kldmgrd_list_cleanup()
{
	cleanup_common
}

# ===================================================================
# kldmgrd_load_invalid_name
#
# Send LOAD with a path-traversal name ("../etc/passwd").
# kldmgrd's module_name_valid rejects anything with "/" or "..".
# ===================================================================

atf_test_case kldmgrd_load_invalid_name cleanup
kldmgrd_load_invalid_name_head()
{
	atf_set "descr" "LOAD with path traversal name returns ERR"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
kldmgrd_load_invalid_name_body()
{
	require_cap_rt
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle
	setup_allow_file "*"
	write_config
	start_stack

	if ! wait_for_log "kldmgrd.*registered\|org.5bsd.system.kldmgr.*ready"; then
		sleep 3
	fi

	run_client_op load "../etc/passwd"

	if [ ! -s "${WORK}/result.out" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client produced no output"
	fi

	# status=1 is KLDMGR_STATUS_ERR
	atf_check -s exit:0 -o ignore grep "^status=1" "${WORK}/result.out"
}
kldmgrd_load_invalid_name_cleanup()
{
	cleanup_common
}

# ===================================================================
# kldmgrd_load_nonexistent
#
# Send LOAD for a module that does not exist.  kldload(2) returns
# ENOENT, which kldmgrd maps to KLDMGR_STATUS_NOTFOUND.
# ===================================================================

atf_test_case kldmgrd_load_nonexistent cleanup
kldmgrd_load_nonexistent_head()
{
	atf_set "descr" "LOAD nonexistent module returns NOTFOUND"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
kldmgrd_load_nonexistent_body()
{
	require_cap_rt
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle
	setup_allow_file "*"
	write_config
	start_stack

	if ! wait_for_log "kldmgrd.*registered\|org.5bsd.system.kldmgr.*ready"; then
		sleep 3
	fi

	run_client_op load "nonexistent_test_module_xyz"

	if [ ! -s "${WORK}/result.out" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client produced no output"
	fi

	# status=2 is KLDMGR_STATUS_NOTFOUND
	atf_check -s exit:0 -o ignore grep "^status=2" "${WORK}/result.out"
}
kldmgrd_load_nonexistent_cleanup()
{
	cleanup_common
}

# ===================================================================
# kldmgrd_load_special_chars
#
# Send LOAD with shell-injection characters.  module_name_valid
# rejects anything outside [a-zA-Z0-9_\-.].
# ===================================================================

atf_test_case kldmgrd_load_special_chars cleanup
kldmgrd_load_special_chars_head()
{
	atf_set "descr" "LOAD with shell metacharacters returns ERR"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
kldmgrd_load_special_chars_body()
{
	require_cap_rt
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle
	setup_allow_file "*"
	write_config
	start_stack

	if ! wait_for_log "kldmgrd.*registered\|org.5bsd.system.kldmgr.*ready"; then
		sleep 3
	fi

	# The semicolon and spaces make this an invalid module name.
	run_client_op load ";rm"

	if [ ! -s "${WORK}/result.out" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client produced no output"
	fi

	# status=1 is KLDMGR_STATUS_ERR
	atf_check -s exit:0 -o ignore grep "^status=1" "${WORK}/result.out"
}
kldmgrd_load_special_chars_cleanup()
{
	cleanup_common
}

# ===================================================================
# kldmgrd_permission_denied
#
# kldmgrd opens /etc/kldmgrd.allow to check the client's label.
# This test creates an allow file that does NOT contain the test
# client's label, so kldmgrd returns KLDMGR_STATUS_PERM.
# ===================================================================

atf_test_case kldmgrd_permission_denied cleanup
kldmgrd_permission_denied_head()
{
	atf_set "descr" "Client not in allow file gets PERM"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
kldmgrd_permission_denied_body()
{
	require_cap_rt
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle "org.test.kldclient"
	# Allow file contains only a different label.
	setup_allow_file "org.5bsd.system.other"
	write_config
	start_stack

	if ! wait_for_log "kldmgrd.*registered\|org.5bsd.system.kldmgr.*ready"; then
		sleep 3
	fi

	run_client_op list

	if [ ! -s "${WORK}/result.out" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client produced no output"
	fi

	# status=3 is KLDMGR_STATUS_PERM
	atf_check -s exit:0 -o ignore grep "^status=3" "${WORK}/result.out"
}
kldmgrd_permission_denied_cleanup()
{
	cleanup_common
}

# ===================================================================
# kldmgrd_unknown_op
#
# Send a request with op=99.  kldmgrd's switch/default returns
# KLDMGR_STATUS_ERR.
# ===================================================================

atf_test_case kldmgrd_unknown_op cleanup
kldmgrd_unknown_op_head()
{
	atf_set "descr" "Unknown op code returns ERR"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
kldmgrd_unknown_op_body()
{
	require_cap_rt
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle
	setup_allow_file "*"
	write_config
	start_stack

	if ! wait_for_log "kldmgrd.*registered\|org.5bsd.system.kldmgr.*ready"; then
		sleep 3
	fi

	run_client_op raw ignored 99

	if [ ! -s "${WORK}/result.out" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client produced no output"
	fi

	# status=1 is KLDMGR_STATUS_ERR
	atf_check -s exit:0 -o ignore grep "^status=1" "${WORK}/result.out"
}
kldmgrd_unknown_op_cleanup()
{
	cleanup_common
}

# ===================================================================

atf_init_test_cases()
{
	atf_add_test_case kldmgrd_list
	atf_add_test_case kldmgrd_load_invalid_name
	atf_add_test_case kldmgrd_load_nonexistent
	atf_add_test_case kldmgrd_load_special_chars
	atf_add_test_case kldmgrd_permission_denied
	atf_add_test_case kldmgrd_unknown_op
}
