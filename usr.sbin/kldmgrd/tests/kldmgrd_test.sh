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
# Requires: root, mac_capability device available.
#

. "$(atf_get_srcdir)/capd_test_harness.sh"

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
	capd_find_serviced
	serviced_bin=$capd_serviced_bin
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

require_mac_capability()
{
	capd_require_device
}

prepare_paths()
{
	capd_paths_init
	WORK=$CAPD_WORK
	APPS_DIR=$CAPD_APPS_SYSTEM
	USER_APPS_DIR=$CAPD_APPS_USER
	CTL_SOCK=$CAPD_SERVICED_SOCKET

	pidfile=$CAPD_PIDFILE
	conffile=$CAPD_CONFIG
	manifestdir="${WORK}/serviced.d"
	sockpath=$CAPD_ORACLE_SOCKET
	logfile=$CAPD_LOG
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
	capd_start_stack
	daemon_pid=$("$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status |
	    sed -n 's/^running pid=//p')
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
	local result

	capd_paths_init
	capd_find_guardian
	capd_stop_stack
	result=$?
	daemon_pid=
	return "$result"
}

cleanup_common()
{
	stop_stack || return 1
	capd_cleanup_stack || return 1
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
# service.  It receives ORACLED_CHANNEL_FD, connects to kldmgrd via
# service_lookup(), sends a request, and writes results to a file.
#
# Usage: build_kldmgr_client
# The resulting binary is at ${WORK}/kldmgr_client.
# ---------------------------------------------------------------

build_kldmgr_client()
{
	cp "$(atf_get_srcdir)/capd_protocol_fixture" \
	    "${WORK}/kldmgr_client"
	chmod 755 "${WORK}/kldmgr_client"
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
arguments = ["kld", "${WORK}/cmd.in", "${WORK}/result.out"];
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
	capd_require_stack_kmods
}
kldmgrd_list_body()
{
	require_mac_capability
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle
	setup_allow_file "*"
	write_config
	start_stack

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
	capd_require_stack_kmods
}
kldmgrd_load_invalid_name_body()
{
	require_mac_capability
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle
	setup_allow_file "*"
	write_config
	start_stack

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
	capd_require_stack_kmods
}
kldmgrd_load_nonexistent_body()
{
	require_mac_capability
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle
	setup_allow_file "*"
	write_config
	start_stack

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
	capd_require_stack_kmods
}
kldmgrd_load_special_chars_body()
{
	require_mac_capability
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle
	setup_allow_file "*"
	write_config
	start_stack

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
	capd_require_stack_kmods
}
kldmgrd_permission_denied_body()
{
	require_mac_capability
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle "org.test.kldclient"
	# Allow file contains only a different label.
	setup_allow_file "org.5bsd.system.other"
	write_config
	start_stack

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
	capd_require_stack_kmods
}
kldmgrd_unknown_op_body()
{
	require_mac_capability
	build_kldmgr_client

	prepare_paths
	install_kldmgrd_bundle
	install_client_bundle
	setup_allow_file "*"
	write_config
	start_stack

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
