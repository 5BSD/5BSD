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
# Requires: root, mac_capability device, cc(1).
#

. "$(atf_get_srcdir)/capd_test_harness.sh"

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
	capd_find_serviced
	serviced_bin=$capd_serviced_bin
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

require_mac_capability()
{
	capd_require_device
}

prepare_paths()
{
	capd_paths_init
	WORK=$CAPD_WORK
	APPS_DIR=$CAPD_APPS_SYSTEM
	CTL_SOCK=$CAPD_SERVICED_SOCKET
	pidfile=$CAPD_PIDFILE
	conffile=$CAPD_CONFIG
	manifestdir="${WORK}/serviced.d"
	sockpath=$CAPD_ORACLE_SOCKET
	logfile=$CAPD_LOG
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
	cp "$(atf_get_srcdir)/capd_protocol_fixture" "${WORK}/${name}"
	chmod 755 "${WORK}/${name}"
}
# ---------------------------------------------------------------
# Create a serviced manifest for a test client binary.
#
# Usage: create_client_manifest <label> <binary> <env_key> <env_val>
# ---------------------------------------------------------------
create_client_manifest()
{
	local label="$1" binary="$2" env_key="$3" env_val="$4" operation

	case "${binary##*/}" in
	rebootd_status_client) operation=status ;;
	rebootd_perm_client) operation=reboot ;;
	rebootd_unknown_client) operation=unknown ;;
	rebootd_flags_client) operation=invalid-flags ;;
	*) atf_fail "unknown reboot fixture name: ${binary##*/}" ;;
	esac

	cat > "${manifestdir}/${label}.ucl" <<EOF
label = "${label}";
program = "${binary}";
arguments = ["reboot", "${operation}", "${env_val}"];
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
	capd_require_stack_kmods
}
rebootd_status_body()
{
	require_mac_capability
	build_rebootd_client "rebootd_status_client"

	start_stack
	create_rebootd_bundle

	create_client_manifest "test-reboot-status" \
	    "${WORK}/rebootd_status_client" \
	    "TEST_OUTPUT" "${WORK}/status.out"

	# Reload to pick up rebootd bundle + test client.
	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" reload

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
# Remaining protocol validation cases.
# ---------------------------------------------------------------
atf_test_case rebootd_permission_denied cleanup
rebootd_permission_denied_head()
{
	atf_set "descr" "REBOOT op returns PERM when client not in allow file"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
	capd_require_stack_kmods
}
rebootd_permission_denied_body()
{
	require_mac_capability
	build_rebootd_client "rebootd_perm_client"
	mkdir -p "${WORK}/rebootd_etc"
	printf "org.5bsd.not.our.service\n" > "${WORK}/rebootd_etc/rebootd.allow"
	export REBOOTD_ALLOW_FILE="${WORK}/rebootd_etc/rebootd.allow"
	start_stack
	create_rebootd_bundle
	create_client_manifest "test-reboot-perm" "${WORK}/rebootd_perm_client" \
	    "TEST_OUTPUT" "${WORK}/perm.out"
	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" reload
	if ! wait_for_file "${WORK}/perm.out" 20; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client did not produce output"
	fi
	atf_check -s exit:0 -o inline:"3\n" cat "${WORK}/perm.out"
}
rebootd_permission_denied_cleanup()
{
	cleanup_common
	rm -rf "${WORK}/rebootd_etc"
}

atf_test_case rebootd_unknown_op cleanup
rebootd_unknown_op_head()
{
	atf_set "descr" "Unknown op code returns REBOOT_STATUS_ERR"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
	capd_require_stack_kmods
}
rebootd_unknown_op_body()
{
	require_mac_capability
	build_rebootd_client "rebootd_unknown_client"
	start_stack
	create_rebootd_bundle
	create_client_manifest "test-reboot-unknown" \
	    "${WORK}/rebootd_unknown_client" "TEST_OUTPUT" "${WORK}/unknown.out"
	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" reload
	if ! wait_for_file "${WORK}/unknown.out" 20; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client did not produce output"
	fi
	atf_check -s exit:0 -o inline:"1\n" cat "${WORK}/unknown.out"
}
rebootd_unknown_op_cleanup()
{
	cleanup_common
}

atf_test_case rebootd_invalid_flags cleanup
rebootd_invalid_flags_head()
{
	atf_set "descr" "REBOOT op with invalid flags returns REBOOT_STATUS_ERR"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
	capd_require_stack_kmods
}
rebootd_invalid_flags_body()
{
	require_mac_capability
	build_rebootd_client "rebootd_flags_client"
	mkdir -p "${WORK}/rebootd_etc"
	printf "test-reboot-flags\n" > "${WORK}/rebootd_etc/rebootd.allow"
	export REBOOTD_ALLOW_FILE="${WORK}/rebootd_etc/rebootd.allow"
	start_stack
	create_rebootd_bundle
	create_client_manifest "test-reboot-flags" "${WORK}/rebootd_flags_client" \
	    "TEST_OUTPUT" "${WORK}/flags.out"
	atf_check -s exit:0 -o ignore oraclectl -s "$sockpath" reload
	if ! wait_for_file "${WORK}/flags.out" 20; then
		cat "$logfile" 2>/dev/null
		atf_fail "test client did not produce output"
	fi
	atf_check -s exit:0 -o inline:"1\n" cat "${WORK}/flags.out"
}
rebootd_invalid_flags_cleanup()
{
	cleanup_common
	rm -rf "${WORK}/rebootd_etc"
}

atf_init_test_cases()
{
	atf_add_test_case rebootd_status
	atf_add_test_case rebootd_permission_denied
	atf_add_test_case rebootd_unknown_op
	atf_add_test_case rebootd_invalid_flags
}
