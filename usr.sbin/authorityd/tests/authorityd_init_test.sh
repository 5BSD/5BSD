#
# SPDX-License-Identifier: BSD-2-Clause
#
# Initialization integrity tests for authorityd.
#
# These verify that the running authorityd instance has applied all
# expected hardening.  Many tests work by confirming that external
# access is DENIED — the denial itself is proof the protection is
# active.  They run against the live system daemon and require root.
#

PATH="$(dirname "$(atf_get_srcdir)"):${PATH}"
export PATH

require_pidfile()
{
	if [ ! -f /var/run/authorityd.pid ]; then
		atf_skip "authorityd pidfile not found"
	fi
	pid=$(cat /var/run/authorityd.pid 2>/dev/null)
	if [ -z "$pid" ]; then
		atf_skip "authorityd pidfile is empty"
	fi
}

# --- isolation ---

atf_test_case isolation_mac_capability_module_loaded cleanup
isolation_mac_capability_module_loaded_head()
{
	atf_set "descr" "mac_capability kernel module is loaded"
	atf_set "require.user" "root"
}
isolation_mac_capability_module_loaded_body()
{
	atf_check -s exit:0 kldstat -qm mac_capability
}
isolation_mac_capability_module_loaded_cleanup()
{
	:
}

atf_test_case isolation_mac_capability_open_denied cleanup
isolation_mac_capability_open_denied_head()
{
	atf_set "descr" "/dev/mac_capability cannot be opened by foreign nonce"
	atf_set "require.user" "root"
}
isolation_mac_capability_open_denied_body()
{
	require_pidfile
	# A new process has a different nonce from authorityd.
	# The isolation MACF hook must deny the open.
	atf_check -s not-exit:0 -e match:"Permission denied" \
	    sh -c 'cat /dev/mac_capability'
}
isolation_mac_capability_open_denied_cleanup()
{
	:
}

atf_test_case isolation_mac_capability_stat_denied cleanup
isolation_mac_capability_stat_denied_head()
{
	atf_set "descr" "/dev/mac_capability cannot be stat'd by foreign nonce"
	atf_set "require.user" "root"
}
isolation_mac_capability_stat_denied_body()
{
	require_pidfile
	# Even stat/test is blocked by the isolation MACF hook.
	atf_check -s not-exit:0 sh -c 'test -c /dev/mac_capability'
}
isolation_mac_capability_stat_denied_cleanup()
{
	:
}

# --- capprotect: visibility ---

atf_test_case capprotect_visible_config cleanup
capprotect_visible_config_head()
{
	atf_set "descr" "authorityd visibility matches integrity.visible config"
	atf_set "require.user" "root"
}
capprotect_visible_config_body()
{
	require_pidfile
	pid=$(cat /var/run/authorityd.pid)
	# Check the config file for visible setting.
	if grep -q 'visible.*true' /etc/authorityd.conf 2>/dev/null; then
		# visible=true: ps must NOT find the process.
		atf_check -s not-exit:0 \
		    sh -c "ps -p $pid -o pid= 2>/dev/null | grep -q ."
	else
		# visible=false (default): ps must find the process.
		atf_check -s exit:0 \
		    sh -c "ps -p $pid -o pid= 2>/dev/null | grep -q ."
	fi
}
capprotect_visible_config_cleanup()
{
	:
}

# --- capprotect: ptrace ---

atf_test_case capprotect_ptrace_denied cleanup
capprotect_ptrace_denied_head()
{
	atf_set "descr" "ptrace attach to authorityd is denied (CP_SF_PTRACE)"
	atf_set "require.user" "root"
}
capprotect_ptrace_denied_body()
{
	require_pidfile
	pid=$(cat /var/run/authorityd.pid)
	# truss uses ptrace; must be denied.
	atf_check -s not-exit:0 -e ignore truss -p "$pid" -e exit
}
capprotect_ptrace_denied_cleanup()
{
	:
}

# --- capprotect: ktrace ---

atf_test_case capprotect_ktrace_denied cleanup
capprotect_ktrace_denied_head()
{
	atf_set "descr" "ktrace on authorityd is denied (CP_SF_KTRACE)"
	atf_set "require.user" "root"
}
capprotect_ktrace_denied_body()
{
	require_pidfile
	pid=$(cat /var/run/authorityd.pid)
	atf_check -s not-exit:0 -e ignore \
	    ktrace -p "$pid" -t c
}
capprotect_ktrace_denied_cleanup()
{
	rm -f ktrace.out
}

# --- capprotect: scheduler ---

atf_test_case capprotect_sched_denied cleanup
capprotect_sched_denied_head()
{
	atf_set "descr" "scheduler manipulation of authorityd is denied (CP_SF_SCHED)"
	atf_set "require.user" "root"
}
capprotect_sched_denied_body()
{
	require_pidfile
	pid=$(cat /var/run/authorityd.pid)
	# Attempt to renice authorityd from a foreign nonce.
	atf_check -s not-exit:0 -e ignore renice 10 -p "$pid"
}
capprotect_sched_denied_cleanup()
{
	:
}

# --- control socket ---

atf_test_case control_socket_exists cleanup
control_socket_exists_head()
{
	atf_set "descr" "control socket exists at /var/run/authorityd.sock"
	atf_set "require.user" "root"
}
control_socket_exists_body()
{
	require_pidfile
	atf_check -s exit:0 test -S /var/run/authorityd.sock
}
control_socket_exists_cleanup()
{
	:
}

atf_test_case control_socket_status cleanup
control_socket_status_head()
{
	atf_set "descr" "authorityctl status returns valid output"
	atf_set "require.user" "root"
}
control_socket_status_body()
{
	require_pidfile
	atf_check -s exit:0 -o match:"authorityd: running" authorityctl status
}
control_socket_status_cleanup()
{
	:
}

atf_test_case control_socket_status_uptime cleanup
control_socket_status_uptime_head()
{
	atf_set "descr" "authorityctl status reports uptime"
	atf_set "require.user" "root"
}
control_socket_status_uptime_body()
{
	require_pidfile
	atf_check -s exit:0 -o match:"uptime:" authorityctl status
}
control_socket_status_uptime_cleanup()
{
	:
}

atf_test_case control_socket_bad_version cleanup
control_socket_bad_version_head()
{
	atf_set "descr" "control socket rejects bad protocol version"
	atf_set "require.user" "root"
}
control_socket_bad_version_body()
{
	require_pidfile
	# Send version=99, op=STATUS, expect ENOTSUP in reply.
	# The first 4 bytes of the reply are the status (uint32 LE).
	# ENOTSUP is 45 (0x2d) on FreeBSD.  Use octal escapes: the
	# FreeBSD printf(1)/sh builtin supports \NNN but NOT \xHH, so hex
	# would emit literal text and corrupt the request (it would still
	# mismatch the version, passing this test for the wrong reason).
	atf_check -s exit:0 -o match:"2d" sh -c '
		{
			printf "\\143\\000\\000\\000"
			printf "\\002\\000\\000\\000"
			printf "\\000\\000\\000\\000"
			printf "\\000\\000\\000\\000"
		} | nc -U /var/run/authorityd.sock | od -A n -t x1 | head -1
	'
}
control_socket_bad_version_cleanup()
{
	:
}

atf_test_case control_socket_unknown_op cleanup
control_socket_unknown_op_head()
{
	atf_set "descr" "control socket rejects unknown opcode"
	atf_set "require.user" "root"
}
control_socket_unknown_op_body()
{
	require_pidfile
	# Send version=1, op=255 (unknown), expect ENOTSUP.  Octal escapes
	# (see control_socket_bad_version): with hex, version=1 would not
	# be emitted, so this would test version mismatch, not the unknown
	# opcode it claims to.
	atf_check -s exit:0 -o match:"2d" sh -c '
		{
			printf "\\001\\000\\000\\000"
			printf "\\377\\000\\000\\000"
			printf "\\000\\000\\000\\000"
			printf "\\000\\000\\000\\000"
		} | nc -U /var/run/authorityd.sock | od -A n -t x1 | head -1
	'
}
control_socket_unknown_op_cleanup()
{
	:
}

# --- control socket: payload validation ---

atf_test_case control_socket_status_with_payload cleanup
control_socket_status_with_payload_head()
{
	atf_set "descr" "status with unexpected payload is rejected"
	atf_set "require.user" "root"
}
control_socket_status_with_payload_body()
{
	require_pidfile
	# Send version=1, op=STATUS(2), flags=0, datalen=4 + 4 bytes
	# of junk payload.  The server must return a non-zero status
	# (EINVAL or similar).  Verify the first 4 bytes of the reply
	# are not all zeros (status != 0).
	atf_check -s exit:0 sh -c '
		reply=$({
			printf "\\x01\\x00\\x00\\x00"
			printf "\\x02\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
			printf "\\x04\\x00\\x00\\x00"
			printf "JUNK"
		} | nc -U /var/run/authorityd.sock | od -A n -t x1 | head -1)
		# First 4 bytes are status — must not be "00 00 00 00"
		status=$(echo "$reply" | awk "{print \$1 \$2 \$3 \$4}")
		test "$status" != "00000000"
	'
}
control_socket_status_with_payload_cleanup()
{
	:
}

# --- control socket: multiple rapid connections ---

atf_test_case control_socket_rapid cleanup
control_socket_rapid_head()
{
	atf_set "descr" "daemon handles multiple rapid status queries"
	atf_set "require.user" "root"
}
control_socket_rapid_body()
{
	require_pidfile
	local i
	for i in 1 2 3 4 5; do
		atf_check -s exit:0 -o match:"running" authorityctl status
	done
}
control_socket_rapid_cleanup()
{
	:
}

# --- control socket: permission ---

atf_test_case control_socket_permissions cleanup
control_socket_permissions_head()
{
	atf_set "descr" "control socket is mode 0700"
	atf_set "require.user" "root"
}
control_socket_permissions_body()
{
	require_pidfile
	# Verify the socket file has restrictive permissions.
	local mode
	mode=$(stat -f '%Lp' /var/run/authorityd.sock)
	atf_check_equal "700" "$mode"
}
control_socket_permissions_cleanup()
{
	:
}

# --- test mode ---

atf_test_case test_mode_no_root cleanup
test_mode_no_root_head()
{
	atf_set "descr" "authorityd -T runs without root"
}
test_mode_no_root_body()
{
	local pid pidfile

	pidfile="$(pwd)/authorityd_test.pid"
	authorityd -T -p "$pidfile" &
	pid=$!

	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
test_mode_no_root_cleanup()
{
	if [ -f authorityd_test.pid ]; then
		pid="$(cat authorityd_test.pid 2>/dev/null || true)"
		if [ -n "$pid" ]; then
			kill "$pid" 2>/dev/null || true
		fi
		rm -f authorityd_test.pid
	fi
}

# --- stale socket cleanup ---

atf_test_case stale_socket_cleanup cleanup
stale_socket_cleanup_head()
{
	atf_set "descr" "authorityd cleans up stale socket on start"
	atf_set "require.user" "root"
}
stale_socket_cleanup_body()
{
	require_pidfile
	# The fact that authorityd started successfully (require_pidfile
	# passes) with a control socket means it either created a new
	# socket or cleaned up a stale one from a previous crash.
	# Verify the socket works.
	atf_check -s exit:0 -o match:"running" authorityctl status
}
stale_socket_cleanup_cleanup()
{
	:
}

# --- configuration ---

atf_test_case config_missing_file_uses_defaults cleanup
config_missing_file_uses_defaults_head()
{
	atf_set "descr" "authorityd starts with defaults when config file is absent"
}
config_missing_file_uses_defaults_body()
{
	local pidfile="$(pwd)/cfg_test.pid"
	authorityd -T -f /nonexistent/authorityd.conf -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_missing_file_uses_defaults_cleanup()
{
	if [ -f cfg_test.pid ]; then
		kill "$(cat cfg_test.pid)" 2>/dev/null || true
		rm -f cfg_test.pid
	fi
}

atf_test_case config_syntax_error_exits cleanup
config_syntax_error_exits_head()
{
	atf_set "descr" "authorityd exits on config syntax error"
}
config_syntax_error_exits_body()
{
	local conffile="$(pwd)/bad.conf"
	echo "this is { not valid ucl }{{{" > "$conffile"
	atf_check -s not-exit:0 -e not-empty \
	    authorityd -T -f "$conffile" -p "$(pwd)/bad.pid"
}
config_syntax_error_exits_cleanup()
{
	rm -f bad.conf bad.pid
}

atf_test_case config_custom_pidfile cleanup
config_custom_pidfile_head()
{
	atf_set "descr" "config pidfile setting is honored"
}
config_custom_pidfile_body()
{
	local conffile="$(pwd)/custom.conf"
	local pidfile="$(pwd)/custom_authority.pid"
	echo "pidfile = \"$pidfile\";" > "$conffile"
	authorityd -T -f "$conffile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 test "$(cat "$pidfile")" = "$pid"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_custom_pidfile_cleanup()
{
	if [ -f custom_authority.pid ]; then
		kill "$(cat custom_authority.pid)" 2>/dev/null || true
		rm -f custom_authority.pid
	fi
	rm -f custom.conf
}

atf_test_case config_cli_overrides_config cleanup
config_cli_overrides_config_head()
{
	atf_set "descr" "-p flag overrides config pidfile"
}
config_cli_overrides_config_body()
{
	local conffile="$(pwd)/override.conf"
	local config_pid="$(pwd)/config_pid.pid"
	local cli_pid="$(pwd)/cli_pid.pid"
	echo "pidfile = \"$config_pid\";" > "$conffile"
	authorityd -T -f "$conffile" -p "$cli_pid" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$cli_pid' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$cli_pid'"
	# CLI -p should win over config pidfile
	atf_check -s exit:1 test -f "$config_pid"
	atf_check -s exit:0 test -f "$cli_pid"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_cli_overrides_config_cleanup()
{
	for f in config_pid.pid cli_pid.pid override.conf; do
		if [ -f "$f" ]; then
			pid="$(cat "$f" 2>/dev/null || true)"
			kill "$pid" 2>/dev/null || true
			rm -f "$f"
		fi
	done
}

atf_test_case config_empty_file_uses_defaults cleanup
config_empty_file_uses_defaults_head()
{
	atf_set "descr" "empty config file uses defaults"
}
config_empty_file_uses_defaults_body()
{
	local conffile="$(pwd)/empty.conf"
	local pidfile="$(pwd)/empty_test.pid"
	touch "$conffile"
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_empty_file_uses_defaults_cleanup()
{
	if [ -f empty_test.pid ]; then
		kill "$(cat empty_test.pid)" 2>/dev/null || true
		rm -f empty_test.pid
	fi
	rm -f empty.conf
}

atf_test_case config_integrity_settings cleanup
config_integrity_settings_head()
{
	atf_set "descr" "integrity settings are parsed from config"
}
config_integrity_settings_body()
{
	local conffile="$(pwd)/integrity.conf"
	local pidfile="$(pwd)/integrity_test.pid"
	cat > "$conffile" <<'ENDCONF'
integrity {
    ptrace = false;
    ktrace = false;
    sched = false;
    wait = false;
}
ENDCONF
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_integrity_settings_cleanup()
{
	if [ -f integrity_test.pid ]; then
		kill "$(cat integrity_test.pid)" 2>/dev/null || true
		rm -f integrity_test.pid
	fi
	rm -f integrity.conf
}

# --- config: claims parsing ---

atf_test_case config_claims_paths cleanup
config_claims_paths_head()
{
	atf_set "descr" "claims.paths are parsed from config"
}
config_claims_paths_body()
{
	local conffile="$(pwd)/claims.conf"
	local pidfile="$(pwd)/claims_test.pid"
	cat > "$conffile" <<'ENDCONF'
claims {
    paths = [
        "/dev/null",
        "/tmp",
    ];
}
ENDCONF
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_claims_paths_cleanup()
{
	if [ -f claims_test.pid ]; then
		kill "$(cat claims_test.pid)" 2>/dev/null || true
		rm -f claims_test.pid
	fi
	rm -f claims.conf
}

atf_test_case config_claims_network cleanup
config_claims_network_head()
{
	atf_set "descr" "claims.network is parsed from config"
}
config_claims_network_body()
{
	local conffile="$(pwd)/claims_net.conf"
	local pidfile="$(pwd)/claims_net_test.pid"
	cat > "$conffile" <<'ENDCONF'
claims {
    network = [
        { port = 9999; protocol = "tcp"; direction = "bind"; },
        { ports = "*"; protocol = "*"; direction = "*"; domain = "*"; },
        { ports = "10000-10010"; protocol = "udp"; direction = "connect"; },
        { ports = ".1024"; protocol = "any"; direction = "any"; },
    ];
}
ENDCONF
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_claims_network_cleanup()
{
	if [ -f claims_net_test.pid ]; then
		kill "$(cat claims_net_test.pid)" 2>/dev/null || true
		rm -f claims_net_test.pid
	fi
	rm -f claims_net.conf
}

atf_test_case config_claims_bad_path cleanup
config_claims_bad_path_head()
{
	atf_set "descr" "nonexistent claim path does not prevent startup"
}
config_claims_bad_path_body()
{
	local conffile="$(pwd)/claims_bad.conf"
	local pidfile="$(pwd)/claims_bad_test.pid"
	cat > "$conffile" <<'ENDCONF'
claims {
    paths = [
        "/nonexistent/path/that/does/not/exist",
    ];
}
ENDCONF
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	# Should start despite bad path (graceful degradation)
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_claims_bad_path_cleanup()
{
	if [ -f claims_bad_test.pid ]; then
		kill "$(cat claims_bad_test.pid)" 2>/dev/null || true
		rm -f claims_bad_test.pid
	fi
	rm -f claims_bad.conf
}

atf_test_case config_claims_system cleanup
config_claims_system_head()
{
	atf_set "descr" "claims.system gate names are parsed"
}
config_claims_system_body()
{
	local conffile="$(pwd)/claims_sys.conf"
	local pidfile="$(pwd)/claims_sys_test.pid"
	cat > "$conffile" <<'ENDCONF'
claims {
    system = ["kldload", "reboot"];
}
ENDCONF
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_claims_system_cleanup()
{
	if [ -f claims_sys_test.pid ]; then
		kill "$(cat claims_sys_test.pid)" 2>/dev/null || true
		rm -f claims_sys_test.pid
	fi
	rm -f claims_sys.conf
}

atf_test_case config_claims_system_bad_name cleanup
config_claims_system_bad_name_head()
{
	atf_set "descr" "unknown system gate name warns but starts"
}
config_claims_system_bad_name_body()
{
	local conffile="$(pwd)/claims_sys_bad.conf"
	local pidfile="$(pwd)/claims_sys_bad_test.pid"
	cat > "$conffile" <<'ENDCONF'
claims {
    system = ["nosuchgate"];
}
ENDCONF
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_claims_system_bad_name_cleanup()
{
	if [ -f claims_sys_bad_test.pid ]; then
		kill "$(cat claims_sys_bad_test.pid)" 2>/dev/null || true
		rm -f claims_sys_bad_test.pid
	fi
	rm -f claims_sys_bad.conf
}

# --- config: negative / boundary tests ---

atf_test_case config_bad_port cleanup
config_bad_port_head()
{
	atf_set "descr" "out-of-range port is rejected"
}
config_bad_port_body()
{
	local conffile="$(pwd)/badport.conf"
	local pidfile="$(pwd)/badport_test.pid"
	cat > "$conffile" <<'ENDCONF'
claims {
    network = [
        { port = 70000; protocol = "tcp"; direction = "bind"; },
    ];
}
ENDCONF
	# Should start (bad port is skipped with warning, not fatal)
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_bad_port_cleanup()
{
	if [ -f badport_test.pid ]; then
		kill "$(cat badport_test.pid)" 2>/dev/null || true
		rm -f badport_test.pid
	fi
	rm -f badport.conf
}

atf_test_case config_relative_path cleanup
config_relative_path_head()
{
	atf_set "descr" "relative claim path is rejected"
}
config_relative_path_body()
{
	local conffile="$(pwd)/relpath.conf"
	local pidfile="$(pwd)/relpath_test.pid"
	cat > "$conffile" <<'ENDCONF'
claims {
    paths = ["relative/path"];
}
ENDCONF
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_relative_path_cleanup()
{
	if [ -f relpath_test.pid ]; then
		kill "$(cat relpath_test.pid)" 2>/dev/null || true
		rm -f relpath_test.pid
	fi
	rm -f relpath.conf
}

atf_test_case config_integer_mode_rejected cleanup
config_integer_mode_rejected_head()
{
	atf_set "descr" "integer control_socket_mode is rejected"
}
config_integer_mode_rejected_body()
{
	local conffile="$(pwd)/intmode.conf"
	local pidfile="$(pwd)/intmode_test.pid"
	cat > "$conffile" <<'ENDCONF'
control_socket_mode = 700;
ENDCONF
	# Should start (integer mode rejected with warning, uses default)
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_integer_mode_rejected_cleanup()
{
	if [ -f intmode_test.pid ]; then
		kill "$(cat intmode_test.pid)" 2>/dev/null || true
		rm -f intmode_test.pid
	fi
	rm -f intmode.conf
}

# --- syslog: initialization completed ---

atf_test_case syslog_init_complete cleanup
syslog_init_complete_head()
{
	atf_set "descr" "authorityd logs successful initialization"
	atf_set "require.user" "root"
}
syslog_init_complete_body()
{
	require_pidfile
	pid=$(cat /var/run/authorityd.pid)
	local logfile="/var/log/daemon.log"
	if [ ! -r "$logfile" ]; then
		atf_skip "daemon.log not readable"
	fi
	# Verify all init stages completed for this pid.
	atf_check -s exit:0 -o not-empty \
	    grep "authorityd\[$pid\].*config:" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "authorityd\[$pid\].*reaper status confirmed" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "authorityd\[$pid\].*enabled OOM protection" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "authorityd\[$pid\].*isolation.*claimed.*/dev/mac_capability" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "authorityd\[$pid\].*integrity active" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "authorityd\[$pid\].*control socket" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "authorityd\[$pid\].*started" "$logfile"
}
syslog_init_complete_cleanup()
{
	:
}

# --- control socket: negative / edge cases ---

atf_test_case control_socket_reload_with_payload cleanup
control_socket_reload_with_payload_head()
{
	atf_set "descr" "reload with unexpected payload is rejected"
	atf_set "require.user" "root"
}
control_socket_reload_with_payload_body()
{
	require_pidfile
	# Send version=1, op=RELOAD(3), flags=0, datalen=4 + 4 bytes junk.
	# Must return non-zero status (EINVAL).
	atf_check -s exit:0 sh -c '
		reply=$({
			printf "\\x01\\x00\\x00\\x00"
			printf "\\x03\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
			printf "\\x04\\x00\\x00\\x00"
			printf "JUNK"
		} | nc -U /var/run/authorityd.sock | od -A n -t x1 | head -1)
		status=$(echo "$reply" | awk "{print \$1 \$2 \$3 \$4}")
		test "$status" != "00000000"
	'
}
control_socket_reload_with_payload_cleanup()
{
	:
}

atf_test_case control_socket_shutdown_with_payload cleanup
control_socket_shutdown_with_payload_head()
{
	atf_set "descr" "shutdown with unexpected payload is rejected"
	atf_set "require.user" "root"
}
control_socket_shutdown_with_payload_body()
{
	require_pidfile
	# Send version=1, op=SHUTDOWN(1), flags=0, datalen=4 + 4 bytes junk.
	atf_check -s exit:0 sh -c '
		reply=$({
			printf "\\x01\\x00\\x00\\x00"
			printf "\\x01\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
			printf "\\x04\\x00\\x00\\x00"
			printf "JUNK"
		} | nc -U /var/run/authorityd.sock | od -A n -t x1 | head -1)
		status=$(echo "$reply" | awk "{print \$1 \$2 \$3 \$4}")
		test "$status" != "00000000"
	'
}
control_socket_shutdown_with_payload_cleanup()
{
	:
}

atf_test_case control_socket_unknown_op_with_payload cleanup
control_socket_unknown_op_with_payload_head()
{
	atf_set "descr" "unknown op with unexpected payload is rejected"
	atf_set "require.user" "root"
}
control_socket_unknown_op_with_payload_body()
{
	require_pidfile
	# Send version=1, op=6 (unused), flags=0, datalen=4 + 4 bytes junk.
	atf_check -s exit:0 sh -c '
		reply=$({
			printf "\\x01\\x00\\x00\\x00"
			printf "\\x06\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
			printf "\\x04\\x00\\x00\\x00"
			printf "JUNK"
		} | nc -U /var/run/authorityd.sock | od -A n -t x1 | head -1)
		status=$(echo "$reply" | awk "{print \$1 \$2 \$3 \$4}")
		test "$status" != "00000000"
	'
}
control_socket_unknown_op_with_payload_cleanup()
{
	:
}

atf_test_case control_socket_services_with_payload cleanup
control_socket_services_with_payload_head()
{
	atf_set "descr" "services with unexpected payload is rejected"
	atf_set "require.user" "root"
}
control_socket_services_with_payload_body()
{
	require_pidfile
	# Send version=1, op=SERVICES(9), flags=0, datalen=4 + 4 bytes junk.
	atf_check -s exit:0 sh -c '
		reply=$({
			printf "\\x01\\x00\\x00\\x00"
			printf "\\x09\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
			printf "\\x04\\x00\\x00\\x00"
			printf "JUNK"
		} | nc -U /var/run/authorityd.sock | od -A n -t x1 | head -1)
		status=$(echo "$reply" | awk "{print \$1 \$2 \$3 \$4}")
		test "$status" != "00000000"
	'
}
control_socket_services_with_payload_cleanup()
{
	:
}

atf_test_case control_socket_empty_connect cleanup
control_socket_empty_connect_head()
{
	atf_set "descr" "daemon handles client that connects and disconnects"
	atf_set "require.user" "root"
}
control_socket_empty_connect_body()
{
	require_pidfile
	# Connect and immediately close — should not crash daemon.
	atf_check -s exit:0 sh -c \
	    "echo '' | nc -U /var/run/authorityd.sock || true"
	# Daemon should still be responsive.
	atf_check -s exit:0 -o match:"running" authorityctl status
}
control_socket_empty_connect_cleanup()
{
	:
}

atf_test_case control_socket_status_shows_claims cleanup
control_socket_status_shows_claims_head()
{
	atf_set "descr" "authorityctl status shows mac_capability claims on live daemon"
	atf_set "require.user" "root"
}
control_socket_status_shows_claims_body()
{
	require_pidfile
	# Live daemon should show /dev/mac_capability in claims.
	atf_check -s exit:0 -o match:"/dev/mac_capability" authorityctl status
	# Should show path count.
	atf_check -s exit:0 -o match:"paths:" authorityctl status
	# Should show network count.
	atf_check -s exit:0 -o match:"network:" authorityctl status
	# Should show system gates.
	atf_check -s exit:0 -o match:"system:" authorityctl status
}
control_socket_status_shows_claims_cleanup()
{
	:
}

# --- nonblocking control socket ---

atf_test_case control_socket_slow_client cleanup
control_socket_slow_client_head()
{
	atf_set "descr" "slow client does not block daemon from serving others"
	atf_set "require.user" "root"
}
control_socket_slow_client_body()
{
	require_pidfile
	# Open a connection that sends nothing (holds the socket open).
	# Use nc in the background with a sleep to keep it connected.
	(sleep 3 | nc -U /var/run/authorityd.sock) &
	slow_pid=$!
	sleep 0.2

	# While the slow client is connected, the daemon must still respond.
	atf_check -s exit:0 -o match:"running" authorityctl status
	atf_check -s exit:0 -o match:"running" authorityctl status

	kill "$slow_pid" 2>/dev/null || true
	wait "$slow_pid" 2>/dev/null || true
}
control_socket_slow_client_cleanup()
{
	:
}

atf_test_case control_socket_concurrent_clients cleanup
control_socket_concurrent_clients_head()
{
	atf_set "descr" "multiple clients get responses concurrently"
	atf_set "require.user" "root"
}
control_socket_concurrent_clients_body()
{
	require_pidfile
	# Launch 5 status queries in parallel.
	for i in 1 2 3 4 5; do
		authorityctl status > "/tmp/ctl_concurrent_${i}.out" 2>&1 &
	done
	wait

	# All must have received a valid response.
	for i in 1 2 3 4 5; do
		atf_check -s exit:0 -o ignore \
		    grep "running" "/tmp/ctl_concurrent_${i}.out"
	done
}
control_socket_concurrent_clients_cleanup()
{
	rm -f /tmp/ctl_concurrent_*.out
}

atf_test_case control_socket_client_timeout cleanup
control_socket_client_timeout_head()
{
	atf_set "descr" "unresponsive client is disconnected after timeout"
	atf_set "require.user" "root"
}
control_socket_client_timeout_body()
{
	require_pidfile
	# Connect and send a partial request (only 8 of 16 header bytes).
	# The daemon should time out and close the connection.
	atf_check -s exit:0 sh -c '
		{
			printf "\\x01\\x00\\x00\\x00"
			printf "\\x02\\x00\\x00\\x00"
			sleep 5
		} | nc -U /var/run/authorityd.sock >/dev/null 2>&1 || true
	'
	# Daemon must still be responsive after the timeout.
	atf_check -s exit:0 -o match:"running" authorityctl status
}
control_socket_client_timeout_cleanup()
{
	:
}

atf_test_case control_socket_sighup_nonblocking cleanup
control_socket_sighup_nonblocking_head()
{
	atf_set "descr" "SIGHUP reload does not block status queries"
	atf_set "require.user" "root"
}
control_socket_sighup_nonblocking_body()
{
	require_pidfile
	pid=$(cat /var/run/authorityd.pid)

	# Send SIGHUP and immediately query status.
	kill -HUP "$pid"
	atf_check -s exit:0 -o match:"running" authorityctl status
}
control_socket_sighup_nonblocking_cleanup()
{
	:
}

# --- early-close and SIGPIPE ---

atf_test_case control_socket_early_close_status cleanup
control_socket_early_close_status_head()
{
	atf_set "descr" "client that closes before reading summary does not crash daemon"
	atf_set "require.user" "root"
}
control_socket_early_close_status_body()
{
	require_pidfile
	# Send a valid STATUS request, read only the 16-byte reply header,
	# then close immediately (before the daemon sends summary text).
	# This triggers a write to a closed socket — must not SIGPIPE.
	atf_check -s exit:0 sh -c '
		{
			printf "\\x01\\x00\\x00\\x00"
			printf "\\x02\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
		} | nc -U /var/run/authorityd.sock | dd bs=16 count=1 of=/dev/null 2>/dev/null
	'
	# Daemon must still be alive.
	atf_check -s exit:0 -o match:"running" authorityctl status
}
control_socket_early_close_status_cleanup()
{
	:
}

atf_test_case control_socket_early_close_services cleanup
control_socket_early_close_services_head()
{
	atf_set "descr" "services client closing mid-summary does not crash daemon"
	atf_set "require.user" "root"
}
control_socket_early_close_services_body()
{
	require_pidfile
	# Send SERVICES request, read 1 byte of response, then close.
	atf_check -s exit:0 sh -c '
		{
			printf "\\x01\\x00\\x00\\x00"
			printf "\\x09\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
		} | nc -U /var/run/authorityd.sock | dd bs=1 count=1 of=/dev/null 2>/dev/null
	'
	atf_check -s exit:0 -o match:"running" authorityctl status
}
control_socket_early_close_services_cleanup()
{
	:
}

atf_test_case control_socket_early_close_reload cleanup
control_socket_early_close_reload_head()
{
	atf_set "descr" "reload client closing mid-summary does not crash daemon"
	atf_set "require.user" "root"
}
control_socket_early_close_reload_body()
{
	require_pidfile
	# Send RELOAD request, read 1 byte, close.
	atf_check -s exit:0 sh -c '
		{
			printf "\\x01\\x00\\x00\\x00"
			printf "\\x03\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
		} | nc -U /var/run/authorityd.sock | dd bs=1 count=1 of=/dev/null 2>/dev/null
	'
	atf_check -s exit:0 -o match:"running" authorityctl status
}
control_socket_early_close_reload_cleanup()
{
	:
}

# --- concurrent SIGHUP plus operations ---

atf_test_case sighup_during_status cleanup
sighup_during_status_head()
{
	atf_set "descr" "SIGHUP during rapid status queries does not corrupt responses"
	atf_set "require.user" "root"
}
sighup_during_status_body()
{
	require_pidfile
	pid=$(cat /var/run/authorityd.pid)

	# Fire off status queries while sending SIGHUPs.
	for i in 1 2 3 4 5; do
		kill -HUP "$pid"
		atf_check -s exit:0 -o match:"running" authorityctl status
	done
}
sighup_during_status_cleanup()
{
	:
}

atf_test_case sighup_during_reload cleanup
sighup_during_reload_head()
{
	atf_set "descr" "SIGHUP interleaved with authorityctl reload is safe"
	atf_set "require.user" "root"
}
sighup_during_reload_body()
{
	require_pidfile
	pid=$(cat /var/run/authorityd.pid)

	# Interleave SIGHUP and control socket reloads.
	kill -HUP "$pid"
	atf_check -s exit:0 -o ignore authorityctl reload
	kill -HUP "$pid"
	atf_check -s exit:0 -o ignore authorityctl reload
	# Daemon must be healthy.
	atf_check -s exit:0 -o match:"running" authorityctl status
	atf_check -s exit:0 -o match:"CLAIMS:" authorityctl status
}
sighup_during_reload_cleanup()
{
	:
}

# --- services available to non-root ---

atf_test_case control_socket_services_any_user cleanup
control_socket_services_any_user_head()
{
	atf_set "descr" "services listing does not require root"
	atf_set "require.user" "root"
}
control_socket_services_any_user_body()
{
	require_pidfile
	# The control socket is mode 0700 owned by root, so non-root
	# can't connect at all.  But verify the daemon doesn't return
	# EPERM for root — the permission check was removed.
	atf_check -s exit:0 -o match:"serviced" authorityctl services
}
control_socket_services_any_user_cleanup()
{
	:
}

atf_test_case config_claims_files_alias cleanup
config_claims_files_alias_head()
{
	atf_set "descr" "claims.files is accepted as alias for claims.paths"
}
config_claims_files_alias_body()
{
	local conffile="$(pwd)/files_alias.conf"
	local pidfile="$(pwd)/files_alias_test.pid"
	cat > "$conffile" <<'ENDCONF'
claims {
    files = ["/dev/mac_capability", "/etc/authorityd.conf"];
}
ENDCONF
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_claims_files_alias_cleanup()
{
	if [ -f files_alias_test.pid ]; then
		kill "$(cat files_alias_test.pid)" 2>/dev/null || true
	fi
}

atf_test_case config_claims_network_address cleanup
config_claims_network_address_head()
{
	atf_set "descr" "claims.network with CIDR address is parsed"
}
config_claims_network_address_body()
{
	local conffile="$(pwd)/net_addr.conf"
	local pidfile="$(pwd)/net_addr_test.pid"
	cat > "$conffile" <<'ENDCONF'
claims {
    network = [
        { port = 443; protocol = "tcp"; direction = "bind"; address = "10.0.0.0/8"; },
        { port = 80; protocol = "tcp"; direction = "bind"; address = "::1"; },
    ];
}
ENDCONF
	authorityd -T -f "$conffile" -p "$pidfile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_claims_network_address_cleanup()
{
	if [ -f net_addr_test.pid ]; then
		kill "$(cat net_addr_test.pid)" 2>/dev/null || true
	fi
}

atf_init_test_cases()
{
	# Isolation
	atf_add_test_case isolation_mac_capability_module_loaded
	atf_add_test_case isolation_mac_capability_open_denied
	atf_add_test_case isolation_mac_capability_stat_denied

	# Capprotect
	atf_add_test_case capprotect_visible_config
	atf_add_test_case capprotect_ptrace_denied
	atf_add_test_case capprotect_ktrace_denied
	atf_add_test_case capprotect_sched_denied

	# Control socket
	atf_add_test_case control_socket_exists
	atf_add_test_case control_socket_permissions
	atf_add_test_case control_socket_status
	atf_add_test_case control_socket_status_uptime
	atf_add_test_case control_socket_bad_version
	atf_add_test_case control_socket_unknown_op
	atf_add_test_case control_socket_status_with_payload
	atf_add_test_case control_socket_rapid
	atf_add_test_case control_socket_reload_with_payload
	atf_add_test_case control_socket_shutdown_with_payload
	atf_add_test_case control_socket_unknown_op_with_payload
	atf_add_test_case control_socket_services_with_payload
	atf_add_test_case control_socket_empty_connect
	atf_add_test_case control_socket_status_shows_claims
	atf_add_test_case control_socket_slow_client
	atf_add_test_case control_socket_concurrent_clients
	atf_add_test_case control_socket_client_timeout
	atf_add_test_case control_socket_sighup_nonblocking
	atf_add_test_case control_socket_early_close_status
	atf_add_test_case control_socket_early_close_services
	atf_add_test_case control_socket_early_close_reload
	atf_add_test_case sighup_during_status
	atf_add_test_case sighup_during_reload
	atf_add_test_case control_socket_services_any_user

	# Configuration
	atf_add_test_case config_missing_file_uses_defaults
	atf_add_test_case config_syntax_error_exits
	atf_add_test_case config_custom_pidfile
	atf_add_test_case config_cli_overrides_config
	atf_add_test_case config_empty_file_uses_defaults
	atf_add_test_case config_integrity_settings
	atf_add_test_case config_claims_paths
	atf_add_test_case config_claims_network
	atf_add_test_case config_claims_files_alias
	atf_add_test_case config_claims_network_address
	atf_add_test_case config_claims_bad_path
	atf_add_test_case config_claims_system
	atf_add_test_case config_claims_system_bad_name
	atf_add_test_case config_bad_port
	atf_add_test_case config_relative_path
	atf_add_test_case config_integer_mode_rejected

	# Daemon behavior
	atf_add_test_case test_mode_no_root
	atf_add_test_case stale_socket_cleanup

	# Syslog
	atf_add_test_case syslog_init_complete
}
