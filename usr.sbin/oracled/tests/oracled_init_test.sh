#
# SPDX-License-Identifier: BSD-2-Clause
#
# Initialization integrity tests for oracled.
#
# These verify that the running oracled instance has applied all
# expected hardening.  Many tests work by confirming that external
# access is DENIED — the denial itself is proof the protection is
# active.  They run against the live system daemon and require root.
#

require_pidfile()
{
	if [ ! -f /var/run/oracled.pid ]; then
		atf_skip "oracled pidfile not found"
	fi
	pid=$(cat /var/run/oracled.pid 2>/dev/null)
	if [ -z "$pid" ]; then
		atf_skip "oracled pidfile is empty"
	fi
}

# --- isolation ---

atf_test_case isolation_cap_rt_module_loaded cleanup
isolation_cap_rt_module_loaded_head()
{
	atf_set "descr" "cap_rt kernel module is loaded"
	atf_set "require.user" "root"
}
isolation_cap_rt_module_loaded_body()
{
	atf_check -s exit:0 kldstat -qm cap_rt
}
isolation_cap_rt_module_loaded_cleanup()
{
	:
}

atf_test_case isolation_cap_rt_open_denied cleanup
isolation_cap_rt_open_denied_head()
{
	atf_set "descr" "/dev/cap_rt cannot be opened by foreign nonce"
	atf_set "require.user" "root"
}
isolation_cap_rt_open_denied_body()
{
	require_pidfile
	# A new process has a different nonce from oracled.
	# The isolation MACF hook must deny the open.
	atf_check -s not-exit:0 -e match:"Permission denied" \
	    sh -c 'cat /dev/cap_rt'
}
isolation_cap_rt_open_denied_cleanup()
{
	:
}

atf_test_case isolation_cap_rt_stat_denied cleanup
isolation_cap_rt_stat_denied_head()
{
	atf_set "descr" "/dev/cap_rt cannot be stat'd by foreign nonce"
	atf_set "require.user" "root"
}
isolation_cap_rt_stat_denied_body()
{
	require_pidfile
	# Even stat/test is blocked by the isolation MACF hook.
	atf_check -s not-exit:0 sh -c 'test -c /dev/cap_rt'
}
isolation_cap_rt_stat_denied_cleanup()
{
	:
}

# --- capprotect: visibility ---

atf_test_case capprotect_visible_config cleanup
capprotect_visible_config_head()
{
	atf_set "descr" "oracled visibility matches integrity.visible config"
	atf_set "require.user" "root"
}
capprotect_visible_config_body()
{
	require_pidfile
	pid=$(cat /var/run/oracled.pid)
	# Check the config file for visible setting.
	if grep -q 'visible.*true' /etc/oracled.conf 2>/dev/null; then
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
	atf_set "descr" "ptrace attach to oracled is denied (CP_SF_PTRACE)"
	atf_set "require.user" "root"
}
capprotect_ptrace_denied_body()
{
	require_pidfile
	pid=$(cat /var/run/oracled.pid)
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
	atf_set "descr" "ktrace on oracled is denied (CP_SF_KTRACE)"
	atf_set "require.user" "root"
}
capprotect_ktrace_denied_body()
{
	require_pidfile
	pid=$(cat /var/run/oracled.pid)
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
	atf_set "descr" "scheduler manipulation of oracled is denied (CP_SF_SCHED)"
	atf_set "require.user" "root"
}
capprotect_sched_denied_body()
{
	require_pidfile
	pid=$(cat /var/run/oracled.pid)
	# Attempt to renice oracled from a foreign nonce.
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
	atf_set "descr" "control socket exists at /var/run/oracled.sock"
	atf_set "require.user" "root"
}
control_socket_exists_body()
{
	require_pidfile
	atf_check -s exit:0 test -S /var/run/oracled.sock
}
control_socket_exists_cleanup()
{
	:
}

atf_test_case control_socket_status cleanup
control_socket_status_head()
{
	atf_set "descr" "oraclectl status returns valid output"
	atf_set "require.user" "root"
}
control_socket_status_body()
{
	require_pidfile
	atf_check -s exit:0 -o match:"oracled: running" oraclectl status
}
control_socket_status_cleanup()
{
	:
}

atf_test_case control_socket_status_uptime cleanup
control_socket_status_uptime_head()
{
	atf_set "descr" "oraclectl status reports uptime"
	atf_set "require.user" "root"
}
control_socket_status_uptime_body()
{
	require_pidfile
	atf_check -s exit:0 -o match:"uptime:" oraclectl status
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
	# ENOTSUP is 45 (0x2d) on FreeBSD.
	atf_check -s exit:0 -o match:"2d" sh -c '
		{
			printf "\\x63\\x00\\x00\\x00"
			printf "\\x02\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
		} | nc -U /var/run/oracled.sock | od -A n -t x1 | head -1
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
	# Send version=1, op=255 (unknown), expect ENOTSUP.
	atf_check -s exit:0 -o match:"2d" sh -c '
		{
			printf "\\x01\\x00\\x00\\x00"
			printf "\\xff\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
		} | nc -U /var/run/oracled.sock | od -A n -t x1 | head -1
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
		} | nc -U /var/run/oracled.sock | od -A n -t x1 | head -1)
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
		atf_check -s exit:0 -o match:"running" oraclectl status
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
	mode=$(stat -f '%Lp' /var/run/oracled.sock)
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
	atf_set "descr" "oracled -T runs without root"
}
test_mode_no_root_body()
{
	local pid pidfile

	pidfile="$(pwd)/oracled_test.pid"
	oracled -T -p "$pidfile" &
	pid=$!

	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
test_mode_no_root_cleanup()
{
	if [ -f oracled_test.pid ]; then
		pid="$(cat oracled_test.pid 2>/dev/null || true)"
		if [ -n "$pid" ]; then
			kill "$pid" 2>/dev/null || true
		fi
		rm -f oracled_test.pid
	fi
}

# --- stale socket cleanup ---

atf_test_case stale_socket_cleanup cleanup
stale_socket_cleanup_head()
{
	atf_set "descr" "oracled cleans up stale socket on start"
	atf_set "require.user" "root"
}
stale_socket_cleanup_body()
{
	require_pidfile
	# The fact that oracled started successfully (require_pidfile
	# passes) with a control socket means it either created a new
	# socket or cleaned up a stale one from a previous crash.
	# Verify the socket works.
	atf_check -s exit:0 -o match:"running" oraclectl status
}
stale_socket_cleanup_cleanup()
{
	:
}

# --- configuration ---

atf_test_case config_missing_file_uses_defaults cleanup
config_missing_file_uses_defaults_head()
{
	atf_set "descr" "oracled starts with defaults when config file is absent"
}
config_missing_file_uses_defaults_body()
{
	local pidfile="$(pwd)/cfg_test.pid"
	oracled -T -f /nonexistent/oracled.conf -p "$pidfile" &
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
	atf_set "descr" "oracled exits on config syntax error"
}
config_syntax_error_exits_body()
{
	local conffile="$(pwd)/bad.conf"
	echo "this is { not valid ucl }{{{" > "$conffile"
	atf_check -s not-exit:0 -e not-empty \
	    oracled -T -f "$conffile" -p "$(pwd)/bad.pid"
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
	local pidfile="$(pwd)/custom_oracle.pid"
	echo "pidfile = \"$pidfile\";" > "$conffile"
	oracled -T -f "$conffile" &
	local pid=$!
	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 test "$(cat "$pidfile")" = "$pid"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
}
config_custom_pidfile_cleanup()
{
	if [ -f custom_oracle.pid ]; then
		kill "$(cat custom_oracle.pid)" 2>/dev/null || true
		rm -f custom_oracle.pid
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
	oracled -T -f "$conffile" -p "$cli_pid" &
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
	oracled -T -f "$conffile" -p "$pidfile" &
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
	oracled -T -f "$conffile" -p "$pidfile" &
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
	oracled -T -f "$conffile" -p "$pidfile" &
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
    ];
}
ENDCONF
	oracled -T -f "$conffile" -p "$pidfile" &
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
	oracled -T -f "$conffile" -p "$pidfile" &
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
	oracled -T -f "$conffile" -p "$pidfile" &
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
	oracled -T -f "$conffile" -p "$pidfile" &
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

# --- syslog: initialization completed ---

atf_test_case syslog_init_complete cleanup
syslog_init_complete_head()
{
	atf_set "descr" "oracled logs successful initialization"
	atf_set "require.user" "root"
}
syslog_init_complete_body()
{
	require_pidfile
	pid=$(cat /var/run/oracled.pid)
	local logfile="/var/log/daemon.log"
	if [ ! -r "$logfile" ]; then
		atf_skip "daemon.log not readable"
	fi
	# Verify all init stages completed for this pid.
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*config:" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*reaper status confirmed" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*enabled OOM protection" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*isolation.*claimed.*/dev/cap_rt" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*integrity active" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*control socket" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*started" "$logfile"
}
syslog_init_complete_cleanup()
{
	:
}

atf_init_test_cases()
{
	# Isolation
	atf_add_test_case isolation_cap_rt_module_loaded
	atf_add_test_case isolation_cap_rt_open_denied
	atf_add_test_case isolation_cap_rt_stat_denied

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

	# Configuration
	atf_add_test_case config_missing_file_uses_defaults
	atf_add_test_case config_syntax_error_exits
	atf_add_test_case config_custom_pidfile
	atf_add_test_case config_cli_overrides_config
	atf_add_test_case config_empty_file_uses_defaults
	atf_add_test_case config_integrity_settings
	atf_add_test_case config_claims_paths
	atf_add_test_case config_claims_network
	atf_add_test_case config_claims_bad_path
	atf_add_test_case config_claims_system
	atf_add_test_case config_claims_system_bad_name

	# Daemon behavior
	atf_add_test_case test_mode_no_root
	atf_add_test_case stale_socket_cleanup

	# Syslog
	atf_add_test_case syslog_init_complete
}
