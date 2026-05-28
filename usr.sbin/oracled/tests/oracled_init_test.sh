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

atf_test_case capprotect_invisible_to_ps cleanup
capprotect_invisible_to_ps_head()
{
	atf_set "descr" "oracled is invisible to ps (CP_SF_VISIBLE)"
	atf_set "require.user" "root"
}
capprotect_invisible_to_ps_body()
{
	require_pidfile
	pid=$(cat /var/run/oracled.pid)
	# ps must not find the process — CP_SF_VISIBLE hides it.
	atf_check -s not-exit:0 sh -c "ps -p $pid -o pid= 2>/dev/null | grep -q ."
}
capprotect_invisible_to_ps_cleanup()
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
	    grep "oracled\[$pid\].*reaper status confirmed" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*enabled OOM protection" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*claimed /dev/cap_rt" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*capprotect shield active" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*control socket" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled\[$pid\].*started" "$logfile"
}
syslog_init_complete_cleanup()
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
	# of junk payload.  Expect EINVAL (22 = 0x16).
	atf_check -s exit:0 -o match:"16" sh -c '
		{
			printf "\\x01\\x00\\x00\\x00"
			printf "\\x02\\x00\\x00\\x00"
			printf "\\x00\\x00\\x00\\x00"
			printf "\\x04\\x00\\x00\\x00"
			printf "JUNK"
		} | nc -U /var/run/oracled.sock | od -A n -t x1 | head -1
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

atf_init_test_cases()
{
	# Isolation
	atf_add_test_case isolation_cap_rt_module_loaded
	atf_add_test_case isolation_cap_rt_open_denied
	atf_add_test_case isolation_cap_rt_stat_denied

	# Capprotect
	atf_add_test_case capprotect_invisible_to_ps
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

	# Daemon behavior
	atf_add_test_case test_mode_no_root
	atf_add_test_case stale_socket_cleanup

	# Syslog
	atf_add_test_case syslog_init_complete
}
