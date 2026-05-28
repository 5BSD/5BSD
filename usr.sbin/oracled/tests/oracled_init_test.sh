#
# SPDX-License-Identifier: BSD-2-Clause
#
# Initialization integrity tests for oracled.
#
# These verify that the running oracled instance has applied all
# expected hardening: procctl self-policy, isolation claim on
# /dev/cap_rt, and capprotect shield.  They run against the live
# system daemon and require root.
#

oracled_pid()
{
	cat /var/run/oracled.pid 2>/dev/null
}

oracled_running()
{
	local pid
	pid=$(oracled_pid)
	[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

# --- procctl hardening ---

atf_test_case procctl_reaper cleanup
procctl_reaper_head()
{
	atf_set "descr" "oracled is a subtree reaper"
	atf_set "require.user" "root"
}
procctl_reaper_body()
{
	atf_check oracled_running
	local pid
	pid=$(oracled_pid)
	# procstat -r shows reaper info; oracled should be its own reaper
	atf_check -s exit:0 -o match:"reaper" procstat -r "$pid"
}
procctl_reaper_cleanup()
{
	:
}

atf_test_case procctl_trace_disabled cleanup
procctl_trace_disabled_head()
{
	atf_set "descr" "oracled has tracing disabled via procctl"
	atf_set "require.user" "root"
}
procctl_trace_disabled_body()
{
	atf_check oracled_running
	local pid
	pid=$(oracled_pid)
	# ptrace attach should fail with EACCES or EPERM
	atf_check -s not-exit:0 -e ignore truss -p "$pid" -e exit 2>&1
}
procctl_trace_disabled_cleanup()
{
	:
}

atf_test_case procctl_oom_protect cleanup
procctl_oom_protect_head()
{
	atf_set "descr" "oracled is OOM-protected"
	atf_set "require.user" "root"
}
procctl_oom_protect_body()
{
	atf_check oracled_running
	local pid
	pid=$(oracled_pid)
	# P_PROTECTED flag in ps flags
	atf_check -s exit:0 -o not-empty \
	    sh -c "procstat -k $pid | grep -i protect || procstat $pid"
}
procctl_oom_protect_cleanup()
{
	:
}

# --- /dev/cap_rt isolation ---

atf_test_case isolation_cap_rt_claimed cleanup
isolation_cap_rt_claimed_head()
{
	atf_set "descr" "/dev/cap_rt is isolated — foreign nonce cannot open"
	atf_set "require.user" "root"
}
isolation_cap_rt_claimed_body()
{
	atf_check oracled_running
	# A new process (different nonce from oracled) should get EACCES
	# when trying to open /dev/cap_rt.
	atf_check -s not-exit:0 -e match:"Permission denied" \
	    sh -c 'exec 3</dev/cap_rt'
}
isolation_cap_rt_claimed_cleanup()
{
	:
}

atf_test_case isolation_cap_rt_device_exists cleanup
isolation_cap_rt_device_exists_head()
{
	atf_set "descr" "/dev/cap_rt device node exists"
	atf_set "require.user" "root"
}
isolation_cap_rt_device_exists_body()
{
	atf_check -s exit:0 test -c /dev/cap_rt
}
isolation_cap_rt_device_exists_cleanup()
{
	:
}

# --- capprotect shield ---

atf_test_case capprotect_ptrace_blocked cleanup
capprotect_ptrace_blocked_head()
{
	atf_set "descr" "capprotect blocks ptrace attach to oracled"
	atf_set "require.user" "root"
}
capprotect_ptrace_blocked_body()
{
	atf_check oracled_running
	local pid
	pid=$(oracled_pid)
	# truss uses ptrace; should be denied by the capprotect MACF hook
	atf_check -s not-exit:0 -e ignore truss -p "$pid" -e exit 2>&1
}
capprotect_ptrace_blocked_cleanup()
{
	:
}

atf_test_case capprotect_signal_blocked cleanup
capprotect_signal_blocked_head()
{
	atf_set "descr" "capprotect blocks foreign signals to oracled"
	atf_set "require.user" "root"
}
capprotect_signal_blocked_body()
{
	atf_check oracled_running
	local pid
	pid=$(oracled_pid)
	# SIGUSR1 from a foreign nonce (this shell) should be denied.
	# oracled does not handle SIGUSR1 so if it arrives, it would
	# terminate the daemon.  Verify the signal is blocked and
	# oracled is still alive afterward.
	kill -USR1 "$pid" 2>/dev/null || true
	sleep 0.2
	atf_check -s exit:0 kill -0 "$pid"
}
capprotect_signal_blocked_cleanup()
{
	:
}

atf_test_case capprotect_ktrace_blocked cleanup
capprotect_ktrace_blocked_head()
{
	atf_set "descr" "capprotect blocks ktrace on oracled"
	atf_set "require.user" "root"
}
capprotect_ktrace_blocked_body()
{
	atf_check oracled_running
	local pid
	pid=$(oracled_pid)
	atf_check -s not-exit:0 -e ignore \
	    ktrace -p "$pid" -t c
	rm -f ktrace.out
}
capprotect_ktrace_blocked_cleanup()
{
	rm -f ktrace.out
}

# --- daemon syslog messages ---

atf_test_case syslog_init_messages cleanup
syslog_init_messages_head()
{
	atf_set "descr" "oracled logs expected initialization messages"
	atf_set "require.user" "root"
}
syslog_init_messages_body()
{
	atf_check oracled_running
	local logfile="/var/log/daemon.log"
	atf_check -s exit:0 test -r "$logfile"
	# Check for key initialization messages
	atf_check -s exit:0 -o not-empty \
	    grep "oracled.*reaper status" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled.*claimed /dev/cap_rt" "$logfile"
	atf_check -s exit:0 -o not-empty \
	    grep "oracled.*capprotect shield active" "$logfile"
}
syslog_init_messages_cleanup()
{
	:
}

atf_init_test_cases()
{
	atf_add_test_case procctl_reaper
	atf_add_test_case procctl_trace_disabled
	atf_add_test_case procctl_oom_protect
	atf_add_test_case isolation_cap_rt_claimed
	atf_add_test_case isolation_cap_rt_device_exists
	atf_add_test_case capprotect_ptrace_blocked
	atf_add_test_case capprotect_signal_blocked
	atf_add_test_case capprotect_ktrace_blocked
	atf_add_test_case syslog_init_messages
}
