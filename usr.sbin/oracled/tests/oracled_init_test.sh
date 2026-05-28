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
	    grep "oracled\[$pid\].*started" "$logfile"
}
syslog_init_complete_cleanup()
{
	:
}

atf_init_test_cases()
{
	atf_add_test_case isolation_cap_rt_module_loaded
	atf_add_test_case isolation_cap_rt_open_denied
	atf_add_test_case isolation_cap_rt_stat_denied
	atf_add_test_case capprotect_invisible_to_ps
	atf_add_test_case capprotect_ptrace_denied
	atf_add_test_case capprotect_ktrace_denied
	atf_add_test_case capprotect_sched_denied
	atf_add_test_case syslog_init_complete
}
