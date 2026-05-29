#
# SPDX-License-Identifier: BSD-2-Clause
#
# Tests for oraclectl(8).
#
# These verify the control interface to oracled(8).  Most tests
# require root and a running oracled instance.
#

require_oracled()
{
	if [ ! -S /var/run/oracled.sock ]; then
		atf_skip "oracled control socket not found"
	fi
}

# --- usage / argument handling ---

atf_test_case usage_no_args
usage_no_args_head()
{
	atf_set "descr" "oraclectl with no args prints usage and fails"
}
usage_no_args_body()
{
	atf_check -s not-exit:0 -e match:"usage:" oraclectl
}

atf_test_case usage_bad_command
usage_bad_command_head()
{
	atf_set "descr" "oraclectl with unknown command prints usage"
}
usage_bad_command_body()
{
	atf_check -s not-exit:0 -e match:"usage:" oraclectl nosuchcommand
}

atf_test_case usage_kldload_no_module
usage_kldload_no_module_head()
{
	atf_set "descr" "oraclectl kldload without module name prints usage"
}
usage_kldload_no_module_body()
{
	atf_check -s not-exit:0 -e match:"usage:" oraclectl kldload
}

atf_test_case usage_extra_args
usage_extra_args_head()
{
	atf_set "descr" "oraclectl status with extra args prints usage"
}
usage_extra_args_body()
{
	atf_check -s not-exit:0 -e match:"usage:" oraclectl status extra
}

# --- connection errors ---

atf_test_case connect_no_daemon
connect_no_daemon_head()
{
	atf_set "descr" "oraclectl fails cleanly when oracled is not running"
	atf_set "require.user" "root"
}
connect_no_daemon_body()
{
	# Use a nonexistent socket path to simulate no daemon.
	# oraclectl hardcodes the path, so we test by ensuring
	# a clean error message if the socket is missing.
	if [ -S /var/run/oracled.sock ]; then
		atf_skip "oracled is running; cannot test missing socket"
	fi
	atf_check -s not-exit:0 -e match:"connect" oraclectl status
}

# --- status command ---

atf_test_case status_running cleanup
status_running_head()
{
	atf_set "descr" "oraclectl status reports running daemon"
	atf_set "require.user" "root"
}
status_running_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"oracled: running" oraclectl status
}
status_running_cleanup()
{
	:
}

atf_test_case status_uptime cleanup
status_uptime_head()
{
	atf_set "descr" "oraclectl status reports uptime"
	atf_set "require.user" "root"
}
status_uptime_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"uptime:" oraclectl status
}
status_uptime_cleanup()
{
	:
}

# --- reload command ---

atf_test_case reload_succeeds cleanup
reload_succeeds_head()
{
	atf_set "descr" "oraclectl reload returns success with summary"
	atf_set "require.user" "root"
}
reload_succeeds_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"reload:" oraclectl reload
}
reload_succeeds_cleanup()
{
	:
}

# --- kldload / kldunload ---

atf_test_case kldload_nonexistent cleanup
kldload_nonexistent_head()
{
	atf_set "descr" "oraclectl kldload with bad module returns error"
	atf_set "require.user" "root"
}
kldload_nonexistent_body()
{
	require_oracled
	atf_check -s not-exit:0 -e match:"No such file" \
	    oraclectl kldload no_such_module_ever
}
kldload_nonexistent_cleanup()
{
	:
}

atf_test_case kldload_already_loaded cleanup
kldload_already_loaded_head()
{
	atf_set "descr" "oraclectl kldload of already loaded module returns error"
	atf_set "require.user" "root"
}
kldload_already_loaded_body()
{
	require_oracled
	# cap_rt is always loaded when oracled is running.
	atf_check -s not-exit:0 -e ignore \
	    oraclectl kldload cap_rt
}
kldload_already_loaded_cleanup()
{
	:
}

# --- shutdown command ---

atf_test_case shutdown_stops_daemon cleanup
shutdown_stops_daemon_head()
{
	atf_set "descr" "oraclectl shutdown stops oracled"
	atf_set "require.user" "root"
}
shutdown_stops_daemon_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"shutdown initiated" \
	    oraclectl shutdown
	sleep 1
	# The socket should be gone after shutdown.
	atf_check -s exit:1 test -S /var/run/oracled.sock
}
shutdown_stops_daemon_cleanup()
{
	# Restart oracled for subsequent tests.
	if [ ! -S /var/run/oracled.sock ]; then
		service oracled start 2>/dev/null || true
		sleep 1
	fi
}

atf_init_test_cases()
{
	# Argument handling (no root needed)
	atf_add_test_case usage_no_args
	atf_add_test_case usage_bad_command
	atf_add_test_case usage_kldload_no_module
	atf_add_test_case usage_extra_args
	atf_add_test_case connect_no_daemon

	# Status
	atf_add_test_case status_running
	atf_add_test_case status_uptime

	# Operations
	atf_add_test_case reload_succeeds
	atf_add_test_case kldload_nonexistent
	atf_add_test_case kldload_already_loaded

	# Shutdown (must be last — it stops the daemon)
	atf_add_test_case shutdown_stops_daemon
}
