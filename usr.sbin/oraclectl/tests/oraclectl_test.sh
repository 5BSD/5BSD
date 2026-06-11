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

# --- status command: negative ---

atf_test_case status_shows_cap_rt_claim cleanup
status_shows_cap_rt_claim_head()
{
	atf_set "descr" "oraclectl status always shows /dev/cap_rt in claims"
	atf_set "require.user" "root"
}
status_shows_cap_rt_claim_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"/dev/cap_rt" oraclectl status
}
status_shows_cap_rt_claim_cleanup()
{
	:
}

atf_test_case status_shows_integrity_flags cleanup
status_shows_integrity_flags_head()
{
	atf_set "descr" "oraclectl status shows specific integrity flag names"
	atf_set "require.user" "root"
}
status_shows_integrity_flags_body()
{
	require_oracled
	# Default integrity flags include ptrace, wait, sched, ktrace.
	atf_check -s exit:0 -o match:"ptrace" oraclectl status
	atf_check -s exit:0 -o match:"ktrace" oraclectl status
}
status_shows_integrity_flags_cleanup()
{
	:
}

atf_test_case status_socket_path cleanup
status_socket_path_head()
{
	atf_set "descr" "oraclectl -s with nonexistent socket fails cleanly"
}
status_socket_path_body()
{
	atf_check -s not-exit:0 -e match:"connect" \
	    oraclectl -s /nonexistent/socket.sock status
}
status_socket_path_cleanup()
{
	:
}

# --- status command: policy output ---

atf_test_case status_shows_config cleanup
status_shows_config_head()
{
	atf_set "descr" "oraclectl status shows config section"
	atf_set "require.user" "root"
}
status_shows_config_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"CONFIG:" oraclectl status
}
status_shows_config_cleanup()
{
	:
}

atf_test_case status_shows_integrity cleanup
status_shows_integrity_head()
{
	atf_set "descr" "oraclectl status shows integrity flags"
	atf_set "require.user" "root"
}
status_shows_integrity_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"INTEGRITY:" oraclectl status
}
status_shows_integrity_cleanup()
{
	:
}

atf_test_case status_shows_claims cleanup
status_shows_claims_head()
{
	atf_set "descr" "oraclectl status shows resource claims"
	atf_set "require.user" "root"
}
status_shows_claims_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"CLAIMS:" oraclectl status
}
status_shows_claims_cleanup()
{
	:
}

atf_test_case status_shows_services cleanup
status_shows_services_head()
{
	atf_set "descr" "oraclectl status shows service summary"
	atf_set "require.user" "root"
}
status_shows_services_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"SERVICED:" oraclectl status
}
status_shows_services_cleanup()
{
	:
}

atf_test_case status_shows_service_mgr cleanup
status_shows_service_mgr_head()
{
	atf_set "descr" "oraclectl status shows service_mgr path"
	atf_set "require.user" "root"
}
status_shows_service_mgr_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"service_mgr:" oraclectl status
}
status_shows_service_mgr_cleanup()
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

atf_test_case reload_idempotent cleanup
reload_idempotent_head()
{
	atf_set "descr" "repeated reloads with no changes succeed"
	atf_set "require.user" "root"
}
reload_idempotent_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"reload:" oraclectl reload
	atf_check -s exit:0 -o match:"reload:" oraclectl reload
	atf_check -s exit:0 -o match:"reload:" oraclectl reload
}
reload_idempotent_cleanup()
{
	:
}

atf_test_case reload_then_status cleanup
reload_then_status_head()
{
	atf_set "descr" "status works correctly after a reload"
	atf_set "require.user" "root"
}
reload_then_status_body()
{
	require_oracled
	atf_check -s exit:0 -o ignore oraclectl reload
	atf_check -s exit:0 -o match:"oracled: running" oraclectl status
	atf_check -s exit:0 -o match:"CLAIMS:" oraclectl status
}
reload_then_status_cleanup()
{
	:
}

# --- reload command: negative ---

atf_test_case reload_returns_summary cleanup
reload_returns_summary_head()
{
	atf_set "descr" "oraclectl reload returns a change summary"
	atf_set "require.user" "root"
}
reload_returns_summary_body()
{
	require_oracled
	# Reload updates oracled config; manifest changes forwarded to serviced.
	atf_check -s exit:0 -o match:"reload:" oraclectl reload
}
reload_returns_summary_cleanup()
{
	:
}

atf_test_case reload_status_coherent cleanup
reload_status_coherent_head()
{
	atf_set "descr" "status is coherent after multiple reloads"
	atf_set "require.user" "root"
}
reload_status_coherent_body()
{
	require_oracled
	atf_check -s exit:0 -o ignore oraclectl reload
	atf_check -s exit:0 -o ignore oraclectl reload
	# Status must still show all expected sections.
	atf_check -s exit:0 -o match:"CONFIG:" oraclectl status
	atf_check -s exit:0 -o match:"INTEGRITY:" oraclectl status
	atf_check -s exit:0 -o match:"CLAIMS:" oraclectl status
	atf_check -s exit:0 -o match:"SERVICED:" oraclectl status
}
reload_status_coherent_cleanup()
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

# --- usage: check and load need a filename ---

atf_test_case usage_check_no_file
usage_check_no_file_head()
{
	atf_set "descr" "oraclectl check without filename prints usage"
}
usage_check_no_file_body()
{
	atf_check -s not-exit:0 -e match:"servicectl" oraclectl check
}

atf_test_case usage_load_no_file
usage_load_no_file_head()
{
	atf_set "descr" "oraclectl load without filename prints usage"
}
usage_load_no_file_body()
{
	atf_check -s not-exit:0 -e match:"servicectl" oraclectl load
}

# --- usage: negative ---

atf_test_case usage_services_bad_flag
usage_services_bad_flag_head()
{
	atf_set "descr" "oraclectl services with bad flag prints usage"
}
usage_services_bad_flag_body()
{
	atf_check -s not-exit:0 -e match:"usage:" oraclectl services -x
}

atf_test_case usage_load_extra_args
usage_load_extra_args_head()
{
	atf_set "descr" "oraclectl load with extra args prints usage"
}
usage_load_extra_args_body()
{
	atf_check -s not-exit:0 -e match:"servicectl" oraclectl load a b
}

atf_test_case usage_reload_extra_args
usage_reload_extra_args_head()
{
	atf_set "descr" "oraclectl reload with extra args prints usage"
}
usage_reload_extra_args_body()
{
	atf_check -s not-exit:0 -e match:"usage:" oraclectl reload extra
}

atf_test_case usage_shutdown_extra_args
usage_shutdown_extra_args_head()
{
	atf_set "descr" "oraclectl shutdown with extra args prints usage"
}
usage_shutdown_extra_args_body()
{
	atf_check -s not-exit:0 -e match:"usage:" oraclectl shutdown now
}

# --- services command ---

atf_test_case services_shows_loaded cleanup
services_shows_loaded_head()
{
	atf_set "descr" "oraclectl services lists loaded services"
	atf_set "require.user" "root"
}
services_shows_loaded_body()
{
	require_oracled
	atf_check -s exit:0 -o match:"serviced" oraclectl services
}
services_shows_loaded_cleanup()
{
	:
}

atf_test_case services_verbose cleanup
services_verbose_head()
{
	atf_set "descr" "oraclectl services -v shows capabilities"
	atf_set "require.user" "root"
}
services_verbose_body()
{
	require_oracled
	# With no services loaded, -v still succeeds and shows serviced info.
	atf_check -s exit:0 -o match:"serviced" oraclectl services -v
}
services_verbose_cleanup()
{
	:
}

# --- check command ---

atf_test_case check_nonexistent cleanup
check_nonexistent_head()
{
	atf_set "descr" "oraclectl check with nonexistent manifest fails"
	atf_set "require.user" "root"
}
check_nonexistent_body()
{
	require_oracled
	atf_check -s not-exit:0 -e match:"servicectl" \
	    oraclectl check nosuch.ucl
}
check_nonexistent_cleanup()
{
	:
}

atf_test_case check_path_traversal cleanup
check_path_traversal_head()
{
	atf_set "descr" "oraclectl check rejects path traversal"
	atf_set "require.user" "root"
}
check_path_traversal_body()
{
	require_oracled
	# The '/' in the payload is rejected by the control socket
	atf_check -s not-exit:0 -e ignore oraclectl check ../../../etc/passwd
}
check_path_traversal_cleanup()
{
	:
}

atf_init_test_cases()
{
	# Argument handling (no root needed)
	atf_add_test_case usage_no_args
	atf_add_test_case usage_bad_command
	atf_add_test_case usage_extra_args
	atf_add_test_case usage_check_no_file
	atf_add_test_case usage_load_no_file
	atf_add_test_case connect_no_daemon

	# Status
	atf_add_test_case status_running
	atf_add_test_case status_uptime
	atf_add_test_case status_shows_config
	atf_add_test_case status_shows_integrity
	atf_add_test_case status_shows_claims
	atf_add_test_case status_shows_services
	atf_add_test_case status_shows_service_mgr
	atf_add_test_case status_shows_cap_rt_claim
	atf_add_test_case status_shows_integrity_flags
	atf_add_test_case status_socket_path

	# Services
	atf_add_test_case services_shows_loaded
	atf_add_test_case services_verbose

	# Check
	atf_add_test_case check_nonexistent
	atf_add_test_case check_path_traversal

	# Reload
	atf_add_test_case reload_succeeds
	atf_add_test_case reload_idempotent
	atf_add_test_case reload_then_status
	atf_add_test_case reload_returns_summary
	atf_add_test_case reload_status_coherent

	# Usage (negative — no root needed)
	atf_add_test_case usage_services_bad_flag
	atf_add_test_case usage_load_extra_args
	atf_add_test_case usage_reload_extra_args
	atf_add_test_case usage_shutdown_extra_args

	# Shutdown (must be last — it stops the daemon)
	atf_add_test_case shutdown_stops_daemon
}
