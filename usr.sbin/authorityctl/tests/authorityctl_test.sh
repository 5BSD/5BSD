#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Isolated ATF tests for authorityctl(8).  No case touches the production
# /var/run/authorityd.sock instance.
#

. "$(atf_get_srcdir)/capd_test_harness.sh"

daemon_pid=
pidfile=
conffile=
sockpath=
logfile=

require_authority_stack_kmods()
{
	capd_require_stack_kmods
}

prepare_paths()
{
	capd_paths_init
	pidfile=$CAPD_PIDFILE
	conffile=$CAPD_CONFIG
	sockpath=$CAPD_AUTHORITY_SOCKET
	logfile=$CAPD_LOG
}

start_authorityd()
{
	prepare_paths
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
service_manager = "";
EOF
	capd_find_guardian
	capd_launch_authority
	daemon_pid=$("$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status |
	    sed -n 's/^running pid=//p')
}

stop_authorityd()
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
	stop_authorityd || return 1
	capd_cleanup_stack || return 1
	rm -f authorityd.pid authorityd.conf authorityd.sock authorityd.log
}

atf_test_case usage_no_args
usage_no_args_head()
{
	atf_set "descr" "authorityctl with no arguments reports usage"
}
usage_no_args_body()
{
	atf_check -s exit:64 -e match:"usage:" authorityctl
}

atf_test_case usage_bad_command
usage_bad_command_head()
{
	atf_set "descr" "authorityctl rejects an unknown command"
}
usage_bad_command_body()
{
	atf_check -s exit:64 -e match:"usage:" authorityctl nosuchcommand
}

atf_test_case usage_extra_args
usage_extra_args_head()
{
	atf_set "descr" "authorityctl rejects extra command arguments"
}
usage_extra_args_body()
{
	atf_check -s exit:64 -e match:"usage:" authorityctl status extra
}

atf_test_case connect_no_daemon
connect_no_daemon_head()
{
	atf_set "descr" "authorityctl reports failure for a missing private socket"
}
connect_no_daemon_body()
{
	atf_check -s not-exit:0 -e match:"connect" \
	    authorityctl -s "$(pwd)/missing.sock" status
}

atf_test_case status_private_daemon cleanup
status_private_daemon_head()
{
	atf_set "descr" "status reports the isolated Authority configuration"
	atf_set "require.user" "root"
	require_authority_stack_kmods
	atf_set "timeout" "60"
}
status_private_daemon_body()
{
	start_authorityd
	authorityctl -s "$sockpath" status > status.out
	atf_check -s exit:0 -o match:"authorityd: running" cat status.out
	atf_check -s exit:0 -o match:"CONFIG:" cat status.out
	atf_check -s exit:0 -o match:"INTEGRITY:" cat status.out
	atf_check -s exit:0 -o match:"CLAIMS:" cat status.out
	atf_check -s exit:0 -o match:"/dev/mac_capability" cat status.out
}
status_private_daemon_cleanup()
{
	cleanup_common
	rm -f status.out
}

atf_test_case reload_private_daemon cleanup
reload_private_daemon_head()
{
	atf_set "descr" "authenticated reload preserves the isolated daemon"
	atf_set "require.user" "root"
	require_authority_stack_kmods
	atf_set "timeout" "60"
}
reload_private_daemon_body()
{
	start_authorityd
	atf_check -s exit:0 -o match:"reload:" \
	    authorityctl -s "$sockpath" reload
	atf_check -s exit:0 -o match:"authorityd: running" \
	    authorityctl -s "$sockpath" status
}
reload_private_daemon_cleanup()
{
	cleanup_common
}

atf_test_case shutdown_private_daemon cleanup
shutdown_private_daemon_head()
{
	atf_set "descr" "authenticated shutdown stops only the isolated daemon"
	atf_set "require.user" "root"
	require_authority_stack_kmods
	atf_set "timeout" "60"
}
shutdown_private_daemon_body()
{
	local i

	start_authorityd
	atf_check -s exit:0 -o match:"shutdown initiated" \
	    authorityctl -s "$sockpath" shutdown
	i=0
	while [ -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	wait "$daemon_pid" 2>/dev/null || true
	daemon_pid=
	atf_check -s exit:0 test ! -S "$sockpath"
	atf_check -s exit:0 test ! -e "$pidfile"
}
shutdown_private_daemon_cleanup()
{
	cleanup_common
}

atf_init_test_cases()
{
	atf_add_test_case usage_no_args
	atf_add_test_case usage_bad_command
	atf_add_test_case usage_extra_args
	atf_add_test_case connect_no_daemon
	atf_add_test_case status_private_daemon
	atf_add_test_case reload_private_daemon
	atf_add_test_case shutdown_private_daemon
}
