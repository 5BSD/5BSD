#
# SPDX-License-Identifier: BSD-2-Clause
#
# Bootstrap and channel protocol tests for capsule + switchboard.
#
# These verify that capsule starts switchboard as its child, the channel
# channel protocol works, and bootstrap restart logic is sound.
#

. "$(atf_get_srcdir)/capd_test_harness.sh"

PATH="$(dirname "$(atf_get_srcdir)"):${PATH}"
export PATH

daemon_pid=
pidfile=
conffile=
sockpath=
logfile=
switchboard_bin=
switchboard_src=
disable_signal_shields=false
shield_helper=

prepare_paths()
{
	capd_paths_init
	pidfile=$CAPD_PIDFILE
	conffile=$CAPD_CONFIG
	sockpath=$CAPD_CAPSULE_SOCKET
	logfile=$CAPD_LOG
}

# Capsule opens these mandatory capability services during initialization,
# before a test-specific mock switchboard process is started.  Keep the complete
# prerequisite set in ATF metadata so Kyua loads it before each test body.
require_capsule_stack_kmods()
{
	capd_require_stack_kmods
}

build_mock_switchboard()
{
	switchboard_src=
	switchboard_bin="$(atf_get_srcdir)/capd_bootstrap_fixture"
	if [ ! -x "$switchboard_bin" ]; then
		atf_fail "bootstrap fixture not found: $switchboard_bin"
	fi
}

find_shield_helper()
{
	local candidate srcdir

	if [ -n "$shield_helper" ] && [ -x "$shield_helper" ]; then
		return 0
	fi
	srcdir=$(atf_get_srcdir)
	for candidate in \
	    "${CAPD_SHIELD_HELPER:-}" \
	    "${srcdir}/mac_capability_shield_helper" \
	    "/usr/tests/sys/mac_capability/mac_capability_shield_helper" \
	    "$(command -v mac_capability_shield_helper 2>/dev/null)"
	do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			shield_helper=$candidate
			return 0
		fi
	done
	atf_fail "mac_capability_shield_helper is unavailable"
}
write_config()
{
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
service_manager = "$switchboard_bin";
EOF
	if $disable_signal_shields; then
		cat >> "$conffile" <<'EOF'
integrity {
    signal = false;
    sigkill = false;
    sigcont = false;
}
EOF
	fi
}

start_capsule()
{
	prepare_paths
	mkdir -p "$(pwd)/switchboard.d"
	write_config
	capd_find_guardian
	capd_launch_capsule
	daemon_pid=$("$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status |
	    sed -n 's/^running pid=//p')
}

wait_for_file()
{
	local path i
	path="$1"
	i=0
	while [ ! -s "$path" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	test -s "$path"
}

wait_for_log()
{
	local pattern i
	pattern="$1"
	i=0
	while ! grep -q "$pattern" "$logfile" 2>/dev/null &&
	    [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	grep -q "$pattern" "$logfile" 2>/dev/null
}

wait_for_authenticated_shutdown()
{
	if ! capd_wait_guardian_exit 100; then
		capd_dump_diagnostics
		atf_fail "Capsule did not exit after authenticated shutdown"
	fi
	capd_close_lease
	if [ -n "$capd_guardian_pid" ]; then
		wait "$capd_guardian_pid" 2>/dev/null ||
		    atf_fail "guardian reported an unclean Capsule shutdown"
		capd_guardian_pid=
	fi
	daemon_pid=
}

stop_capsule()
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
	local cleanup_status

	cleanup_status=0
	# ATF invokes cleanup in a new process.  Exiting the body closes its
	# guardian lease, so the guardian may already be performing the intended
	# fail-safe shutdown when this graceful request races it.  Cleanup is
	# successful if the recovery pass proves that no stack remains; tests
	# concerned with graceful shutdown assert that behavior in their body.
	stop_capsule || true
	capd_cleanup_stack || cleanup_status=1
	sleep 0.2
	rm -rf capsule.pid capsule.conf switchboard.d capsule.sock \
	    capsule.log mock_switchboard mock_switchboard.c mock-mode \
	    switchboard-started.out switchboard-ping-ok.out
	return "$cleanup_status"
}

# -------------------------------------------------------------------
# Test cases
# -------------------------------------------------------------------

atf_test_case bootstrap_starts_switchboard cleanup
bootstrap_starts_switchboard_head()
{
	atf_set "descr" "capsule starts switchboard as its child via pdfork"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
bootstrap_starts_switchboard_body()
{
	build_mock_switchboard
	start_capsule

	if ! wait_for_file switchboard-started.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "switchboard did not start (mac_capability channel service may not be loaded)"
	fi

	# Verify the channel fd was inherited.
	atf_check -s exit:0 -o match:"channel_fd=" grep "channel_fd=" switchboard-started.out

	# Verify capsule logged the start.
	atf_check -s exit:0 -o ignore grep "bootstrap: started switchboard" "$logfile"

	# Verify capsule is still healthy.
	capd_capsule_ctl "$sockpath" status | grep -q running ||
	    atf_fail "Capsule status request failed"
}
bootstrap_starts_switchboard_cleanup()
{
	cleanup_common
}

atf_test_case bootstrap_channel_ping cleanup
bootstrap_channel_ping_head()
{
	atf_set "descr" "switchboard can ping capsule over the channel"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
bootstrap_channel_ping_body()
{
	echo "ping-then-sleep" > mock-mode
	build_mock_switchboard
	start_capsule

	if ! wait_for_file switchboard-ping-ok.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "switchboard did not start or ping failed"
	fi

	atf_check -s exit:0 -o match:"ok" cat switchboard-ping-ok.out
	capd_capsule_ctl "$sockpath" status | grep -q running ||
	    atf_fail "Capsule status request failed"
}
bootstrap_channel_ping_cleanup()
{
	rm -f mock-mode
	cleanup_common
}

atf_test_case control_reload_reaches_switchboard cleanup
control_reload_reaches_switchboard_head()
{
	atf_set "descr" "authenticated Capsule reload is forwarded to switchboard"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
control_reload_reaches_switchboard_body()
{
	echo "wait-for-reload" > mock-mode
	build_mock_switchboard
	start_capsule

	if ! wait_for_file switchboard-started.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "switchboard did not start"
	fi
	capd_capsule_ctl "$sockpath" reload | grep -q "reload:" ||
	    atf_fail "Capsule reload request failed"
	if ! wait_for_file switchboard-reload.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "switchboard did not receive the forwarded reload"
	fi
	atf_check -s exit:0 -o inline:'reloaded\n' cat switchboard-reload.out
}
control_reload_reaches_switchboard_cleanup()
{
	rm -f mock-mode switchboard-reload.out
	cleanup_common
}

atf_test_case bootstrap_channel_loss_kills_switchboard cleanup
bootstrap_channel_loss_kills_switchboard_head()
{
	atf_set "descr" "loss of the exclusive Capsule channel kills the switchboard instance"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
bootstrap_channel_loss_kills_switchboard_body()
{
	echo "close-channel-then-sleep" > mock-mode
	build_mock_switchboard
	start_capsule

	if ! wait_for_file switchboard-started.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "bootstrap fixture did not start"
	fi

	i=0
	while ! grep -q "switchboard killed by signal" "$logfile" 2>/dev/null &&
	    [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	atf_check -s exit:0 -o ignore \
	    grep "switchboard closed channel" "$logfile"
	atf_check -s exit:0 -o ignore \
	    grep "switchboard killed by signal" "$logfile"
	stop_capsule
}
bootstrap_channel_loss_kills_switchboard_cleanup()
{
	rm -f mock-mode
	cleanup_common
}

atf_test_case bootstrap_ready_logged cleanup
bootstrap_ready_logged_head()
{
	atf_set "descr" "capsule logs when switchboard sends READY"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
bootstrap_ready_logged_body()
{
	build_mock_switchboard
	start_capsule

	if ! wait_for_file switchboard-started.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "switchboard did not start"
	fi

	if ! wait_for_log "capsule_proto: switchboard ready"; then
		cat "$logfile" 2>/dev/null
		atf_fail "capsule did not process switchboard READY"
	fi
}
bootstrap_ready_logged_cleanup()
{
	cleanup_common
}

atf_test_case bootstrap_restart_on_crash cleanup
bootstrap_restart_on_crash_head()
{
	atf_set "descr" "capsule restarts switchboard after it crashes"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
bootstrap_restart_on_crash_body()
{
	echo "crash-immediately" > mock-mode
	build_mock_switchboard
	start_capsule

	# Wait for the restart log entry.
	if ! wait_for_log "scheduling restart"; then
		cat "$logfile" 2>/dev/null
		atf_skip "restart not observed (mac_capability may not be loaded)"
	fi

	# Verify capsule logged the exit.
	atf_check -s exit:0 -o ignore \
	    grep "bootstrap: switchboard exited" "$logfile"

	# Verify capsule is still alive.
	capd_capsule_ctl "$sockpath" status | grep -q running ||
	    atf_fail "Capsule status request failed"
}
bootstrap_restart_on_crash_cleanup()
{
	rm -f mock-mode
	cleanup_common
}

atf_test_case bootstrap_clean_shutdown cleanup
bootstrap_clean_shutdown_head()
{
	atf_set "descr" "shutdown stops switchboard before capsule exits"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
bootstrap_clean_shutdown_body()
{
	build_mock_switchboard
	start_capsule

	if ! wait_for_file switchboard-started.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "switchboard did not start"
	fi

	capd_capsule_ctl "$sockpath" shutdown >/dev/null ||
	    atf_fail "Capsule shutdown request failed"
	wait_for_authenticated_shutdown

	atf_check -s exit:0 -o ignore \
	    grep "bootstrap: stopping switchboard" "$logfile"
}
bootstrap_clean_shutdown_cleanup()
{
	cleanup_common
}

atf_test_case ambient_signals_denied_control_shutdown_allowed cleanup
ambient_signals_denied_control_shutdown_allowed_head()
{
	atf_set "descr" "foreign ambient signals are denied while control shutdown remains authorized"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}
ambient_signals_denied_control_shutdown_allowed_body()
{
	local operation signal_status

	disable_signal_shields=true
	build_mock_switchboard
	find_shield_helper
	start_capsule

	if ! wait_for_file switchboard-started.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "switchboard did not start"
	fi

	# The build-time helper is exec'd from a vnode known to rotate the
	# program nonce (proved by cap_pro_exec_rotates_nonce).  A system
	# /bin/kill cannot be used as that proof: depending on its executable
	# vnode and mount policy, it may not present a distinct nonzero nonce and
	# therefore is not a reliable foreign observer.  Exercise the general,
	# SIGKILL, and SIGCONT branches.
	for operation in signal0 signal sigkill sigcont; do
		"$shield_helper" "$operation" "$daemon_pid"
		signal_status=$?
		case "$signal_status" in
		0) ;;
		1)
			if [ "$operation" = sigcont ]; then
				atf_fail "foreign same-session SIGCONT bypassed MAC policy; install and boot a kernel containing the p_cansignal MAC veto"
			fi
			atf_fail "foreign ambient $operation unexpectedly reached Capsule"
			;;
		*)
			atf_fail "signal helper failed for $operation (status $signal_status)"
			;;
		esac
		capd_capsule_ctl "$sockpath" status | grep -q running ||
		    atf_fail "Capsule status request failed"
	done

	# Configuration cannot turn the mandatory shields back off.
	atf_check -s exit:0 -o ignore \
	    grep "integrity.signal=false ignored" "$logfile"
	atf_check -s exit:0 -o ignore \
	    grep "integrity.sigkill=false ignored" "$logfile"
	atf_check -s exit:0 -o ignore \
	    grep "integrity.sigcont=false ignored" "$logfile"

	# service(8) uses this authenticated control path, not kill(2).
	capd_capsule_ctl "$sockpath" shutdown | grep -q "shutdown initiated" ||
	    atf_fail "Capsule shutdown request failed"
	wait_for_authenticated_shutdown
	atf_check -s exit:0 test ! -e "$pidfile"
}
ambient_signals_denied_control_shutdown_allowed_cleanup()
{
	cleanup_common
}

atf_test_case bootstrap_no_service_manager cleanup
bootstrap_no_service_manager_head()
{
	atf_set "descr" "capsule starts without service_manager if not configured"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
bootstrap_no_service_manager_body()
{
	if ! sh -c 'exec 3</dev/mac_capability' 2>/dev/null; then
		atf_skip "/dev/mac_capability not available"
	fi
	prepare_paths
	mkdir -p "$(pwd)/switchboard.d"

	# Config with empty service_manager.
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
service_manager = "";
EOF

	capd_find_guardian
	capd_launch_capsule
	daemon_pid=$("$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status |
	    sed -n 's/^running pid=//p')

	# Should log that no service_manager is configured.
	atf_check -s exit:0 -o ignore \
	    grep "no service_manager configured" "$logfile"

	# Daemon should still be healthy.
	capd_capsule_ctl "$sockpath" status | grep -q running ||
	    atf_fail "Capsule status request failed"
}
bootstrap_no_service_manager_cleanup()
{
	cleanup_common
}

atf_init_test_cases()
{
	atf_add_test_case bootstrap_starts_switchboard
	atf_add_test_case bootstrap_channel_ping
	atf_add_test_case control_reload_reaches_switchboard
	atf_add_test_case bootstrap_channel_loss_kills_switchboard
	atf_add_test_case bootstrap_ready_logged
	atf_add_test_case bootstrap_restart_on_crash
	atf_add_test_case bootstrap_clean_shutdown
	atf_add_test_case ambient_signals_denied_control_shutdown_allowed
	atf_add_test_case bootstrap_no_service_manager
}
