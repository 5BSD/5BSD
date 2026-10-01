#
# SPDX-License-Identifier: BSD-2-Clause
#
# Launch-level verification of the manifest launch-policy keys: what a unit
# actually observes (or what switchboard actually does) after it is launched.
#

_helpers="$(dirname "$0")/test_helpers.sh"
if [ ! -f "$_helpers" ]; then
	_helpers="/usr/src/usr.sbin/switchboard/tests/test_helpers.sh"
fi
. "$_helpers"

# Fixture result files are written by the unit under its own identity.
touch_open()
{
	local f
	for f in "$@"; do
		: > "$f"
		chmod 666 "$f"
	done
}

# Wait until file $1 has at least $2 lines (default 1), up to $3 seconds.
wait_for_lines()
{
	local file="$1" want="${2:-1}" max i
	max=$(( ${3:-15} * 10 ))
	i=0
	while [ "$(wc -l < "$file" 2>/dev/null || echo 0)" -lt "$want" ] &&
	    [ "$i" -lt "$max" ]; do
		i=$((i + 1))
		sleep 0.1
	done
	[ "$(wc -l < "$file" 2>/dev/null || echo 0)" -ge "$want" ]
}

report_value()
{
	sed -n "s/^$1=//p" "$2"
}

fail_with_log()
{
	cat "$logfile" 2>/dev/null
	atf_fail "$1"
}

# ===================================================================
# limits / umask / nice
# ===================================================================

atf_test_case limits_umask_nice_applied cleanup
limits_umask_nice_applied_head()
{
	atf_set "descr" \
	    "limits (soft/hard nofile, data, core), umask and nice reach the launched unit"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
limits_umask_nice_applied_body()
{
	prepare_paths
	touch_open launch.out
	make_fixture_svc system lim \
	    'limits { nofile { soft = 100; hard = 200; } data = 2147483648; core = 0; }
	    umask = "0027"; nice = -3;' \
	    launch-report "${WORK}/launch.out"
	start_stack
	wait_for_file launch.out || fail_with_log "unit did not report"

	[ "$(report_value nofile_soft launch.out)" = 100 ] ||
	    atf_fail "nofile soft: $(cat launch.out)"
	[ "$(report_value nofile_hard launch.out)" = 200 ] ||
	    atf_fail "nofile hard: $(cat launch.out)"
	[ "$(report_value data_soft launch.out)" = 2147483648 ] ||
	    atf_fail "data soft: $(cat launch.out)"
	[ "$(report_value data_hard launch.out)" = 2147483648 ] ||
	    atf_fail "data hard: $(cat launch.out)"
	[ "$(report_value core_soft launch.out)" = 0 ] ||
	    atf_fail "core soft: $(cat launch.out)"
	[ "$(report_value core_hard launch.out)" = 0 ] ||
	    atf_fail "core hard: $(cat launch.out)"
	[ "$(report_value umask launch.out)" = 0027 ] ||
	    atf_fail "umask: $(cat launch.out)"
	[ "$(report_value nice launch.out)" = -3 ] ||
	    atf_fail "system bundle nice -3 not applied: $(cat launch.out)"
}
limits_umask_nice_applied_cleanup()
{
	cleanup_common
	rm -f launch.out
}

atf_test_case nice_clamped_for_user_bundle cleanup
nice_clamped_for_user_bundle_head()
{
	atf_set "descr" \
	    "a non-system bundle cannot raise its priority: negative nice is clamped to 0"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
nice_clamped_for_user_bundle_body()
{
	prepare_paths
	touch_open launch.out
	make_fixture_svc user nicer 'nice = -5;' \
	    launch-report "${WORK}/launch.out"
	start_stack
	wait_for_file launch.out || fail_with_log "unit did not report"
	[ "$(report_value nice launch.out)" = 0 ] ||
	    atf_fail "user bundle nice not clamped to 0: $(cat launch.out)"
}
nice_clamped_for_user_bundle_cleanup()
{
	cleanup_common
	rm -f launch.out
}

atf_test_case nice_positive_honoured_for_user_bundle cleanup
nice_positive_honoured_for_user_bundle_head()
{
	atf_set "descr" "a non-system bundle may lower its own priority"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
nice_positive_honoured_for_user_bundle_body()
{
	prepare_paths
	touch_open launch.out
	make_fixture_svc user nicep 'nice = 7;' \
	    launch-report "${WORK}/launch.out"
	start_stack
	wait_for_file launch.out || fail_with_log "unit did not report"
	[ "$(report_value nice launch.out)" = 7 ] ||
	    atf_fail "positive nice not applied: $(cat launch.out)"
}
nice_positive_honoured_for_user_bundle_cleanup()
{
	cleanup_common
	rm -f launch.out
}

# ===================================================================
# restart policy: throttle, on-crash
# ===================================================================

# Gap in milliseconds between the first two launches recorded in $1.
first_gap_ms()
{
	awk 'NR == 1 { a = $1 } NR == 2 { print $1 - a; exit }' "$1"
}

atf_test_case throttle_delays_restart cleanup
throttle_delays_restart_head()
{
	atf_set "descr" \
	    "throttle sets a floor on the delay before a crashed unit restarts"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
throttle_delays_restart_body()
{
	local gap

	prepare_paths
	touch_open slow.counts
	make_fixture_svc system slow \
	    'restart = "on-crash"; throttle = 5; max_failures = 10;' \
	    launch-count "${WORK}/slow.counts" signal
	start_stack
	wait_for_lines slow.counts 2 30 ||
	    fail_with_log "throttled unit was not restarted"
	gap=$(first_gap_ms slow.counts)
	[ "$gap" -ge 4900 ] ||
	    atf_fail "restart came ${gap}ms after the crash; throttle is 5s"
}
throttle_delays_restart_cleanup()
{
	cleanup_common
	rm -f slow.counts
}

atf_test_case default_restart_delay_is_short cleanup
default_restart_delay_is_short_head()
{
	atf_set "descr" \
	    "without throttle the first crash restart is not delayed by the throttle floor"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
default_restart_delay_is_short_body()
{
	local gap

	prepare_paths
	touch_open fast.counts
	make_fixture_svc system fast \
	    'restart = "on-crash"; max_failures = 10;' \
	    launch-count "${WORK}/fast.counts" signal
	start_stack
	wait_for_lines fast.counts 2 30 ||
	    fail_with_log "unit was not restarted"
	gap=$(first_gap_ms fast.counts)
	[ "$gap" -lt 4500 ] ||
	    atf_fail "default restart took ${gap}ms"
}
default_restart_delay_is_short_cleanup()
{
	cleanup_common
	rm -f fast.counts
}

atf_test_case on_crash_restarts_only_after_signal cleanup
on_crash_restarts_only_after_signal_head()
{
	atf_set "descr" \
	    "restart=on-crash restarts a signalled unit but not one that exited 0 or 1"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
on_crash_restarts_only_after_signal_body()
{
	prepare_paths
	touch_open sig.counts ex0.counts ex1.counts
	make_fixture_svc system sig \
	    'restart = "on-crash"; max_failures = 10;' \
	    launch-count "${WORK}/sig.counts" signal
	make_fixture_svc system ex0 \
	    'restart = "on-crash"; max_failures = 10;' \
	    launch-count "${WORK}/ex0.counts" exit0
	make_fixture_svc system ex1 \
	    'restart = "on-crash"; max_failures = 10;' \
	    launch-count "${WORK}/ex1.counts" exit1
	start_stack
	wait_for_lines sig.counts 2 30 ||
	    fail_with_log "signalled unit was not restarted"
	wait_for_lines ex0.counts 1 || fail_with_log "ex0 never launched"
	wait_for_lines ex1.counts 1 || fail_with_log "ex1 never launched"
	# Outlast the default restart delay so a wrongful restart would show.
	sleep 6
	[ "$(wc -l < ex0.counts)" -eq 1 ] ||
	    atf_fail "unit that exited 0 was restarted: $(cat ex0.counts)"
	[ "$(wc -l < ex1.counts)" -eq 1 ] ||
	    atf_fail "unit that exited 1 was restarted: $(cat ex1.counts)"
}
on_crash_restarts_only_after_signal_cleanup()
{
	cleanup_common
	rm -f sig.counts ex0.counts ex1.counts
}

# ===================================================================
# socket activation: mode / owner / group
# ===================================================================

atf_test_case socket_mode_owner_group cleanup
socket_mode_owner_group_head()
{
	atf_set "descr" \
	    "activation socket path takes the declared mode, owner and group; a connect launches the unit"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
socket_mode_owner_group_body()
{
	local sock

	prepare_paths
	sock="${WORK}/act.sock"
	touch_open launch.out
	make_fixture_svc system actsock \
	    "activation { socket { name = \"t\"; listen = \"unix:${sock}\"; mode = \"0660\"; owner = \"nobody\"; group = \"wheel\"; } }" \
	    launch-report "${WORK}/launch.out"
	start_stack
	i=0
	while [ ! -S "$sock" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	[ -S "$sock" ] || fail_with_log "activation socket was not created"
	[ "$(stat -f '%Lp %Su %Sg' "$sock")" = "660 nobody wheel" ] ||
	    atf_fail "socket is $(stat -f '%Lp %Su %Sg' "$sock")"
	: | nc -U -w 1 "$sock" >/dev/null 2>&1 || true
	wait_for_file launch.out ||
	    fail_with_log "connect to the socket did not launch the unit"
}
socket_mode_owner_group_cleanup()
{
	cleanup_common
	rm -f launch.out act.sock
}

atf_init_test_cases()
{
	atf_add_test_case limits_umask_nice_applied
	atf_add_test_case nice_clamped_for_user_bundle
	atf_add_test_case nice_positive_honoured_for_user_bundle
	atf_add_test_case throttle_delays_restart
	atf_add_test_case default_restart_delay_is_short
	atf_add_test_case on_crash_restarts_only_after_signal
	atf_add_test_case socket_mode_owner_group
}
