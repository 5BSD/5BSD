#
# SPDX-License-Identifier: BSD-2-Clause
#

guardian_pid=
guardian_bin=
control=

find_guardian()
{
	guardian_bin="$(atf_get_srcdir)/capd_test_guardian"
	if [ ! -x "$guardian_bin" ]; then
		atf_skip "capd_test_guardian is not built"
	fi
}

start_guarded_sleep()
{
	local i

	find_guardian
	control="$(pwd)/guardian.sock"
	mkfifo -m 0600 lease
	exec 9<>lease
	"$guardian_bin" run -l "$(pwd)/lease" -s "$control" -- \
	    /bin/sleep 300 >guardian.log 2>&1 9>&- &
	guardian_pid=$!
	i=0
	while [ ! -S "$control" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.02
	done
	if [ ! -S "$control" ]; then
		cat guardian.log >&2
		atf_fail "guardian did not create its control socket"
	fi
}

cleanup_guardian()
{
	if [ -n "$control" ] && [ -S "$control" ] &&
	    [ -n "$guardian_bin" ]; then
		"$guardian_bin" ctl -s "$control" kill >/dev/null 2>&1 || true
	fi
	exec 9>&-
	if [ -n "$guardian_pid" ]; then
		wait "$guardian_pid" 2>/dev/null || true
	fi
	rm -f guardian.sock lease guardian.log
}

atf_test_case explicit_kill cleanup
explicit_kill_head()
{
	atf_set "descr" "guardian terminates its exact child through procdesc authority"
}
explicit_kill_body()
{
	local child status

	start_guarded_sleep
	child=$("$guardian_bin" ctl -s "$control" status |
	    sed -n 's/^running pid=//p')
	case "$child" in
	''|*[!0-9]*) atf_fail "guardian returned an invalid child PID" ;;
	esac
	atf_check -s exit:0 -o inline:"terminating\n" \
	    "$guardian_bin" ctl -s "$control" kill
	wait "$guardian_pid"
	status=$?
	guardian_pid=
	exec 9>&-
	atf_check_equal "$status" 137
	atf_check -s not-exit:0 -e ignore ps -p "$child" -o pid=
	atf_check_equal "$(test -e "$control"; echo $?)" 1
}
explicit_kill_cleanup()
{
	cleanup_guardian
}

atf_test_case lease_loss cleanup
lease_loss_head()
{
	atf_set "descr" "closing the test lease kills and reaps the guarded child"
}
lease_loss_body()
{
	local child status

	start_guarded_sleep
	child=$("$guardian_bin" ctl -s "$control" status |
	    sed -n 's/^running pid=//p')
	exec 9>&-
	wait "$guardian_pid"
	status=$?
	guardian_pid=
	atf_check_equal "$status" 137
	atf_check -s not-exit:0 -e ignore ps -p "$child" -o pid=
	atf_check_equal "$(test -e "$control"; echo $?)" 1
}
lease_loss_cleanup()
{
	cleanup_guardian
}

atf_test_case guardian_signal cleanup
guardian_signal_head()
{
	atf_set "descr" "terminating the guardian first terminates its guarded child"
}
guardian_signal_body()
{
	local child status

	start_guarded_sleep
	child=$("$guardian_bin" ctl -s "$control" status |
	    sed -n 's/^running pid=//p')
	kill -TERM "$guardian_pid"
	wait "$guardian_pid"
	status=$?
	guardian_pid=
	exec 9>&-
	atf_check_equal "$status" 137
	atf_check -s not-exit:0 -e ignore ps -p "$child" -o pid=
}
guardian_signal_cleanup()
{
	cleanup_guardian
}

atf_init_test_cases()
{
	atf_add_test_case explicit_kill
	atf_add_test_case lease_loss
	atf_add_test_case guardian_signal
}
