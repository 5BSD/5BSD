#
PATH="$(dirname "$(atf_get_srcdir)"):${PATH}"
export PATH
# SPDX-License-Identifier: BSD-2-Clause
#

# Lifecycle cases must not consume the installed machine's policy.
prepare_lifecycle()
{
	capsule_bin=$(atf_config_get capsule capsule)
	conffile="$(pwd)/lifecycle.conf"
	printf '%s\n' '# Test-local lifecycle configuration.' > "$conffile"
	chmod 600 "$conffile"
}

atf_test_case foreground_lifecycle cleanup
foreground_lifecycle_head()
{
	atf_set "descr" "capsule starts in foreground test mode and removes pidfile on stop"
}
foreground_lifecycle_body()
{
	local pid pidfile

	prepare_lifecycle
	pidfile="$(pwd)/capsule.pid"

	atf_check -s not-exit:0 -e match:"usage: capsule" \
	    "$capsule_bin" -T -f "$conffile" unexpected

	"$capsule_bin" -T -f "$conffile" -p "$pidfile" &
	pid=$!

	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s exit:0 test "$(cat "$pidfile")" = "$pid"
	atf_check -s exit:0 kill -HUP "$pid"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
	rc=$?
	atf_check_equal 0 "$rc"
	atf_check -s exit:1 test -e "$pidfile"
}
foreground_lifecycle_cleanup()
{
	if [ -f capsule.pid ]; then
		pid="$(cat capsule.pid 2>/dev/null || true)"
		if [ -n "$pid" ]; then
			kill "$pid" 2>/dev/null || true
		fi
		rm -f capsule.pid
	fi
}

atf_test_case duplicate_pidfile cleanup
duplicate_pidfile_head()
{
	atf_set "descr" "capsule refuses to start when pidfile is locked"
}
duplicate_pidfile_body()
{
	local pid pidfile

	prepare_lifecycle
	pidfile="$(pwd)/capsule.pid"
	"$capsule_bin" -T -f "$conffile" -p "$pidfile" &
	pid=$!

	atf_check -s exit:0 -o ignore sh -c \
	    "i=0; while [ ! -s '$pidfile' ] && [ \$i -lt 50 ]; do i=\$((i + 1)); sleep 0.1; done; test -s '$pidfile'"
	atf_check -s not-exit:0 -e match:"already running" \
	    "$capsule_bin" -T -f "$conffile" -p "$pidfile"
	atf_check -s exit:0 kill -TERM "$pid"
	wait "$pid"
	rc=$?
	atf_check_equal 0 "$rc"
}
duplicate_pidfile_cleanup()
{
	if [ -f capsule.pid ]; then
		pid="$(cat capsule.pid 2>/dev/null || true)"
		if [ -n "$pid" ]; then
			kill "$pid" 2>/dev/null || true
		fi
		rm -f capsule.pid
	fi
}

atf_init_test_cases()
{
	atf_add_test_case foreground_lifecycle
	atf_add_test_case duplicate_pidfile
}
