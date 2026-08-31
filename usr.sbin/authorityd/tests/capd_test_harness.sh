#
# SPDX-License-Identifier: BSD-2-Clause
#
# Canonical lifecycle harness for capability-daemon integration tests.
#

CAPD_LEASE_FD=9
capd_guardian_pid=
capd_guardian_bin=
capd_serviced_bin=
capd_authorityd_bin=

capd_paths_init()
{
	CAPD_WORK=$(pwd)
	# Units default to the unprivileged capability identity; fixtures and
	# script services must still be able to create their result markers in
	# the test work directory.
	chmod 1777 "$CAPD_WORK"
	CAPD_PIDFILE="${CAPD_WORK}/authorityd.pid"
	CAPD_CONFIG="${CAPD_WORK}/authorityd.conf"
	CAPD_AUTHORITY_SOCKET="${CAPD_WORK}/authorityd.sock"
	CAPD_SERVICED_SOCKET="${CAPD_WORK}/serviced.sock"
	CAPD_LOG="${CAPD_WORK}/authorityd.log"
	CAPD_GUARDIAN_SOCKET="${CAPD_WORK}/guardian.sock"
	CAPD_LEASE="${CAPD_WORK}/guardian.lease"
	CAPD_APPS_SYSTEM="${CAPD_WORK}/Capabilities/System"
	CAPD_APPS_USER="${CAPD_WORK}/Capabilities"
}

capd_require_stack_kmods()
{
	local kmods

	kmods="mac_capability mac_capability_isolation mac_capability_system"
	kmods="$kmods mac_capability_capprotect mac_capability_channel"
	kmods="$kmods mac_capability_coalition"
	if [ "$#" -gt 0 ]; then
		kmods="$kmods $*"
	fi
	atf_set "require.kmods" "$kmods"
}

capd_require_device()
{
	if [ ! -c /dev/mac_capability ]; then
		atf_skip "mac_capability device not available"
	fi
}

capd_find_guardian()
{
	local candidate srcdir

	if [ -n "$capd_guardian_bin" ] && [ -x "$capd_guardian_bin" ]; then
		return 0
	fi
	srcdir=$(atf_get_srcdir 2>/dev/null || pwd)
	for candidate in \
	    "${CAPD_TEST_GUARDIAN:-}" \
	    "${srcdir}/capd_test_guardian" \
	    "$(command -v capd_test_guardian 2>/dev/null)"
	do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			capd_guardian_bin=$candidate
			return 0
		fi
	done
	atf_fail "capd_test_guardian is unavailable"
}

capd_find_serviced()
{
	local candidate machine machine_arch

	if [ -n "$capd_serviced_bin" ] && [ -x "$capd_serviced_bin" ]; then
		return 0
	fi
	machine=$(uname -m)
	machine_arch=$(uname -p)
	# Prefer the source-build serviced: qualification must exercise the
	# same revision as the staged libraries.  An installed serviced from an
	# older world silently reintroduces userland ABI skew (svc_manifest
	# grew without an SHLIB_MAJOR bump, which manifested as stack-protector
	# aborts when the installed binary ran against newer libraries).
	for candidate in \
	    "${CAPD_TEST_SERVICED:-}" \
	    "/usr/obj/usr/src/${machine}.${machine_arch}/usr.sbin/serviced/serviced" \
	    /usr/libexec/serviced \
	    "$(command -v serviced 2>/dev/null)"
	do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			capd_serviced_bin=$candidate
			return 0
		fi
	done
	atf_fail "serviced is unavailable"
}

capd_find_authorityd()
{
	local candidate machine machine_arch

	if [ -n "$capd_authorityd_bin" ] && [ -x "$capd_authorityd_bin" ]; then
		return 0
	fi
	machine=$(uname -m)
	machine_arch=$(uname -p)
	# Same source-build preference as capd_find_serviced, and for the same
	# reason: an installed authorityd from an older world must not be paired
	# with the staged libraries.
	for candidate in \
	    "${CAPD_TEST_AUTHORITYD:-}" \
	    "/usr/obj/usr/src/${machine}.${machine_arch}/usr.sbin/authorityd/authorityd" \
	    "$(command -v authorityd 2>/dev/null)"
	do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			capd_authorityd_bin=$candidate
			return 0
		fi
	done
	atf_fail "authorityd is unavailable"
}

capd_stack_prepare()
{
	capd_paths_init
	capd_find_guardian
	capd_find_serviced
	mkdir -p "$CAPD_APPS_SYSTEM" "$CAPD_APPS_USER"
	cat >"$CAPD_CONFIG" <<EOF
pidfile = "$CAPD_PIDFILE";
control_socket = "$CAPD_AUTHORITY_SOCKET";
control_socket_mode = "0700";
service_manager = "$capd_serviced_bin";
EOF
	export SERVICED_BUNDLE_DIR_SYSTEM="$CAPD_APPS_SYSTEM"
	export SERVICED_BUNDLE_DIR_USER="$CAPD_APPS_USER"
	# Fixture serviced must never replay the host's /etc/rc.
	export SERVICED_SKIP_RC=1
}

capd_dump_diagnostics()
{
	if [ -n "${CAPD_GUARDIAN_SOCKET:-}" ] &&
	    [ -S "$CAPD_GUARDIAN_SOCKET" ] &&
	    [ -n "$capd_guardian_bin" ]; then
		"$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status \
		    2>/dev/null || true
	fi
	if [ -n "${CAPD_AUTHORITY_SOCKET:-}" ] &&
	    [ -S "$CAPD_AUTHORITY_SOCKET" ] &&
	    command -v authorityctl >/dev/null 2>&1; then
		authorityctl -s "$CAPD_AUTHORITY_SOCKET" status 2>/dev/null || true
	fi
	if [ -n "${CAPD_LOG:-}" ] && [ -r "$CAPD_LOG" ]; then
		tail -100 "$CAPD_LOG" >&2
	fi
	# Kernel wait-channel states show whether a lingering stack process is
	# stuck in an unkillable kernel sleep rather than merely slow.
	ps -axo pid,ppid,state,wchan,command 2>/dev/null | \
	    grep -E 'authorityd|serviced|capd_test_guardian|capd_service' | \
	    grep -v grep >&2 || true
}

capd_guardian_is_running()
{
	[ -S "$CAPD_GUARDIAN_SOCKET" ] &&
	    "$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status \
	    >/dev/null 2>&1
}

capd_launch_authority()
{
	local i

	rm -f "$CAPD_GUARDIAN_SOCKET" "$CAPD_LEASE"
	mkfifo -m 0600 "$CAPD_LEASE" || atf_fail "cannot create guardian lease"
	# Open read/write before launch so neither side blocks.  Close this inherited
	# descriptor in the guardian process; only the test shell owns the writer.
	exec 9<>"$CAPD_LEASE"
	capd_find_authorityd
	"$capd_guardian_bin" run -l "$CAPD_LEASE" \
	    -s "$CAPD_GUARDIAN_SOCKET" -- \
	    "$capd_authorityd_bin" -d -f "$CAPD_CONFIG" >"$CAPD_LOG" 2>&1 9>&- &
	capd_guardian_pid=$!

	i=0
	while ! capd_guardian_is_running && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if ! capd_guardian_is_running; then
		capd_dump_diagnostics
		atf_fail "guardian did not launch Authority"
	fi

	i=0
	while [ ! -S "$CAPD_AUTHORITY_SOCKET" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -S "$CAPD_AUTHORITY_SOCKET" ]; then
		capd_dump_diagnostics
		atf_fail "Authority did not create its control socket"
	fi
}

capd_start_stack()
{
	local i

	capd_require_device
	capd_find_guardian
	capd_find_serviced
	if [ -z "${CAPD_CONFIG:-}" ] || [ ! -r "$CAPD_CONFIG" ]; then
		capd_stack_prepare
	fi
	capd_launch_authority

	i=0
	while ! grep -q "serviced ready" "$CAPD_LOG" 2>/dev/null &&
	    [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if ! grep -q "serviced ready" "$CAPD_LOG" 2>/dev/null; then
		capd_dump_diagnostics
		atf_fail "serviced did not become ready"
	fi
}

capd_wait_guardian_exit()
{
	local i limit

	limit=$1
	i=0
	while capd_guardian_is_running && [ "$i" -lt "$limit" ]; do
		i=$((i + 1))
		sleep 0.1
	done
	! capd_guardian_is_running
}

capd_close_lease()
{

	exec 9>&-
}

capd_stop_stack()
{
	local graceful

	# Socket FILES may be stale leftovers of a killed process group; only
	# a live guardian (or an authorityd that answers its socket) matters.
	if ! capd_guardian_is_running; then
		capd_close_lease
		if [ -n "$capd_guardian_pid" ]; then
			wait "$capd_guardian_pid" 2>/dev/null || true
			capd_guardian_pid=
		fi
		if [ -S "$CAPD_AUTHORITY_SOCKET" ] &&
		    command -v authorityctl >/dev/null 2>&1; then
			authorityctl -s "$CAPD_AUTHORITY_SOCKET" shutdown \
			    >/dev/null 2>&1 || true
		fi
		return 0
	fi
	graceful=0
	if [ -S "$CAPD_AUTHORITY_SOCKET" ] &&
	    command -v authorityctl >/dev/null 2>&1; then
		if authorityctl -s "$CAPD_AUTHORITY_SOCKET" shutdown \
		    >/dev/null 2>&1; then
			graceful=1
		fi
	fi
	if capd_wait_guardian_exit 350; then
		capd_close_lease
		if [ -n "$capd_guardian_pid" ]; then
			wait "$capd_guardian_pid" 2>/dev/null || true
			capd_guardian_pid=
		fi
		[ "$graceful" -eq 1 ]
		return
	fi

	capd_dump_diagnostics
	if capd_guardian_is_running; then
		"$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" kill \
		    >/dev/null 2>&1 || true
	fi
	if ! capd_wait_guardian_exit 50; then
		echo "guardian could not terminate the Authority stack" >&2
		return 1
	fi
	capd_close_lease
	if [ -n "$capd_guardian_pid" ]; then
		wait "$capd_guardian_pid" 2>/dev/null || true
		capd_guardian_pid=
	fi
	return 1
}

capd_cleanup_stack()
{
	local i

	capd_paths_init
	capd_find_guardian
	if [ -S "$CAPD_AUTHORITY_SOCKET" ] &&
	    command -v authorityctl >/dev/null 2>&1; then
		authorityctl -s "$CAPD_AUTHORITY_SOCKET" shutdown \
		    >/dev/null 2>&1 || true
	fi
	# Judge the guardian by liveness, never by socket-file existence:
	# the test-body process group is killed when the body exits, which
	# strips the guardian of its atexit socket removal and leaves a
	# stale file behind.
	if capd_guardian_is_running; then
		"$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" kill \
		    >/dev/null 2>&1 || true
	fi
	i=0
	while capd_guardian_is_running && [ "$i" -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if capd_guardian_is_running; then
		capd_dump_diagnostics
		return 1
	fi
	rm -rf "$CAPD_PIDFILE" "$CAPD_CONFIG" "$CAPD_AUTHORITY_SOCKET" \
	    "$CAPD_SERVICED_SOCKET" "$CAPD_GUARDIAN_SOCKET" "$CAPD_LEASE" \
	    "$CAPD_LOG" "${CAPD_WORK}/Capabilities"
	return 0
}
