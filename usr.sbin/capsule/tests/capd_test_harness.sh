#
# SPDX-License-Identifier: BSD-2-Clause
#
# Canonical lifecycle harness for capability-daemon integration tests.
#

CAPD_LEASE_FD=9
capd_guardian_pid=
capd_guardian_bin=
capd_serviced_bin=
capd_capsule_bin=

capd_paths_init()
{
	CAPD_WORK=$(pwd)
	# Units default to the unprivileged capability identity; fixtures and
	# script services must still be able to create their result markers in
	# the test work directory.
	chmod 1777 "$CAPD_WORK"
	CAPD_PIDFILE="${CAPD_WORK}/capsule.pid"
	CAPD_CONFIG="${CAPD_WORK}/capsule.conf"
	CAPD_CAPSULE_SOCKET="${CAPD_WORK}/capsule.sock"
	CAPD_SERVICED_SOCKET="${CAPD_WORK}/serviced.sock"
	CAPD_LOG="${CAPD_WORK}/capsule.log"
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

capd_find_capsule()
{
	local candidate machine machine_arch

	if [ -n "$capd_capsule_bin" ] && [ -x "$capd_capsule_bin" ]; then
		return 0
	fi
	machine=$(uname -m)
	machine_arch=$(uname -p)
	# Same source-build preference as capd_find_serviced, and for the same
	# reason: an installed capsule from an older world must not be paired
	# with the staged libraries.
	for candidate in \
	    "${CAPD_TEST_CAPSULE:-}" \
	    "/usr/obj/usr/src/${machine}.${machine_arch}/usr.sbin/capsule/capsule" \
	    "$(command -v capsule 2>/dev/null)"
	do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			capd_capsule_bin=$candidate
			return 0
		fi
	done
	atf_fail "capsule is unavailable"
}

capd_stack_prepare()
{
	capd_paths_init
	capd_find_guardian
	capd_find_serviced
	mkdir -p "$CAPD_APPS_SYSTEM" "$CAPD_APPS_USER"
	cat >"$CAPD_CONFIG" <<EOF
pidfile = "$CAPD_PIDFILE";
control_socket = "$CAPD_CAPSULE_SOCKET";
control_socket_mode = "0700";
service_manager = "$capd_serviced_bin";
EOF
	export SERVICED_BUNDLE_DIR_SYSTEM="$CAPD_APPS_SYSTEM"
	export SERVICED_BUNDLE_DIR_USER="$CAPD_APPS_USER"
	# Fixture serviced must never replay the host's /etc/rc.
	export SERVICED_SKIP_RC=1
}

# Test-only access to capsule's private root control socket.  The public
# capsulectl(8) intentionally uses the capability plane and has no socket
# override, while isolated stack tests must address their own daemon instance.
capd_capsule_ctl()
{
	local op reply status verb

	reply=".capd-control-reply.$$"
	verb=$2
	case "$verb" in
	shutdown) op=1 ;;
	status) op=2 ;;
	reload) op=3 ;;
	*) return 64 ;;
	esac
	{
		printf '\001\000\000\000'
		printf "\\$(printf '%03o' "$op")\\000\\000\\000"
		printf '\000\000\000\000\000\000\000\000'
	} | nc -U "$1" >"$reply" || {
		rm -f "$reply"
		return 1
	}
	status=$(od -A n -t u4 -N 4 "$reply" | awk '{ print $1 }')
	if [ "$status" != 0 ]; then
		rm -f "$reply"
		return 1
	fi
	case "$verb" in
	shutdown) echo "capsule: shutdown initiated" ;;
	status)
		echo "capsule: running"
		dd if="$reply" bs=16 skip=1 2>/dev/null
		;;
	reload) dd if="$reply" bs=16 skip=1 2>/dev/null ;;
	esac
	rm -f "$reply"
}

capd_dump_diagnostics()
{
	if [ -n "${CAPD_GUARDIAN_SOCKET:-}" ] &&
	    [ -S "$CAPD_GUARDIAN_SOCKET" ] &&
	    [ -n "$capd_guardian_bin" ]; then
		"$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status \
		    2>/dev/null || true
	fi
	if [ -n "${CAPD_CAPSULE_SOCKET:-}" ] &&
	    [ -S "$CAPD_CAPSULE_SOCKET" ]; then
		capd_capsule_ctl "$CAPD_CAPSULE_SOCKET" status 2>/dev/null || true
	fi
	if [ -n "${CAPD_LOG:-}" ] && [ -r "$CAPD_LOG" ]; then
		tail -100 "$CAPD_LOG" >&2
	fi
	# Kernel wait-channel states show whether a lingering stack process is
	# stuck in an unkillable kernel sleep rather than merely slow.
	ps -axo pid,ppid,state,wchan,command 2>/dev/null | \
	    grep -E 'capsule|serviced|capd_test_guardian|capd_service' | \
	    grep -v grep >&2 || true
}

capd_guardian_is_running()
{
	[ -S "$CAPD_GUARDIAN_SOCKET" ] &&
	    "$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status \
	    >/dev/null 2>&1
}

capd_launch_capsule()
{
	local i

	rm -f "$CAPD_GUARDIAN_SOCKET" "$CAPD_LEASE"
	mkfifo -m 0600 "$CAPD_LEASE" || atf_fail "cannot create guardian lease"
	# Open read/write before launch so neither side blocks.  Close this inherited
	# descriptor in the guardian process; only the test shell owns the writer.
	exec 9<>"$CAPD_LEASE"
	capd_find_capsule
	"$capd_guardian_bin" run -l "$CAPD_LEASE" \
	    -s "$CAPD_GUARDIAN_SOCKET" -- \
	    "$capd_capsule_bin" -d -f "$CAPD_CONFIG" >"$CAPD_LOG" 2>&1 9>&- &
	capd_guardian_pid=$!

	i=0
	while ! capd_guardian_is_running && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if ! capd_guardian_is_running; then
		capd_dump_diagnostics
		atf_fail "guardian did not launch Capsule"
	fi

	i=0
	while [ ! -S "$CAPD_CAPSULE_SOCKET" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -S "$CAPD_CAPSULE_SOCKET" ]; then
		capd_dump_diagnostics
		atf_fail "Capsule did not create its control socket"
	fi
}

capd_start_stack()
{
	local i

	# A test-local Capsule stack must never replay the host's rc(8).
	# Some suites provide their own readable config and bypass prepare().
	export SERVICED_SKIP_RC=1

	capd_require_device
	capd_find_guardian
	capd_find_serviced
	if [ -z "${CAPD_CONFIG:-}" ] || [ ! -r "$CAPD_CONFIG" ]; then
		capd_stack_prepare
	fi
	capd_launch_capsule

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
	# a live guardian (or an capsule that answers its socket) matters.
	if ! capd_guardian_is_running; then
		capd_close_lease
		if [ -n "$capd_guardian_pid" ]; then
			wait "$capd_guardian_pid" 2>/dev/null || true
			capd_guardian_pid=
		fi
		if [ -S "$CAPD_CAPSULE_SOCKET" ]; then
			capd_capsule_ctl "$CAPD_CAPSULE_SOCKET" shutdown \
			    >/dev/null 2>&1 || true
		fi
		return 0
	fi
	graceful=0
	if [ -S "$CAPD_CAPSULE_SOCKET" ]; then
		if capd_capsule_ctl "$CAPD_CAPSULE_SOCKET" shutdown \
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
		echo "guardian could not terminate the Capsule stack" >&2
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
	if [ -S "$CAPD_CAPSULE_SOCKET" ]; then
		capd_capsule_ctl "$CAPD_CAPSULE_SOCKET" shutdown \
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
	rm -rf "$CAPD_PIDFILE" "$CAPD_CONFIG" "$CAPD_CAPSULE_SOCKET" \
	    "$CAPD_SERVICED_SOCKET" "$CAPD_GUARDIAN_SOCKET" "$CAPD_LEASE" \
	    "$CAPD_LOG" "${CAPD_WORK}/Capabilities"
	return 0
}
