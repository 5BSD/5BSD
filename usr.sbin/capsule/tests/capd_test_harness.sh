#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Canonical lifecycle harness for capability-daemon integration tests.
#

CAPD_LEASE_FD=9
capd_guardian_pid=
capd_guardian_bin=
capd_lookup_exec_bin=
capd_switchboard_bin=
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
	CAPD_SWITCHBOARD_SOCKET="${CAPD_WORK}/switchboard.sock"
	CAPD_LOG="${CAPD_WORK}/capsule.log"
	CAPD_GUARDIAN_SOCKET="${CAPD_WORK}/guardian.sock"
	CAPD_LEASE="${CAPD_WORK}/guardian.lease"
	CAPD_APPS_SYSTEM="${CAPD_WORK}/Capabilities/System"
	CAPD_APPS_USER="${CAPD_WORK}/Capabilities"
}

# ----------------------------------------------------------------------------
# Authority issuer.
#
# Only PID 1 may create the protected authority issuer (CAP_AUTH_ISSUER_CREATE),
# so a test-local Capsule normally cannot issue unit authority and its
# switchboard fails every unit launch.  A kernel built with
# options MAC_CAPABILITY_TEST_PERMISSIVE (GENERIC-TEST) and booted with
# kern.mac_capability.test_issuer=1 lets a test-local Capsule create a test
# issuer until PID 1 anchors the boot, loudly logged as TEST MODE; that is the
# stack tier these cases run in, plane off (docs/book/src/develop/testing.md;
# mac_capability(4)).  On any other kernel, cases that require launched units
# check this prerequisite before starting their stack and skip with
# DEFERRED_STACK_TIER, which the runner counts as not a pass; on the stack
# tier (atf config stack_tier=1) the same check fails instead.  Cases that
# need no launched unit still run.  A daemon log message must never turn an
# assertion into a skip.
# ----------------------------------------------------------------------------

CAPD_ISSUER_SKIP="DEFERRED_STACK_TIER: requires a unit issuer: a test-local Capsule off PID 1 needs a GENERIC-TEST kernel booted plane-off with kern.mac_capability.test_issuer=1"

# True when a test-local Capsule gets a test issuer: the switch is on and
# PID 1 has not anchored the boot.
capd_test_relax()
{
	[ "$(sysctl -n kern.mac_capability.test_issuer 2>/dev/null)" = 1 ] &&
	    [ "$(sysctl -n kern.mac_capability.test_issuer_state 2>/dev/null)" != anchored ]
}

# Call only from cases that require successful unit authority issuance.
# Check the environment before launching processes, never after an assertion.
capd_require_unit_issuer()
{
	capd_test_relax && return 0
	if [ "$(atf_config_get stack_tier 0)" = 1 ]; then
		atf_fail "the stack tier has no unit issuer:" \
		    "kern.mac_capability.test_issuer=$(sysctl -n kern.mac_capability.test_issuer 2>&1)" \
		    "state=$(sysctl -n kern.mac_capability.test_issuer_state 2>&1)"
	fi
	atf_skip "$CAPD_ISSUER_SKIP"
}

# After a stack start on a kernel that gives test issuers: the test-local Capsule
# must have created one, which the kernel logs with its pid.  Print the
# issuer's identity; fail at once without one, never running on into
# secondary "service did not start" failures.
capd_expect_test_issuer()
{
	local i pid line

	capd_test_relax || return 0
	pid=$("$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status 2>/dev/null |
	    sed -n 's/^running pid=//p')
	[ -n "$pid" ] || atf_fail "cannot read the test-local Capsule's pid"
	i=0
	while [ "$i" -lt 100 ]; do
		line=$(dmesg -a 2>/dev/null | grep -a "mac_capability: TEST MODE: pid $pid ([^)]*) created authority issuer " | tail -n 1)
		[ -z "$line" ] || break
		i=$((i + 1))
		sleep 0.1
	done
	if [ -z "$line" ]; then
		capd_dump_diagnostics
		atf_fail "test-local Capsule did not create a relaxed issuer (pid $pid)"
	fi
	# A reused pid could match an older stack's line: the count must have
	# grown since this Capsule was launched.
	[ "$(sysctl -n kern.mac_capability.test_issuers)" -gt "${CAPD_TEST_ISSUERS_BEFORE:-0}" ] ||
	    atf_fail "no test issuer was created since the test-local Capsule (pid $pid) was launched"
	echo "test issuer: $(echo "$line" | sed -n 's/.* created authority issuer \([0-9]*\) off PID 1.*/\1/p') (Capsule pid $pid)"
}

# The test issuers still alive; empty on a kernel without them.
capd_test_issuers_live()
{
	sysctl -n kern.mac_capability.test_issuers_live 2>/dev/null
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
	# A test-local stack needs its own claim on the control device.  Under a
	# live plane PID 1 already holds it, so the private Capsule would exit
	# on EPERM: that is the environment, not a regression.  Test this first:
	# the claim also hides the node from stat(2) unless the image boots with
	# kern.mac_capability_isolation.enforce=0, and the skip should name the
	# real cause.
	if [ "$(ps -o comm= -p 1 2>/dev/null)" = "capsule" ]; then
		atf_skip "DEFERRED_PLANEOFF_TIER: mac_capability device is" \
		    "claimed by the live plane (test-local stack; run plane-off)"
	fi
	if [ ! -c /dev/mac_capability ]; then
		atf_skip "mac_capability device not available"
	fi
}

capd_find_guardian()
{
	local candidate selected srcdir

	# Explicit qualification inputs must never fall back to another revision.
	selected=$(atf_config_get capd_guardian "${CAPD_TEST_GUARDIAN:-}")
	if atf_config_has capd_guardian || [ -n "$selected" ]; then
		[ -x "$selected" ] || atf_fail "selected guardian is not executable: $selected"
		capd_guardian_bin=$selected
		return 0
	fi

	if [ -n "$capd_guardian_bin" ] && [ -x "$capd_guardian_bin" ]; then
		return 0
	fi
	srcdir=$(atf_get_srcdir 2>/dev/null || pwd)
	for candidate in \
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

capd_find_lookup_exec()
{
	local candidate srcdir

	if [ -n "$capd_lookup_exec_bin" ] && [ -x "$capd_lookup_exec_bin" ]; then
		return 0
	fi
	srcdir=$(atf_get_srcdir 2>/dev/null || pwd)
	for candidate in \
	    "${srcdir}/capd_lookup_exec" \
	    "$(command -v capd_lookup_exec 2>/dev/null)"
	do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			capd_lookup_exec_bin=$candidate
			return 0
		fi
	done
	atf_fail "capd_lookup_exec is unavailable"
}

capd_find_switchboard()
{
	local candidate selected machine machine_arch

	# Explicit qualification inputs must never fall back to another revision.
	selected=$(atf_config_get capd_switchboard "${CAPD_TEST_SWITCHBOARD:-}")
	if atf_config_has capd_switchboard || [ -n "$selected" ]; then
		[ -x "$selected" ] || atf_fail "selected switchboard is not executable: $selected"
		capd_switchboard_bin=$selected
		return 0
	fi

	if [ -n "$capd_switchboard_bin" ] && [ -x "$capd_switchboard_bin" ]; then
		return 0
	fi
	machine=$(uname -m)
	machine_arch=$(uname -p)
	# Prefer the source-build switchboard: qualification must exercise the
	# same revision as the staged libraries.
	for candidate in \
	    "/usr/obj/usr/src/${machine}.${machine_arch}/usr.sbin/switchboard/switchboard" \
	    /usr/libexec/switchboard \
	    "$(command -v switchboard 2>/dev/null)"
	do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			capd_switchboard_bin=$candidate
			return 0
		fi
	done
	atf_fail "switchboard is unavailable"
}

capd_find_capsule()
{
	local candidate selected machine machine_arch

	# Explicit qualification inputs must never fall back to another revision.
	selected=$(atf_config_get capd_capsule "${CAPD_TEST_CAPSULE:-}")
	if atf_config_has capd_capsule || [ -n "$selected" ]; then
		[ -x "$selected" ] || atf_fail "selected capsule is not executable: $selected"
		capd_capsule_bin=$selected
		return 0
	fi

	if [ -n "$capd_capsule_bin" ] && [ -x "$capd_capsule_bin" ]; then
		return 0
	fi
	machine=$(uname -m)
	machine_arch=$(uname -p)
	# Same source-build preference as capd_find_switchboard, and for the same
	# reason: an installed capsule from an older world must not be paired
	# with the staged libraries.
	for candidate in \
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
	capd_find_switchboard
	mkdir -p "$CAPD_APPS_SYSTEM" "$CAPD_APPS_USER"
	cat >"$CAPD_CONFIG" <<EOF
pidfile = "$CAPD_PIDFILE";
control_socket = "$CAPD_CAPSULE_SOCKET";
control_socket_mode = "0700";
lookup_route_export = true;
service_manager = "$capd_switchboard_bin";
EOF
	export SWITCHBOARD_BUNDLE_DIR_SYSTEM="$CAPD_APPS_SYSTEM"
	export SWITCHBOARD_BUNDLE_DIR_USER="$CAPD_APPS_USER"
	# Fixture switchboard must never replay the host's /etc/rc.
	export SWITCHBOARD_SKIP_RC=1
}

# Test-only access to capsule's private root control socket.  The public
# capsulectl(8) intentionally uses the capability plane and has no socket
# override, while isolated stack tests must address their own daemon instance.
capd_capsule_ctl()
{
	local op reply status verb

	# Unique per call: $$ is the shell's pid, not a subshell's, so
	# parallel callers would otherwise share one file.
	reply=$(mktemp -t capd-control-reply) || return 1
	verb=$2
	case "$verb" in
	shutdown) op=1 ;;
	status) op=2 ;;
	reload) op=3 ;;
	*) return 64 ;;
	esac
	{
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
	    grep -E 'capsule|switchboard|capd_test_guardian|capd_service' | \
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

	# Every test-local Capsule needs its own claim on the control device,
	# including the suites that launch one without capd_start_stack.
	capd_require_device
	rm -f "$CAPD_GUARDIAN_SOCKET" "$CAPD_LEASE"
	mkfifo -m 0600 "$CAPD_LEASE" || atf_fail "cannot create guardian lease"
	# Open read/write before launch so neither side blocks.  Close this inherited
	# descriptor in the guardian process; only the test shell owns the writer.
	exec 9<>"$CAPD_LEASE"
	capd_find_capsule
	# The test issuers created before this Capsule: its own must be a new one.
	CAPD_TEST_ISSUERS_BEFORE=$(sysctl -n kern.mac_capability.test_issuers 2>/dev/null || echo 0)
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
	export SWITCHBOARD_SKIP_RC=1

	capd_require_device
	capd_find_guardian
	capd_find_switchboard
	if [ -z "${CAPD_CONFIG:-}" ] || [ ! -r "$CAPD_CONFIG" ]; then
		capd_stack_prepare
	fi
	capd_launch_capsule

	i=0
	while ! grep -q "switchboard ready" "$CAPD_LOG" 2>/dev/null &&
	    [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if ! grep -q "switchboard ready" "$CAPD_LOG" 2>/dev/null; then
		capd_dump_diagnostics
		atf_fail "switchboard did not become ready"
	fi
	capd_expect_test_issuer
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
	# The stack is gone, so is its test issuer (freed asynchronously).
	i=0
	while [ -n "$(capd_test_issuers_live)" ] &&
	    [ "$(capd_test_issuers_live)" -ne 0 ] && [ "$i" -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ -n "$(capd_test_issuers_live)" ] && [ "$(capd_test_issuers_live)" -ne 0 ]; then
		echo "test issuers still alive after the stack stopped:" \
		    "$(capd_test_issuers_live)" >&2
		dmesg -a | grep -a 'mac_capability: TEST MODE' | tail -n 5 >&2
		return 1
	fi
	rm -rf "$CAPD_PIDFILE" "$CAPD_CONFIG" "$CAPD_CAPSULE_SOCKET" \
	    "$CAPD_SWITCHBOARD_SOCKET" "$CAPD_GUARDIAN_SOCKET" "$CAPD_LEASE" \
	    "$CAPD_LOG" "${CAPD_WORK}/Capabilities"
	return 0
}
