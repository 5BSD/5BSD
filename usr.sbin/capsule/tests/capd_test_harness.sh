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
capd_wait_file_bin=
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
	# The guardian's PID, for an ATF cleanup (a new process) to wait on.
	CAPD_GUARDIAN_PIDFILE="${CAPD_WORK}/guardian.pid"
	# Test issuers live and created before the case's first stack, for the
	# cleanup (a separate process) to wait back to and report against.
	CAPD_ISSUERS_LIVE_FILE="${CAPD_WORK}/issuers-live.before"
	CAPD_ISSUERS_CREATED_FILE="${CAPD_WORK}/issuers-created.before"
	# What the body is waiting for while it waits without a deadline, one
	# file per wait (CAPD_WAITING.XXXXXX; waits can run concurrently, in
	# background subshells): a case its ATF timeout ends there leaves them
	# for the cleanup to report.
	CAPD_WAITING="${CAPD_WORK}/capd-waiting"
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
	local pid line

	capd_test_relax || return 0
	pid=$("$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status 2>/dev/null |
	    sed -n 's/^running pid=//p')
	[ -n "$pid" ] || atf_fail "cannot read the test-local Capsule's pid"
	# No wait: Capsule creates the start's issuer before it forks
	# SwitchBoard (bootstrap_issuer_take()), the kernel logs the creation
	# before the create returns, and the caller has already seen
	# "switchboard ready", which only that SwitchBoard can cause.
	line=$(dmesg -a 2>/dev/null | grep -a "mac_capability: TEST MODE: pid $pid ([^)]*) created authority issuer " | tail -n 1)
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

capd_find_wait_file()
{
	local candidate srcdir

	if [ -n "$capd_wait_file_bin" ] && [ -x "$capd_wait_file_bin" ]; then
		return 0
	fi
	srcdir=$(atf_get_srcdir 2>/dev/null || pwd)
	for candidate in \
	    "${srcdir}/capd_wait_file" \
	    "$(command -v capd_wait_file 2>/dev/null)"
	do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			capd_wait_file_bin=$candidate
			return 0
		fi
	done
	atf_fail "capd_wait_file is unavailable"
}

# Wait on file events, with no deadline of its own (the case's ATF timeout
# bounds it): capd_wait_path [-e] [-p pid] path [text]; see capd_wait_file.c.
# Exit 2: process pid exited first.
capd_wait_path()
{
	local rc waiting

	capd_find_wait_file
	waiting=$(capd_waiting_begin "capd_wait_file $*")
	rc=0
	"$capd_wait_file_bin" "$@" || rc=$?
	[ -z "$waiting" ] || rm -f "$waiting"
	return "$rc"
}

# Record what a wait is waiting for in a file of its own; print its name
# (nothing when there is no work directory).
capd_waiting_begin()
{
	local waiting

	[ -n "${CAPD_WAITING:-}" ] || return 0
	waiting=$(mktemp "${CAPD_WAITING}.XXXXXX") || return 0
	echo "$1" > "$waiting"
	echo "$waiting"
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
	# The service fixtures' own errors (capd_service_fixture writes its
	# stderr there; SwitchBoard discards a unit's stderr).
	if [ -n "${CAPD_WORK:-}" ] && [ -s "${CAPD_WORK}/fixture-errors" ]; then
		echo "fixture-errors:" >&2
		cat "${CAPD_WORK}/fixture-errors" >&2
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
	local rc

	# Every test-local Capsule needs its own claim on the control device,
	# including the suites that launch one without capd_start_stack.
	capd_require_device
	capd_find_wait_file
	# The Capsule socket is the launch's readiness event: a leftover of an
	# earlier stack must not stand for it.
	rm -f "$CAPD_GUARDIAN_SOCKET" "$CAPD_LEASE" "$CAPD_CAPSULE_SOCKET"
	mkfifo -m 0600 "$CAPD_LEASE" || atf_fail "cannot create guardian lease"
	# Open read/write before launch so neither side blocks.  Close this inherited
	# descriptor in the guardian process; only the test shell owns the writer.
	exec 9<>"$CAPD_LEASE"
	capd_find_capsule
	# The test issuers created before this Capsule: its own must be a new one.
	CAPD_TEST_ISSUERS_BEFORE=$(sysctl -n kern.mac_capability.test_issuers 2>/dev/null || echo 0)
	# Only before the case's first stack: a relaunch must not count an
	# earlier stack's issuer, not yet freed, as the baseline.
	if [ ! -e "$CAPD_ISSUERS_LIVE_FILE" ]; then
		capd_test_issuers_live > "$CAPD_ISSUERS_LIVE_FILE" 2>/dev/null || true
		echo "$CAPD_TEST_ISSUERS_BEFORE" > "$CAPD_ISSUERS_CREATED_FILE"
	fi
	"$capd_guardian_bin" run -l "$CAPD_LEASE" \
	    -s "$CAPD_GUARDIAN_SOCKET" -- \
	    "$capd_capsule_bin" -d -f "$CAPD_CONFIG" >"$CAPD_LOG" 2>&1 9>&- &
	capd_guardian_pid=$!
	echo "$capd_guardian_pid" > "$CAPD_GUARDIAN_PIDFILE"

	# The guardian listens on its socket before it forks Capsule, so
	# Capsule's control socket appearing means both are up.  Wait on that
	# event, or on the guardian's exit (Capsule exited), with no deadline:
	# the case's ATF timeout bounds a launch that hangs.
	echo "waiting for Capsule's control socket $CAPD_CAPSULE_SOCKET" \
	    "(guardian pid $capd_guardian_pid)"
	rc=0
	capd_wait_path -e -p "$capd_guardian_pid" "$CAPD_CAPSULE_SOCKET" ||
	    rc=$?
	if [ "$rc" -ne 0 ]; then
		capd_dump_diagnostics
		[ "$rc" -eq 2 ] &&
		    atf_fail "Capsule exited before it created its control socket"
		atf_fail "waiting for Capsule's control socket failed"
	fi
	if [ ! -S "$CAPD_CAPSULE_SOCKET" ]; then
		capd_dump_diagnostics
		atf_fail "$CAPD_CAPSULE_SOCKET is not a socket"
	fi
	if ! capd_guardian_is_running; then
		capd_dump_diagnostics
		atf_fail "guardian did not launch Capsule"
	fi
}

capd_start_stack()
{
	local rc

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

	# Event wait on the log, ended early by Capsule's exit; the case's ATF
	# timeout bounds a SwitchBoard that never becomes ready.
	echo "waiting for \"switchboard ready\" in $CAPD_LOG"
	rc=0
	capd_wait_path -p "$capd_guardian_pid" "$CAPD_LOG" \
	    "switchboard ready" || rc=$?
	if [ "$rc" -ne 0 ]; then
		capd_dump_diagnostics
		[ "$rc" -eq 2 ] &&
		    atf_fail "Capsule exited before switchboard became ready"
		atf_fail "waiting for switchboard ready failed"
	fi
	capd_expect_test_issuer
}

# Wait for the guardian to exit (pwait: a kqueue NOTE_EXIT, no polling and
# no deadline; the case's ATF timeout bounds it).  The body's own guardian
# is its unreaped child, so its PID cannot be reused; a PID read from the
# pidfile (an ATF cleanup) is waited on only while it still names the
# guardian.
capd_wait_guardian_exit()
{
	local pid waiting

	pid=${capd_guardian_pid:-$(cat "$CAPD_GUARDIAN_PIDFILE" 2>/dev/null || true)}
	case "$pid" in
	''|*[!0-9]*)
		echo "no guardian PID to wait on" >&2
		return 1 ;;
	esac
	if [ -z "$capd_guardian_pid" ] &&
	    [ "$(ps -p "$pid" -o comm= 2>/dev/null)" != \
	    "$(basename "$capd_guardian_bin")" ]; then
		! capd_guardian_is_running
		return
	fi
	echo "waiting for guardian $pid to exit"
	waiting=$(capd_waiting_begin "guardian $pid to exit")
	pwait "$pid" 2>/dev/null || true
	[ -z "$waiting" ] || rm -f "$waiting"
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
	# A shutdown Capsule took ends in the guardian's exit, waited for
	# without a deadline (the case's ATF timeout bounds a shutdown that
	# hangs).  One it did not take is a failure: the guardian kills the
	# stack, and the stop still waits for its exit.
	if [ "$graceful" -eq 0 ]; then
		echo "Capsule did not take the shutdown request:" \
		    "the guardian kills the stack" >&2
		capd_dump_diagnostics
		"$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" kill \
		    >/dev/null 2>&1 || true
	fi
	if ! capd_wait_guardian_exit; then
		capd_dump_diagnostics
		echo "guardian could not terminate the Capsule stack" >&2
		return 1
	fi
	capd_close_lease
	if [ -n "$capd_guardian_pid" ]; then
		wait "$capd_guardian_pid" 2>/dev/null || true
		capd_guardian_pid=
	fi
	[ "$graceful" -eq 1 ]
}

capd_cleanup_stack()
{
	local f guardian_pid killed before live waiting

	capd_paths_init
	capd_find_guardian
	# A body its ATF timeout ended in a wait: report what it waited for
	# and the stack's state, which the timeout did not.
	waiting=
	for f in "$CAPD_WAITING".*; do
		[ -s "$f" ] || continue
		echo "the body ended while waiting for: $(cat "$f")" >&2
		waiting=yes
	done
	[ -z "$waiting" ] || capd_dump_diagnostics
	if [ -S "$CAPD_CAPSULE_SOCKET" ]; then
		capd_capsule_ctl "$CAPD_CAPSULE_SOCKET" shutdown \
		    >/dev/null 2>&1 || true
	fi
	# Judge the guardian by liveness, never by socket-file existence:
	# the test-body process group is killed when the body exits, which
	# strips the guardian of its atexit socket removal and leaves a
	# stale file behind.
	killed=no
	if capd_guardian_is_running &&
	    "$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" kill \
	    >/dev/null 2>&1; then
		killed=yes
	fi
	# Wait for the guardian process itself to exit (pwait: a kqueue
	# NOTE_EXIT, no polling; the ATF cleanup timeout bounds it).  The PID
	# is checked to still name the guardian, so a recycled PID is never
	# waited on.  A live guardian that did not take the kill request (its
	# socket gone or unanswered) is sent SIGTERM, which ends it and, with
	# its process descriptor, Capsule.
	guardian_pid=$(cat "$CAPD_GUARDIAN_PIDFILE" 2>/dev/null || true)
	case "$guardian_pid" in
	''|*[!0-9]*) ;;
	*)	if [ "$(ps -p "$guardian_pid" -o comm= 2>/dev/null)" = \
		    "$(basename "$capd_guardian_bin")" ]; then
			if [ "$killed" = no ]; then
				echo "guardian $guardian_pid did not take the kill request: SIGTERM" >&2
				kill -TERM "$guardian_pid" 2>/dev/null || true
			fi
			pwait "$guardian_pid" 2>/dev/null || true
		fi ;;
	esac
	if capd_guardian_is_running; then
		capd_dump_diagnostics
		return 1
	fi
	# The stack is gone, so are its test issuers, freed asynchronously once
	# their last reference drops.  Wait back to the count live before this
	# stack (so an issuer leaked earlier does not hold every later cleanup)
	# with the test kernel's wait: a sleep woken by each free, no polling,
	# bounded by the ATF cleanup timeout.  The evidence is written first, so
	# a leak that holds the wait until that timeout still leaves it.
	before=$(cat "$CAPD_ISSUERS_LIVE_FILE" 2>/dev/null || true)
	live=$(capd_test_issuers_live)
	case "$before:$live" in
	*[!0-9:]*|:*|*:) ;;
	*)	if [ "$live" -gt "$before" ]; then
			echo "waiting for this case's test issuers to be freed" \
			    "(normal: they are freed asynchronously; evidence if" \
			    "the cleanup times out): live=$live before=$before" \
			    "created=$(sysctl -n kern.mac_capability.test_issuers)" \
			    "created-before=$(cat "$CAPD_ISSUERS_CREATED_FILE" 2>/dev/null || echo unknown)" >&2
			dmesg -a | grep -a 'mac_capability: TEST MODE' | tail -n 5 >&2
			if ! sysctl debug.mac_capability.test_issuers_wait_live="$before" \
			    >/dev/null; then
				echo "waiting for test issuers to be freed failed" >&2
				return 1
			fi
		fi ;;
	esac
	rm -rf "$CAPD_PIDFILE" "$CAPD_CONFIG" "$CAPD_CAPSULE_SOCKET" \
	    "$CAPD_SWITCHBOARD_SOCKET" "$CAPD_GUARDIAN_SOCKET" "$CAPD_LEASE" \
	    "$CAPD_GUARDIAN_PIDFILE" "$CAPD_ISSUERS_LIVE_FILE" \
	    "$CAPD_ISSUERS_CREATED_FILE" "$CAPD_LOG" "$CAPD_WAITING".* \
	    "${CAPD_WORK}/Capabilities"
	return 0
}
