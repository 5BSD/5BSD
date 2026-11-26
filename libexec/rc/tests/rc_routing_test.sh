#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# rc.subr routing pins of switchboard-init-rescope.md (slice SR0).  They run
# in a plane-on guest (Capsule PID 1) and in a plane-off guest (stock init,
# capability_plane=NO); each case names the tier it needs and skips in the
# other.
#
# Behaviour pins fail on dev for the reason the design gives, and pass once
# the slice named on the case lands:
#   rc_routed_under_shutdown_noop          SR2 (no routing exists on dev)
#   firstboot_reboot_failure_continues     SR2 (rc exits 1 on dev)
# Regression pins pass on dev and must keep passing:
#   no_unit_calls_stop_boot, plane_off_unrouted, service_status_exit_codes,
#   onestart_when_disabled.
#
# The test daemon is rc_pin_fixture (rc.subr's default start of
# rc_pin_daemon, rc_unit=daemon), installed beside this program.  Waits are
# on events (pwait(1), a pidfile written before the start command exits);
# none has a deadline of its own: ATF's timeout bounds the case.

fixture()
{
	echo "$(atf_get_srcdir)/rc_pin_fixture"
}

pid1_comm()
{
	ps -o comm= -p 1 | tr -d ' '
}

# The plane is on when PID 1 is Capsule and the loader did not turn it off
# (rc.subr's own predicate is `kenv capability_plane` not off).
plane_on()
{
	[ "$(pid1_comm)" = capsule ] &&
	    [ "$(kenv -q capability_plane)" != NO ]
}

require_plane_on()
{
	plane_on ||
	    atf_skip "needs the plane-on tier (PID 1 is $(pid1_comm))"
}

require_plane_off()
{
	plane_on &&
	    atf_skip "DEFERRED_PLANEOFF_TIER: PID 1 is Capsule; run PLANE_OFF=1"
	[ "$(pid1_comm)" = init ] ||
	    atf_skip "needs stock init as PID 1 (PID 1 is $(pid1_comm))"
}

# The live pid a pidfile names (pidfiles end without a newline, so read(1)
# would report end of file).
pidfile_pid()
{
	local pid

	pid=$(cat "$1" 2>/dev/null) || return 1
	case $pid in ''|*[!0-9]*) return 1 ;; esac
	kill -0 "$pid" 2>/dev/null || return 1
	echo "$pid"
}

fixture_pid()
{
	pidfile_pid /var/run/rcpinfix.pid
}

fixture_stop()
{
	local pid

	pid=$(fixture_pid) || return 0
	"$(fixture)" onestop > /dev/null 2>&1
	kill -0 "$pid" 2>/dev/null || return 0
	kill -TERM "$pid" 2>/dev/null
	pwait "$pid" 2>/dev/null
	return 0
}

# ---------------------------------------------------------------------------
# Regression (static): the only users of RC_PID are stop_boot()'s callers.
# A routed unit shell's RC_PID is its own pid, not /etc/rc's, so no unit may
# call stop_boot (switchboard-init-rescope.md 3.3, S7).

atf_test_case no_unit_calls_stop_boot
no_unit_calls_stop_boot_head()
{
	atf_set "descr" "no rc.d script that is or becomes a unit calls stop_boot"
}
no_unit_calls_stop_boot_body()
{
	local dir f bad kind

	dir=$(atf_config_get rc_source /etc)/rc.d
	[ -d "$dir" ] || atf_fail "no rc.d directory at $dir"
	bad=
	for f in "$dir"/*; do
		[ -f "$f" ] || continue
		grep -Eq '(^|[^_[:alnum:]])stop_boot([^_[:alnum:]]|$)' "$f" ||
		    continue
		kind=
		# A declared kind other than none.
		if grep -Eq '^[[:space:]]*rc_unit="?(daemon|instance|oneshot|accept)' "$f"; then
			kind=declared
		# rc.subr's default start: command= and no start_cmd= (the
		# Q1 rule makes such a script a unit unless it opts out).
		elif grep -Eq '^[[:space:]]*command=' "$f" &&
		    ! grep -Eq '^[[:space:]]*start_cmd=' "$f" &&
		    ! grep -Eq '^[[:space:]]*rc_unit="?none' "$f"; then
			kind=default-start
		fi
		[ -z "$kind" ] || bad="$bad ${f##*/}($kind)"
	done
	[ -z "$bad" ] ||
	    atf_fail "unit scripts that call stop_boot (their RC_PID is not /etc/rc's):$bad"
	# The callers exist: the check above is not vacuous.
	grep -lE '(^|[^_[:alnum:]])stop_boot([^_[:alnum:]]|$)' "$dir"/* \
	    > callers || true
	[ -s callers ] || atf_fail "no rc.d script calls stop_boot: the check read nothing"
}

# ---------------------------------------------------------------------------
# Behaviour (SR2): under /etc/rc.shutdown with no SwitchBoard reachable (the
# post-crash reboot), a routed faststop is a silent no-op with status 0 and
# runs no stop command (3.2, channel note 5.6.4 K1).  On dev nothing is
# routed: the stop runs in the caller and stops the daemon.

atf_test_case rc_routed_under_shutdown_noop cleanup
rc_routed_under_shutdown_noop_head()
{
	atf_set "descr" "rc_shutdown and no SwitchBoard: a routed faststop exits 0 silently, stopping nothing"
	atf_set "require.user" "root"
}
rc_routed_under_shutdown_noop_body()
{
	local pid rc why

	require_plane_on
	atf_check -s exit:0 -o ignore -e ignore "$(fixture)" onestart
	pid=$(fixture_pid) || atf_fail "the test daemon did not start"
	rc=0
	"$(atf_get_srcdir)/rc_noroute_exec" env rc_shutdown=reboot \
	    "$(fixture)" faststop > stop.out 2> stop.err || rc=$?
	why=
	[ "$rc" = 0 ] || why="$why; exit status $rc, not 0"
	[ ! -s stop.out ] || why="$why; stdout: $(tr '\n' ' ' < stop.out)"
	[ ! -s stop.err ] || why="$why; stderr: $(tr '\n' ' ' < stop.err)"
	kill -0 "$pid" 2>/dev/null ||
	    why="$why; the stop command ran in the caller and stopped the daemon (no routing)"
	[ -z "$why" ] ||
	    atf_fail "routed faststop under rc_shutdown with no SwitchBoard:${why#;}"
}
rc_routed_under_shutdown_noop_cleanup()
{
	fixture_stop
}

# ---------------------------------------------------------------------------
# Regression (plane off): stock init, no SwitchBoard, nothing routed.  The
# boot's cron is init's child, as on FreeBSD, in no coalition, and a script
# started by hand is not handed anywhere (13, "Plane-off boots").

atf_test_case plane_off_unrouted cleanup
plane_off_unrouted_head()
{
	atf_set "descr" "plane off: cron's parent is PID 1 (init) and rc.subr routes nothing"
	atf_set "require.user" "root"
}
plane_off_unrouted_body()
{
	local cron pid coal

	require_plane_off
	! pgrep -x switchboard > /dev/null ||
	    atf_fail "a switchboard runs with the plane off"
	cron=$(pidfile_pid /var/run/cron.pid) ||
	    atf_fail "no running cron in /var/run/cron.pid: cron did not start"
	[ "$(ps -o ppid= -p "$cron" | tr -d ' ')" = 1 ] ||
	    atf_fail "cron's parent is $(ps -o comm= -p "$(ps -o ppid= -p "$cron")"), not init"
	coal=$(procstat coalition "$cron" | awk 'NR == 2 { print $3 }')
	[ "$coal" = 0 ] || atf_fail "cron is in coalition $coal with the plane off"
	atf_check -s exit:0 -o ignore -e ignore "$(fixture)" onestart
	pid=$(fixture_pid) || atf_fail "the test daemon did not start"
	coal=$(procstat coalition "$pid" | awk 'NR == 2 { print $3 }')
	[ "$coal" = 0 ] || atf_fail "the test daemon is in coalition $coal with the plane off"
	atf_check -s exit:0 -o ignore -e ignore "$(fixture)" onestop
	kill -0 "$pid" 2>/dev/null && atf_fail "onestop left the test daemon running"
	return 0
}
plane_off_unrouted_cleanup()
{
	fixture_stop
}

# ---------------------------------------------------------------------------
# Behaviour (SR2, design 8.5): a firstboot reboot request that fails is
# logged and /etc/rc goes on, in both integrity branches.  On dev the
# enforcing branch exits 1 when shutdown(8) fails and the other exits 1 when
# `kill -INT 1` fails.  This exercises rc's own cleanup block with seams for
# the commands that would act on the guest (as firstboot_integrity_test):
# the failing reboot command is substituted, which is the pin's form in the
# design (rev 1.3).  A refusing capsulectl cannot set it up on a running
# system: shutdown(8) then falls back to `reboot -l` (reboot(2)).

firstboot_setup()
{
	local rc_source

	rc_source=$(atf_config_get rc_source /etc)
	sed -n '/^# Remove the firstboot sentinel,/,/^echo /p' \
	    "${rc_source}/rc" > cleanup-range.sh
	grep -q '^echo ' cleanup-range.sh || atf_fail 'cleanup block boundary missing'
	sed '$d' cleanup-range.sh |
	    sed 's,/sbin/shutdown -r now,test_shutdown -r now,' > block.sh
	cat > seams.sh <<-'SEAMS'
	SYSCTL=test_sysctl
	test_sysctl() { printf '%s\n' "$MODE"; }
	checkyesno() { [ "$root_rw_mount" = YES ]; }
	mount() { echo "mount $*" >> operations; }
	chflags() { :; }
	kill() { echo "kill $*" >> operations; return 1; }
	test_shutdown() { echo "shutdown $*" >> operations; return 1; }
	logger() { echo "logger $*: $(cat)" >> operations; }
	SEAMS
	printf '. ./seams.sh\n. ./block.sh\n' > exercise.sh
	mkdir -p state
	firstboot_sentinel="$PWD/state/firstboot"
	export firstboot_sentinel
}

atf_test_case firstboot_reboot_failure_continues
firstboot_reboot_failure_continues_head()
{
	atf_set "descr" "a failed firstboot reboot request is logged and /etc/rc continues"
}
firstboot_reboot_failure_continues_body()
{
	local mode rc why

	firstboot_setup
	why=
	for mode in 0 1; do
		rm -f operations
		: > "$firstboot_sentinel"
		: > "$firstboot_sentinel-reboot"
		rc=0
		env MODE=$mode root_rw_mount=YES sh exercise.sh > out 2> err || rc=$?
		[ "$rc" = 0 ] ||
		    why="$why; integrity=$mode: rc exits $rc ($(tr '\n' ' ' < operations 2>/dev/null))"
		grep -q '^shutdown -r now$' operations 2>/dev/null ||
		    why="$why; integrity=$mode: no shutdown -r now request"
		grep -Eq '^logger .*-t rc.*: Firstboot reboot request failed; continuing without reboot$' \
		    operations 2>/dev/null ||
		    why="$why; integrity=$mode: the failure is not logged"
		[ ! -e "$firstboot_sentinel" ] && [ ! -e "$firstboot_sentinel-reboot" ] ||
		    why="$why; integrity=$mode: a sentinel is left"
	done
	[ -z "$why" ] || atf_fail "${why#; }"
}

# ---------------------------------------------------------------------------
# Regression: rc.subr's status answers 0 for a running daemon and 1 for one
# that is not running, routed or not (3.3: 0 running, 1 stopped).

atf_test_case service_status_exit_codes cleanup
service_status_exit_codes_head()
{
	atf_set "descr" "service status: 0 when running, 1 when stopped"
	atf_set "require.user" "root"
}
service_status_exit_codes_body()
{
	local pid

	[ -r /var/run/cron.pid ] && pgrep -x cron > /dev/null ||
	    atf_fail "cron is not running in this guest"
	atf_check -s exit:0 -o match:'is running as pid' -e ignore service cron status
	fixture_stop
	atf_check -s exit:1 -o ignore -e ignore "$(fixture)" onestatus
	atf_check -s exit:0 -o ignore -e ignore "$(fixture)" onestart
	pid=$(fixture_pid) || atf_fail "the test daemon did not start"
	atf_check -s exit:0 -o match:"is running as pid $pid" -e ignore \
	    "$(fixture)" onestatus
	atf_check -s exit:0 -o ignore -e ignore "$(fixture)" onestop
	pwait "$pid" 2>/dev/null
	atf_check -s exit:1 -o match:'is not running' -e ignore "$(fixture)" onestatus
}
service_status_exit_codes_cleanup()
{
	fixture_stop
}

# ---------------------------------------------------------------------------
# Regression: a disabled script refuses `start` with rc.subr's message and
# starts with `onestart`.

atf_test_case onestart_when_disabled cleanup
onestart_when_disabled_head()
{
	atf_set "descr" "a disabled script: start refuses with rc.subr's message, onestart starts it"
	atf_set "require.user" "root"
}
onestart_when_disabled_body()
{
	local pid

	fixture_stop
	! grep -q rcpinfix_enable /etc/rc.conf /etc/rc.conf.local 2>/dev/null ||
	    atf_fail "rcpinfix_enable is set in rc.conf"
	atf_check -s exit:0 \
	    -o match:"Cannot 'start' rcpinfix. Set rcpinfix_enable to YES" \
	    -e ignore "$(fixture)" start
	! fixture_pid > /dev/null || atf_fail "start of a disabled script started it"
	atf_check -s exit:0 -o ignore -e ignore "$(fixture)" onestart
	pid=$(fixture_pid) || atf_fail "onestart did not start the disabled script"
	atf_check -s exit:0 -o ignore -e ignore "$(fixture)" onestop
	pwait "$pid" 2>/dev/null
	! fixture_pid > /dev/null || atf_fail "onestop left the test daemon running"
}
onestart_when_disabled_cleanup()
{
	fixture_stop
}

atf_init_test_cases()
{
	atf_add_test_case no_unit_calls_stop_boot
	atf_add_test_case rc_routed_under_shutdown_noop
	atf_add_test_case plane_off_unrouted
	atf_add_test_case firstboot_reboot_failure_continues
	atf_add_test_case service_status_exit_codes
	atf_add_test_case onestart_when_disabled
}
