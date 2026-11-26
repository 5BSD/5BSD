#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# SwitchBoard rc unit pins of switchboard-init-rescope.md (slice SR0), run
# against the system SwitchBoard of a plane-on guest after a full boot
# (vm-provider.sh, Capsule PID 1).
#
# Behaviour pins fail on dev for the reason the design gives; each names the
# slice that makes it pass:
#   boot_daemons_in_units          SR2 (gettys and sshd exempt until SR4/SR5)
#   service_restart_routed         SR2
#   ifnet_detach_stops_instance    SR3
#   sshd_per_connection            SR5
#   base_daemons_tracked           SR2
#   switchboard_env_has_no_config  SR1 (SwitchBoard's start line naming its
#                                  environment overrides is absent on dev)
# Regression pins pass on dev and must keep passing:
#   sshd_onerestart_keeps_sessions (a daemon restart keeps sshd sessions
#   today; restarting the accept listener after SR5);
#   ssh_maxstartups_enforced (sshd enforces it today; SwitchBoard after SR5).
#
# The cases change the guest (rc.conf.local, a test user, sshd, a tap
# interface) and restore it in their cleanup: run them only in a disposable
# guest.

. "$(atf_get_srcdir)/rc_units_helpers.sh"

# ---------------------------------------------------------------------------
# Behaviour (SR2): every daemon is in a coalition SwitchBoard lists.

# Capsule's own children are exempt: until SR4 the gettys and the login
# sessions under them (this test runs in one) are Capsule's (dated
# 2026-11-25, SR0; SR4 moves the gettys into SwitchBoard and removes this
# exemption, SR5 adds sshd's per-connection instances).
EXEMPT_SESSION_COMMS="getty login"

atf_test_case boot_daemons_in_units
boot_daemons_in_units_head()
{
	atf_set "descr" "after boot, every process but kernel threads, PID 1, SwitchBoard and Capsule's own children is in a coalition SwitchBoard lists"
	atf_set "require.user" "root"
}
boot_daemons_in_units_body()
{
	local sb pid ppid flags state comm coal exempt bad roots c

	require_plane_on
	sb=$(sb_pid)
	sb_coalitions > listed
	[ -s listed ] || atf_fail "SwitchBoard lists no coalition"
	procstat -a coalition | awk 'NR > 1 { print $1, $3 }' > coal.map
	ps -ax -o pid= -o ppid= -o flags= -o state= -o comm= > procs
	# The session roots: Capsule's gettys and the logins they became.
	roots=$(awk -v comms=" $EXEMPT_SESSION_COMMS " \
	    '$2 == 1 && index(comms, " " $5 " ") { print $1 }' procs)
	# Their descendants, by parent links, to a fixed point.
	echo "$roots" | tr ' ' '\n' | sed '/^$/d' > exempt
	while :; do
		awk 'NR == FNR { e[$1] = 1; next } ($2 in e) && !($1 in e) { print $1 }' \
		    exempt procs > more
		[ -s more ] || break
		cat more >> exempt
	done
	bad=
	while read -r pid ppid flags state comm; do
		[ "$pid" = 0 ] || [ "$pid" = 1 ] || [ "$pid" = "$sb" ] && continue
		case $state in Z*) continue ;; esac
		# Kernel processes: the children of pid 0, and P_SYSTEM.
		[ "$ppid" = 0 ] && continue
		case $flags in ''|*[!0-9a-fA-F]*) ;; *)
			[ $((0x$flags & 0x200)) = 0 ] || continue ;;
		esac
		grep -qx "$pid" exempt && continue
		coal=$(awk -v p="$pid" '$1 == p { print $2; exit }' coal.map)
		if [ -z "$coal" ] || [ "$coal" = 0 ]; then
			bad="$bad $comm[$pid](parent $(pdesc "$ppid"), no coalition)"
		elif ! grep -qx "$coal" listed; then
			bad="$bad $comm[$pid](parent $(pdesc "$ppid"), coalition $coal not SwitchBoard's)"
		fi
	done < procs
	[ -z "$bad" ] ||
	    atf_fail "processes outside SwitchBoard's units:$bad"
}

# ---------------------------------------------------------------------------
# Behaviour (SR2): `service cron restart` is routed: the new cron runs in
# unit cron's coalition and is SwitchBoard's child.

atf_test_case service_restart_routed
service_restart_routed_head()
{
	atf_set "descr" "service cron restart: the new cron is in unit cron's coalition, and its parent is SwitchBoard"
	atf_set "require.user" "root"
}
service_restart_routed_body()
{
	local sb old new ppid coal ucoal why

	require_plane_on
	sb=$(sb_pid)
	old=$(pidfile_pid /var/run/cron.pid) || atf_fail "cron is not running"
	atf_check -s exit:0 -o ignore -e ignore service cron restart
	new=$(pidfile_pid /var/run/cron.pid) || atf_fail "no running cron after the restart"
	[ "$new" != "$old" ] ||
	    atf_fail "cron $old was not replaced"
	ppid=$(ppid_of "$new")
	coal=$(coal_of "$new")
	ucoal=$(unit_field cron coal)
	why=
	[ "$ppid" = "$sb" ] ||
	    why="$why; the new cron's parent is $(pdesc "$ppid"), not SwitchBoard[$sb]"
	[ -n "$coal" ] && [ "$coal" != 0 ] ||
	    why="$why; the new cron is in no coalition"
	[ -n "$ucoal" ] && [ "$coal" = "$ucoal" ] ||
	    why="$why; unit cron's coalition is '${ucoal:-none}' ($(unit_line cron | tr -s ' ')), the new cron's $coal"
	[ -z "$why" ] || atf_fail "${why#; }"
}

# ---------------------------------------------------------------------------
# Behaviour (SR3): an interface's dhclient is the instance unit
# dhclient@<if>; IFNET DETACH stops it.  The test plays the DHCP server on
# the far end of a tap(4) interface (rc_pin_dhcpd.py).

TAP=tap5713

dhcpd_start()	# dhcpd_start IF SERVER CLIENT
{
	mkfifo dhcpd.in dhcpd.out || atf_fail "mkfifo"
	python3.12 -I "$(atf_get_srcdir)/rc_pin_dhcpd.py" "$1" "$2" "$3" \
	    < dhcpd.in > dhcpd.out 2> dhcpd.err &
	echo $! > dhcpd.pid
	exec 8> dhcpd.in 9< dhcpd.out
	read -r l <&9 && [ "$l" = ready ] ||
	    atf_fail "the DHCP server did not start: $(cat dhcpd.err)"
}

dhcpd_stop()
{
	local p

	[ -f dhcpd.pid ] || return 0
	read -r p < dhcpd.pid
	exec 8>&- 9<&- 2>/dev/null
	pwait "$p" 2>/dev/null
	rm -f dhcpd.pid
}

# The devd actions running now (devd's children), waited for: devd runs an
# event's actions to completion, so when they exit the event is handled.
devd_actions_wait()
{
	local devd kids

	devd=$(pidfile_pid /var/run/devd.pid) || atf_fail "devd is not running"
	kids=$(pgrep -P "$devd" | tr '\n' ' ')
	[ -z "$kids" ] || pwait $kids
}

atf_test_case ifnet_detach_stops_instance cleanup
ifnet_detach_stops_instance_head()
{
	atf_set "descr" "a DHCP tap interface: dhclient@tapN runs as an instance unit; ifconfig tapN destroy stops it"
	atf_set "require.user" "root"
	atf_set "require.progs" "python3.12"
}
ifnet_detach_stops_instance_body()
{
	local l dh state

	require_plane_on
	! ifconfig "$TAP" > /dev/null 2>&1 || atf_fail "$TAP exists already"
	conf_set "ifconfig_$TAP" DHCP
	# Created first, so devd's IFNET ATTACH starts dhclient; the server
	# opens it at once, which gives it the link dhclient waits for.
	atf_check -s exit:0 -o ignore -e ignore ifconfig "$TAP" create
	dhcpd_start "$TAP" 192.0.2.1 192.0.2.10
	read -r l <&9 && [ "$l" = ack ] ||
	    atf_fail "dhclient on $TAP got no lease: $(cat dhcpd.err)"
	# The lease is acknowledged inside the ATTACH action's start; its
	# end is the end of that action.
	devd_actions_wait
	dh=$(pgrep -f "^dhclient: $TAP" | head -n 1)
	[ -n "$dh" ] || dh=$(pgrep -x dhclient | head -n 1)
	[ -n "$dh" ] || atf_fail "no dhclient runs for $TAP after its lease"
	state=$(unit_settled "dhclient@$TAP")
	[ "$state" = running ] ||
	    atf_fail "no unit dhclient@$TAP (state $state; dhclient $(pdesc "$dh"), parent $(pdesc "$(ppid_of "$dh")"), coalition $(coal_of "$dh"))"
	dhcpd_stop
	atf_check -s exit:0 -o ignore -e ignore ifconfig "$TAP" destroy
	# dhclient may exit by itself first (RTM_IFANNOUNCE); the DETACH
	# stop makes the instance stopped.  Waited on SwitchBoard's unit
	# lines; ATF's timeout is the only bound.
	unit_wait_state "dhclient@$TAP" stopped
}
ifnet_detach_stops_instance_cleanup()
{
	. "$(atf_get_srcdir)/rc_units_helpers.sh"
	local p

	if [ -f dhcpd.pid ]; then
		read -r p < dhcpd.pid
		kill "$p" 2>/dev/null
	fi
	ifconfig "$TAP" destroy 2>/dev/null
	conf_restore
}

# ---------------------------------------------------------------------------
# sshd: a test user with a key, and sessions held open through fifos.

# The PCB addresses of the TCP sockets listening on port 22.
SSH_LISTENERS_SH='netstat -Aan -p tcp | awk '"'"'$NF == "LISTEN" && $5 ~ /[.:]22$/ { print $1 }'"'"' | sort'
ssh_listeners()
{
	sh -c "$SSH_LISTENERS_SH"
}

# ssh_wait_listen [BEFORE]: wait until something listens on port 22 (and,
# with BEFORE, a file of earlier listeners, none of them is among them).
# rc.subr's start of sshd returns when sshd has daemonized, before it binds;
# sshd writes its pidfile once its sockets are bound, so the condition is
# re-read on events of /var/run and the pidfile (rc_pin_waituntil.py).  A
# SwitchBoard accept listener (SR5) is armed when the routed start returns.
ssh_wait_listen()
{
	python3.12 -I "$(atf_get_srcdir)/rc_pin_waituntil.py" \
	    /var/run /var/run/sshd.pid -- sh -c '
		l=$(sh -c "$0")
		[ -n "$l" ] || exit 1
		[ -z "$1" ] || [ -z "$(echo "$l" | comm -12 "$1" -)" ]' \
	    "$SSH_LISTENERS_SH" "${1:-}" ||
	    atf_fail "waiting for sshd to listen failed"
}

SSH_USER=srcpin

ssh_setup()
{
	local home

	home=$(mktemp -d /var/tmp/srcpin-home.XXXXXX)
	echo "$home" > ssh.home
	pw useradd "$SSH_USER" -d "$home" -s /bin/sh -c "SR0 ssh pin" ||
	    atf_fail "cannot add user $SSH_USER"
	mkdir -p "$home/.ssh"
	ssh-keygen -q -t ed25519 -N '' -f "$PWD/id" ||
	    atf_fail "ssh-keygen"
	cp id.pub "$home/.ssh/authorized_keys"
	chown -R "$SSH_USER" "$home"
	chmod 700 "$home" "$home/.ssh"
}

ssh_teardown()
{
	local p

	for p in $(cat ssh.pids 2>/dev/null); do
		kill "$p" 2>/dev/null
	done
	service sshd onestop > /dev/null 2>&1
	pw userdel "$SSH_USER" 2>/dev/null
	[ -f ssh.home ] && rm -rf "$(cat ssh.home)"
	conf_restore
}

# ssh_session N: an authenticated session whose remote command is cat(1),
# its input on fd 3+N's fifo and its output read on fd 5+N's.  Waits for
# the session's READY line.
ssh_session()
{
	local n=$1 l

	mkfifo "in$n" "out$n" || atf_fail mkfifo
	ssh -T -i "$PWD/id" -o BatchMode=yes -o StrictHostKeyChecking=no \
	    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
	    "$SSH_USER@127.0.0.1" 'echo READY; exec cat' \
	    < "in$n" > "out$n" 2> "err$n" &
	echo $! >> ssh.pids
	eval "exec $((3 + n))> in$n $((5 + n))< out$n"
	eval "read -r l <&$((5 + n))" && [ "$l" = READY ] ||
	    atf_fail "ssh session $n did not start: $(cat "err$n")"
}

# ---------------------------------------------------------------------------
# Behaviour (SR5): sshd per connection: each connection is an `sshd -i`
# instance in a coalition of its own, under SwitchBoard.

atf_test_case sshd_per_connection cleanup
sshd_per_connection_head()
{
	atf_set "descr" "two ssh connections: two sshd instances in two coalitions under SwitchBoard"
	atf_set "require.user" "root"
	atf_set "require.progs" "python3.12"
}
sshd_per_connection_body()
{
	local sb listener c1 c2 why n

	require_plane_on
	sb=$(sb_pid)
	ssh_setup
	atf_check -s exit:0 -o ignore -e ignore service sshd onestart
	ssh_wait_listen
	ssh_session 1
	ssh_session 2
	set -- $(pgrep -U "$SSH_USER" -x cat)
	[ $# = 2 ] || atf_fail "expected two session commands, found $#: $*"
	c1=$(coal_of "$1") c2=$(coal_of "$2")
	why=
	[ "$c1" != 0 ] && [ "$c2" != 0 ] && [ "$c1" != "$c2" ] ||
	    why="$why; the sessions' coalitions are $c1 and $c2 (one sshd daemon)"
	for n in "$1" "$2"; do
		has_ancestor "$n" "$sb" ||
		    why="$why; session $(pdesc "$n") is not under SwitchBoard"
	done
	if listener=$(pidfile_pid /var/run/sshd.pid); then
		for n in "$1" "$2"; do
			! has_ancestor "$n" "$listener" ||
			    why="$why; session $(pdesc "$n") is a child of the sshd daemon $(pdesc "$listener")"
		done
	fi
	[ -z "$why" ] || atf_fail "sshd is not per connection:${why#;}"
}
sshd_per_connection_cleanup()
{
	. "$(atf_get_srcdir)/rc_units_helpers.sh"
	ssh_teardown
}

# ---------------------------------------------------------------------------
# Regression (SR5 keeps it): `service sshd onerestart` replaces the listener
# and keeps the sessions.  The listener is observed as sshd's LISTEN sockets
# (netstat -Aan PCB addresses): a daemon's on dev, SwitchBoard's accept
# listener after SR5; every one must be new after the restart.  sshd_enable
# is NO in the guest, so plain `restart` would do nothing: onerestart.


atf_test_case sshd_onerestart_keeps_sessions cleanup
sshd_onerestart_keeps_sessions_head()
{
	atf_set "descr" "service sshd onerestart replaces the listener and keeps two sessions"
	atf_set "require.user" "root"
	atf_set "require.progs" "python3.12"
}
sshd_onerestart_keeps_sessions_body()
{
	local n l

	require_plane_on
	ssh_setup
	atf_check -s exit:0 -o ignore -e ignore service sshd onestart
	ssh_wait_listen
	ssh_session 1
	ssh_session 2
	ssh_listeners > listen.before
	[ -s listen.before ] || atf_fail "no socket listens on port 22"
	atf_check -s exit:0 -o ignore -e ignore service sshd onerestart
	ssh_wait_listen "$PWD/listen.before"
	ssh_listeners > listen.after
	[ -s listen.after ] || atf_fail "no socket listens on port 22 after onerestart"
	[ -z "$(comm -12 listen.before listen.after)" ] ||
	    atf_fail "onerestart kept listening socket(s) $(comm -12 listen.before listen.after | tr '\n' ' '): the listener was not replaced"
	for n in 1 2; do
		eval "echo PING$n >&$((3 + n))"
		eval "read -r l <&$((5 + n))" && [ "$l" = "PING$n" ] ||
		    atf_fail "session $n did not survive service sshd onerestart"
	done
}
sshd_onerestart_keeps_sessions_cleanup()
{
	. "$(atf_get_srcdir)/rc_units_helpers.sh"
	ssh_teardown
}

# ---------------------------------------------------------------------------
# Regression (SR5 keeps it): MaxStartups 2:100:2 refuses a third concurrent
# unauthenticated connection.  sshd enforces it on dev; SwitchBoard does
# after SR5, from `sshd -G ${sshd_flags}`.

atf_test_case ssh_maxstartups_enforced cleanup
ssh_maxstartups_enforced_head()
{
	atf_set "descr" "MaxStartups 2:100:2: a third concurrent unauthenticated connection is dropped"
	atf_set "require.user" "root"
	atf_set "require.progs" "python3.12"
}
ssh_maxstartups_enforced_body()
{
	local n l

	require_plane_on
	conf_set sshd_flags "-o MaxStartups=2:100:2"
	atf_check -s exit:0 -o ignore -e ignore service sshd onestart
	ssh_wait_listen
	for n in 1 2 3; do
		mkfifo "nin$n" "nout$n" || atf_fail mkfifo
		nc 127.0.0.1 22 < "nin$n" > "nout$n" 2> "nerr$n" &
		echo $! >> ssh.pids
		eval "exec $((3 + n))> nin$n $((6 + n))< nout$n"
		l=
		eval "read -r l <&$((6 + n))" || true
		case $n:$l in
		[12]:SSH-2.0-*) ;;
		[12]:*)	atf_fail "unauthenticated connection $n got no banner ('$l')" ;;
		# Dropped: end of file, or sshd's refusal line, no banner.
		3:SSH-2.0-*)
			atf_fail "a third concurrent unauthenticated connection was served" ;;
		3:*)	echo "third connection: '${l:-end of file}'" ;;
		esac
	done
}
ssh_maxstartups_enforced_cleanup()
{
	. "$(atf_get_srcdir)/rc_units_helpers.sh"
	ssh_teardown
}

# ---------------------------------------------------------------------------
# Behaviour (SR2): every base daemon and instance unit of a default boot
# reports a main pid; none is "running (untracked)".

atf_test_case base_daemons_tracked
base_daemons_tracked_head()
{
	atf_set "descr" "every base rc unit of a default boot reports a main pid"
	atf_set "require.user" "root"
}
base_daemons_tracked_body()
{
	local units bad

	require_plane_on
	sb_status > status
	# rc units: the labels that are not native (bundle/unit) labels.
	units=$(awk 'NF >= 2 && $1 !~ /\// && $1 !~ /:$/ &&
	    $2 ~ /^(running|stopped|starting|stopping|done|exited|failed)/ { print $1 }' status)
	[ -n "$units" ] || atf_fail "SwitchBoard shows no rc unit: $(cat status)"
	bad=$(awk '$1 !~ /\// && $1 !~ /:$/ && $2 == "running" && ($0 !~ / pid [0-9]+/ || $0 ~ /untracked/) {
	    print $1 }' status | tr '\n' ' ')
	[ -z "$bad" ] ||
	    atf_fail "rc units running without a main pid (untracked): $bad"
}

# ---------------------------------------------------------------------------
# Behaviour (SR1): SwitchBoard reads its own configuration file; Capsule
# forwards no configuration through its environment.  The observation is
# SwitchBoard's start line, which SR1 adds:
#   configuration: <path>; environment overrides: none
# (names only, never values, of the SWITCHBOARD_* variables it was started
# with).  SwitchBoard starts before /etc/rc starts syslogd, so the line
# reaches the console only: it is read from the console (dmesg -a, and the
# logs in case syslogd also has it).  procstat -e cannot observe the
# environment: the shield refuses it (EPERM).  On dev the line is absent.
# The reroot harness checks the SwitchBoard started after single-user,
# which dev starts with SWITCHBOARD_RC_FASTBOOT.

atf_test_case switchboard_env_has_no_config
switchboard_env_has_no_config_head()
{
	atf_set "descr" "SwitchBoard's start line reports no configuration taken from its environment"
	atf_set "require.user" "root"
}
switchboard_env_has_no_config_body()
{
	local sb l

	require_plane_on
	sb=$(sb_pid)
	l=$(sb_config_line "$sb")
	[ -n "$l" ] ||
	    atf_fail "SwitchBoard[$sb] logged no 'configuration: <path>; environment overrides:' line on the console (SR1 adds it)"
	echo "$l"
	case $l in
	*"environment overrides: none") ;;
	*)	! echo "$l" | grep -Eq 'SWITCHBOARD_(BUNDLE_DIR_[A-Z_]*|RUN_DIR|SKIP_RC|RC_FASTBOOT)' ||
		    atf_fail "Capsule forwards configuration in SwitchBoard's environment: ${l##*environment overrides: }" ;;
	esac
}

atf_init_test_cases()
{
	atf_add_test_case boot_daemons_in_units
	atf_add_test_case service_restart_routed
	atf_add_test_case ifnet_detach_stops_instance
	atf_add_test_case sshd_per_connection
	atf_add_test_case sshd_onerestart_keeps_sessions
	atf_add_test_case ssh_maxstartups_enforced
	atf_add_test_case base_daemons_tracked
	atf_add_test_case switchboard_env_has_no_config
}
