#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Login pins of switchboard-init-rescope.md (slice SR0): a plane-on guest
# after a full boot with a serial console (vm-provider.sh; the run's own
# login is the ttyu0 getty) and an extra ttys entry this test adds: an
# autologin getty on a pseudo-terminal whose controlling side the test holds
# (rc_pin_pty.py relays it through two fifos), whose login program is
# rc_pin_login (an interactive sh that keeps typed-ahead input).
#
# Behaviour pins, failing on dev for the reason the design gives, passing
# after SR4:
#   getty_under_switchboard   the parent is Capsule; no coalition
#   logout_kills_background   a background job survives the logout
#
# The extra entry is added with `capsulectl rescan` (init(8)'s `init q`;
# SwitchBoard serves it after SR4) and removed the same way.  Waits are on
# events: a byte from the line, a process exit; ATF's timeout bounds them.

. "$(atf_get_srcdir)/rc_units_helpers.sh"

TTYS_TAG="# srcpin getty_test"

# Open the line (fd 3 types on it, fd 4 reads it), add its autologin entry
# and ask PID 1's side to rescan.
line_add()
{
	cp /etc/ttys ttys.orig && cp /etc/gettytab gettytab.orig ||
	    atf_fail "cannot save /etc/ttys and /etc/gettytab"
	mkfifo pty.in pty.out || atf_fail mkfifo
	python3.12 -I "$(atf_get_srcdir)/rc_pin_pty.py" "$PWD/pty.log" < pty.in > pty.out \
	    2> pty.err &
	echo $! > pty.pid
	exec 3> pty.in 4< pty.out
	read -r LINE <&4 || atf_fail "no pseudo-terminal: $(cat pty.err)"
	echo "$LINE" > pty.name
	echo "line: $LINE"
	printf '\nsrcpin|SR0 getty pin:\\\n\t:al=root:lo=%s:tc=3wire:\n' \
	    "$(atf_get_srcdir)/rc_pin_login" >> /etc/gettytab
	printf '%s\t"/usr/libexec/getty srcpin"\tvt100\ton secure\t%s\n' \
	    "$LINE" "$TTYS_TAG" >> /etc/ttys
	atf_check -s exit:0 -o ignore -e ignore capsulectl rescan
}

line_remove()
{
	local p

	# What the line and its processes did, for a case that failed or
	# ran out of time.
	echo "line $(cat pty.name 2>/dev/null) wrote: $(tr -c '[:print:]' '.' < pty.log 2>/dev/null | head -c 2000)" >&2
	ps -ax -o pid= -o ppid= -o tty= -o state= -o command= |
	    grep -E 'getty|login|pts' >&2

	# The entry goes first, so no respawn reads a gettytab without it.
	[ -f ttys.orig ] && cp ttys.orig /etc/ttys
	capsulectl rescan > /dev/null 2>&1
	[ -f gettytab.orig ] && cp gettytab.orig /etc/gettytab
	exec 3>&- 4<&- 2>/dev/null
	if [ -f pty.pid ]; then
		read -r p < pty.pid
		kill "$p" 2>/dev/null
	fi
	return 0
}

# Block until getty writes its banner on the line ("... (host) (tty)"):
# getty has opened the line and flushed it, so what is typed from now on
# reaches the session's shell.
line_wait_banner()
{
	local l h

	h=$(hostname)
	while IFS= read -r l <&4; do
		case $l in *"($h)"*) return 0 ;; esac
	done
	atf_fail "the line ended before getty wrote its banner"
}

# line_cmd CMD [EXPR]: type CMD, then a marker line with EXPR (default $?)
# expanded by the session's shell; print what follows the marker.
line_cmd()
{
	local tag l

	tag="SRCPIN$$x$(jot -r 1 100000 999999)"
	printf '%s\necho %s:%s\n' "$1" "$tag" "${2:-\$?}" >&3
	while IFS= read -r l <&4; do
		l=$(printf '%s' "$l" | tr -d '\r')
		case $l in
		*"echo $tag"*) ;;
		*"$tag:"*) echo "${l#*"$tag:"}"; return 0 ;;
		esac
	done
	atf_fail "the line ended before '$1' answered"
}

# The process that runs the session on the line: getty, which became the
# login program (comm sh).
session_proc()
{
	local t

	t=$(cat pty.name)
	ps -ax -o pid= -o tty= -o comm= | awk -v t="$t" -v s="${t#pts/}" \
	    '($2 == t || $2 == s) && ($3 == "login" || $3 == "getty" || $3 == "sh") { print $1; exit }'
}

atf_test_case getty_under_switchboard cleanup
getty_under_switchboard_head()
{
	atf_set "descr" "each getty is SwitchBoard's child, in a coalition of its own with no leader"
	atf_set "require.user" "root"
}
getty_under_switchboard_body()
{
	local sb p pp coal rel rpid why sbcoal seen

	require_plane_on
	sb=$(sb_pid)
	sbcoal=$(coal_of "$sb")
	line_add
	line_wait_banner
	line_cmd "echo up" > /dev/null
	why= seen=
	for p in $( { ps -ax -o pid= -o comm= |
	    awk '$2 == "getty" || $2 == "login" { print $1 }'; session_proc; } |
	    sort -un); do
		pp=$(ppid_of "$p")
		# A login's own children (none) and logins started by
		# something else (su, a shell) are not gettys.
		[ "$pp" = 1 ] || [ "$pp" = "$sb" ] || continue
		set -- $(procstat --libxo=text coalition "$p" | awk 'NR == 2 { print $3, $5, $6 }')
		coal=${1:-0} rpid=${2:-0} rel=${3:--}
		seen="$seen $(pdesc "$p")"
		[ "$pp" = "$sb" ] ||
		    why="$why; $(pdesc "$p") on $(ps -o tt= -p "$p" | tr -d ' ')'s parent is $(pdesc "$pp"), not SwitchBoard[$sb]"
		if [ "$coal" = 0 ]; then
			why="$why; $(pdesc "$p") is in no coalition"
			continue
		fi
		[ "$coal" != "$sbcoal" ] ||
		    why="$why; $(pdesc "$p") shares SwitchBoard's coalition $coal"
		# Responsible for itself: RPID is its own leader, which must
		# be none.
		[ "$rel" != self ] || [ "$rpid" = 0 ] ||
		    why="$why; $(pdesc "$p")'s coalition $coal has leader $rpid"
	done
	[ -n "$seen" ] || atf_fail "no getty or login process found"
	echo "gettys and logins:$seen"
	# One coalition per getty.
	[ -z "$(for p in $seen; do p=${p##*[}; coal_of "${p%]}"; done | sort | uniq -d | grep -vx 0)" ] ||
	    why="$why; two gettys share a coalition"
	[ -z "$why" ] || atf_fail "${why#; }"
}
getty_under_switchboard_cleanup()
{
	. "$(atf_get_srcdir)/rc_units_helpers.sh"
	line_remove
}

atf_test_case logout_kills_background cleanup
logout_kills_background_head()
{
	atf_set "descr" "nohup sleep 1000 &, then logout: the background job is gone"
	atf_set "require.user" "root"
}
logout_kills_background_body()
{
	local bg login state

	require_plane_on
	line_add
	line_wait_banner
	bg=$(line_cmd 'nohup sleep 1000 > /dev/null 2>&1 &' '$!')
	case $bg in ''|*[!0-9]*) atf_fail "no background job pid ('$bg')" ;; esac
	echo "$bg" > bg.pid
	kill -0 "$bg" || atf_fail "the background job $bg is not running"
	login=$(session_proc)
	[ -n "$login" ] || atf_fail "no login process on ${LINE}A"
	printf 'exit\n' >&3
	pwait "$login"
	# The respawned getty's session answering means the logout was
	# handled (SwitchBoard closes the coalition before it respawns).
	line_wait_banner
	line_cmd "echo again" > /dev/null
	state=$(ps -o state= -p "$bg" 2>/dev/null | tr -d ' ')
	case $state in
	''|Z*) ;;
	*) atf_fail "the background job $(pdesc "$bg") survived the logout (state $state, parent $(pdesc "$(ppid_of "$bg")"))" ;;
	esac
}
logout_kills_background_cleanup()
{
	. "$(atf_get_srcdir)/rc_units_helpers.sh"
	local bg

	if [ -f bg.pid ]; then
		read -r bg < bg.pid
		kill "$bg" 2>/dev/null
	fi
	line_remove
}

atf_init_test_cases()
{
	atf_add_test_case getty_under_switchboard
	atf_add_test_case logout_kills_background
}
