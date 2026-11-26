#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Helpers of the rc unit, getty and sshd pins of switchboard-init-rescope.md
# (slice SR0), which run against the system SwitchBoard of a plane-on guest
# (Capsule PID 1): rc_units_boot_test and getty_test.
#
# Waits are on events: a SwitchBoard log line appended after a mark (tail -f
# on a regular file sleeps in kevent until the file grows; it does not
# follow a rotation, which no case causes), a process exit (pwait), a byte
# on a terminal or a pipe.  None has a deadline of its own; ATF's timeout
# bounds every case.

# Where SwitchBoard's unit lines go (as vm-provider.sh's gate reads them).
SB_LOGS="/var/log/messages /var/log/daemon.log"
SB_UNIT_RE='switchboard\[[0-9]+\]: (service |rc unit |unit |oneshot |switchboard started)'

pid1_comm()
{
	ps -o comm= -p 1 | tr -d ' '
}

require_plane_on()
{
	[ "$(pid1_comm)" = capsule ] && [ "$(kenv -q capability_plane)" != NO ] ||
	    atf_skip "DEFERRED_PLANEON_TIER: PID 1 is $(pid1_comm); run without PLANE_OFF=1"
	sb_pid > /dev/null || atf_fail "no switchboard process with the plane on"
}

sb_pid()
{
	local p

	p=$(pgrep -x switchboard | head -n 1)
	[ -n "$p" ] || return 1
	echo "$p"
}

# comm[pid] of a process, for messages.
pdesc()
{
	local c

	c=$(ps -o comm= -p "$1" 2>/dev/null | tr -d ' ')
	echo "${c:-gone}[$1]"
}

ppid_of()
{
	ps -o ppid= -p "$1" 2>/dev/null | tr -d ' '
}

# The coalition id of a process (kinfo_proc ki_coalition; 0 = none).
coal_of()
{
	procstat --libxo=text coalition "$1" 2>/dev/null | awk 'NR == 2 { print $3 }'
}

# True when ANCESTOR is PID or one of its ancestors.
has_ancestor()
{
	local p=$1 a=$2

	while [ -n "$p" ] && [ "$p" != 0 ]; do
		[ "$p" = "$a" ] && return 0
		[ "$p" = 1 ] && return 1
		p=$(ppid_of "$p")
	done
	return 1
}

# SwitchBoard's status, once.  A status that cannot be read fails the case.
sb_status()
{
	switchboardctl status > sb-status.out 2>&1 ||
	    atf_fail "switchboardctl status failed: $(head -n 3 sb-status.out)"
	cat sb-status.out
}

# The coalition ids SwitchBoard lists: every coal=N of its status (dev's
# form) and, once SR2 adds it, everything `switchboardctl status -c` names.
sb_coalitions()
{
	{
		sb_status
		switchboardctl status -c 2>/dev/null || true
	} | grep -Eo '(coal|coalition)[= ]+[0-9]+' | grep -Eo '[0-9]+$' |
	    sort -un
}

# One unit's status line: label, state, attributes.
unit_line()
{
	sb_status | awk -v u="$1" '$1 == u || $1 == "rc:" u { print; exit }'
}

# A unit's state: running, stopped, ... ; "absent" when SwitchBoard has no
# such unit; "+pending" is appended for a scheduled restart.
unit_state()
{
	unit_line "$1" | awk '{ s = $2; for (i = 3; i <= NF; i++)
		if ($i == "restart-pending") s = s "+pending"; print s }
	    END { if (NR == 0) print "absent" }'
}

unit_field()	# unit_field LABEL KEY: the N of KEY=N, or of "KEY N"
{
	unit_line "$1" | awk -v k="$2" '{ for (i = 2; i <= NF; i++) {
		if (index($i, k "=") == 1) { print substr($i, length(k) + 2); exit }
		if ($i == k && i < NF) { print $(i + 1); exit } } }'
}

# SwitchBoard PID's start line "configuration: <path>; environment
# overrides: ..." (SR1), from the console (dmesg -a; its syslog form
# "<time> <host> switchboard <pid> - - configuration: ...") or a log.
sb_config_line()	# sb_config_line PID
{
	{ dmesg -a; cat $SB_LOGS /var/log/console.log; } 2>/dev/null |
	    tr -d '\r' | grep -E "(switchboard\[$1\]:| switchboard $1 - -) configuration: .*; environment overrides: " |
	    tail -n 1
}

# A mark of the SwitchBoard logs: their sizes now.
sb_log_mark()
{
	local f

	for f in $SB_LOGS; do
		stat -f %z "$f" 2>/dev/null || echo 0
	done | tr '\n' ' '
}

# sb_log_wait MARK REGEX: block until a line matching REGEX is appended to
# one of the logs after MARK.
sb_log_wait()
{
	local mark=$1 re=$2 f off fifo tails rc

	fifo=$(mktemp -u "${PWD}/logwait.XXXXXX")
	mkfifo "$fifo" || atf_fail "mkfifo $fifo"
	tails=
	set -- $mark
	for f in $SB_LOGS; do
		off=${1:-0}
		shift
		tail -c +$((off + 1)) -f "$f" > "$fifo" 2>/dev/null &
		tails="$tails $!"
	done
	rc=0
	grep -Eq -m 1 -- "$re" < "$fifo" || rc=$?
	kill $tails 2>/dev/null
	wait $tails 2>/dev/null
	rm -f "$fifo"
	return $rc
}

# The state of LABEL once it is not starting, stopping or restart-pending,
# re-read whenever SwitchBoard logs a unit line.  An absent unit is
# returned at once: nothing will create it while the test waits.
unit_settled()
{
	local mark s

	while :; do
		mark=$(sb_log_mark)
		s=$(unit_state "$1")
		case $s in
		starting|stopping|*+pending) ;;
		*) echo "$s"; return 0 ;;
		esac
		sb_log_wait "$mark" "$SB_UNIT_RE" ||
		    atf_fail "the SwitchBoard logs ended while $1 was $s"
	done
}

# The state of LABEL, waited on SwitchBoard's unit lines until it is WANT;
# ATF's timeout is the only bound.
unit_wait_state()	# unit_wait_state LABEL WANT
{
	local mark s

	while :; do
		mark=$(sb_log_mark)
		s=$(unit_state "$1")
		[ "$s" = "$2" ] && return 0
		sb_log_wait "$mark" "$SB_UNIT_RE" ||
		    atf_fail "the SwitchBoard logs ended while $1 was $s"
	done
}

# rc.conf.local settings made by a case, removed by its cleanup (with the
# file, when the case created it).
conf_set()	# conf_set NAME VALUE
{
	[ -e conf-set.list ] || [ -e /etc/rc.conf.local ] ||
	    : > "${PWD}/conf-created"
	sysrc -f /etc/rc.conf.local "$1=$2" > /dev/null ||
	    atf_fail "cannot set $1 in /etc/rc.conf.local"
	echo "$1" >> "${PWD}/conf-set.list"
}

conf_restore()
{
	local n

	[ -f conf-set.list ] || return 0
	for n in $(sort -u conf-set.list); do
		sysrc -f /etc/rc.conf.local -x "$n" > /dev/null 2>&1
	done
	# sysrc -x leaves the file it emptied.
	if [ -e conf-created ] && ! grep -q '[^[:space:]]' /etc/rc.conf.local 2>/dev/null; then
		rm -f /etc/rc.conf.local
	fi
	rm -f conf-set.list conf-created
}

# The fixture daemon's rc.d script, installed beside the test.
fixture()
{
	echo "$(atf_get_srcdir)/rc_pin_fixture"
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
