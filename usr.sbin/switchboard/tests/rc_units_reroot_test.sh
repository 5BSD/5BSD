#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# SwitchBoard init pins of switchboard-init-rescope.md (slice SR0) that need
# boot-time configuration, a reboot, a transition during /etc/rc or
# single-user: the EXTRA_SCRIPT of a vm-provider.sh reroot run (REROOT=1,
# PLANE_OFF=1, KERNEL_TIER=test, a GENERIC-TEST stage).  The plane-off pass
# (VM_REROOT=before) writes the configuration and the rc.d markers; the
# guest then reroots into Capsule as PID 1, whose /etc/rc is the first one
# the pins judge.  The loader variable srcpin_case selects:
#
#   boot     boot configuration (regression pins flags_respected,
#            rc_local_runs, jail_enable_starts_jail,
#            dhclient_from_rc_before_rc_ends; behaviour pin
#            cron_disabled_not_running, which rc_adopt fails on dev), then
#            one reboot with a firstboot sentinel and -reboot
#            (shutdown_order, utx_records, firstboot_reboot_reaches_pid1);
#   trans    a reboot, then a reroot, requested by an rc.d script during
#            /etc/rc (transition_signals_registered_early).  On dev the
#            reroot hangs the guest at "Trying to mount root" (issue
#            2026-11-26-reroot-during-rc-hangs-at-mount-root): the reroot
#            half's failure is printed before the reroot is requested and
#            replaced by the pass after it, so a hang ends at the run
#            deadline with that failure on the console;
#   bgfsck   securelevel_before_getty (kern_securelevel 0 at boot, a getty
#            wrapper on an nmdm(4) line records the level it starts at;
#            LOADER_EXTRA nmdm_load="YES"), then harness_unclean_reboot and
#            bgfsck_unit;
#   single   `shutdown now` to single-user (single_user_switchboard_sequence;
#            SINGLE_USER_SHELL=/root/vm-extra.sh, so that this script is the
#            single-user shell), then switchboard_env_has_no_config for the
#            SwitchBoard started after single-user.
#
# A run passes through several boots.  Before each reboot the script saves
# the results as vm-provider.sh's reroot does (/var/db/vm-provider-reroot.tar)
# and makes the next boot plane-on (the loader.conf of a PLANE_OFF=1 image
# turns the plane off); the login after the boot runs it again with
# VM_REROOT=after, and the state file /var/db/srcpin.state says which pass
# it is.  Every pin prints "SRCPIN_PASS: <pin>" or "SRCPIN_FAIL: <pin>:
# <why>" and is recorded in /var/db/srcpin.results, which the last pass
# prints whole with a SRCPIN_SUMMARY line.  Behaviour pins fail on dev for
# the reason the design gives; regression pins must pass.
#
# Waits are on events: pwait(1) for an exit, the next boot's login.  None
# has a deadline of its own: the harness deadline (TIMEOUT_S) bounds the run.
set -u
# The case: the loader's on the first boot, then the one the plane-off pass
# recorded (a later boot's loader.conf is the pass's own rewrite).
case=$(cat /var/db/srcpin.case 2>/dev/null || kenv -q srcpin_case || echo boot)
STATE=/var/db/srcpin.state
RESULTS=/var/db/srcpin.results
RCLOG=/var/db/srcpin.rc
SHUTLOG=/var/db/srcpin.shut
TESTS=/usr/tests/usr.sbin/switchboard
LOGS="/var/log/messages /var/log/daemon.log /var/log/capability.log /var/log/console.log"
TAP=tap5714

note() { echo "SRCPIN: $*"; }
pid1() { ps -o comm= -p 1 | tr -d ' '; }
# kern.boot_id is 16 opaque bytes: printed in hex.
bootid() { sysctl -b kern.boot_id | od -An -tx1 | tr -d ' \n'; }
# pass PIN KIND / fail PIN KIND WHY: KIND is behaviour or regression.
pass() { echo "SRCPIN_PASS: $1 ($2)"; echo "pass $2 $1" >> $RESULTS; }
fail() { echo "SRCPIN_FAIL: $1 ($2): $3"; echo "fail $2 $1 $3" >> $RESULTS; }
judge() {	# judge PIN KIND WHY: pass when WHY is empty
	if [ -z "$3" ]; then pass "$1" "$2"; else fail "$1" "$2" "${3#; }"; fi
}

# The logs as they were when MARK (log sizes) was taken: what was appended
# since.  A log that was rotated since is read whole.
mark() { for f in $LOGS; do stat -f %z "$f" 2>/dev/null || echo 0; done | tr '\n' ' '; }
since() {	# since MARK
	local f off
	set -- $1
	for f in $LOGS; do
		off=${1:-0}; shift
		[ -f "$f" ] || continue
		if [ "$(stat -f %z "$f")" -ge "$off" ]; then
			tail -c +$((off + 1)) "$f"
		else
			cat "$f"
		fi
	done
}

# The next boot runs Capsule with the plane on (the image's loader.conf is
# a PLANE_OFF=1 one; reroot set the plane on through kenv only).
next_boot_plane_on() {
	sed -i '' '/^capability_plane=/d' /boot/loader.conf
	printf 'init_path="/sbin/capsule"\n' > /boot/loader.conf.local
}

# Save the results and the state, then hand the guest to CMD; this pass
# ends with it (PID 1 never exits, so pwait waits for the transition).
leave() {	# leave STATE CMD...
	local st=$1
	shift
	echo "$st" > $STATE
	tar -cf /var/db/vm-provider-reroot.tar -C /tmp kyua-results
	sync
	note "state $st: $*"
	"$@" || { fail harness harness "'$*' failed"; return 1; }
	pwait 1
	exit 1
}

# ------------------------------------------------------------- rc.d markers
install_markers() {
	# Every /etc/rc once root is writable: boot id and PID 1.
	cat > /etc/rc.d/srcpinrc <<'EOS'
#!/bin/sh
# PROVIDE: srcpinrc
# REQUIRE: FILESYSTEMS
. /etc/rc.subr
name=srcpinrc
start_cmd=srcpinrc_start
stop_cmd=:
srcpinrc_start() {
	echo "rc boot=$(sysctl -b kern.boot_id | od -An -tx1 | tr -d ' \n') pid1=$(ps -o comm= -p 1 | tr -d ' ') at=$(date +%s)" >> /var/db/srcpin.rc
}
run_rc_command "$1"
EOS
	# Every rc.shutdown: who runs it and what still runs then.
	cat > /etc/rc.d/srcpinshut <<'EOS'
#!/bin/sh
# PROVIDE: srcpinshut
# REQUIRE: cron
# KEYWORD: shutdown
. /etc/rc.subr
name=srcpinshut
start_cmd=:
stop_cmd=srcpinshut_stop
count() { pgrep -x "$1" | wc -l | tr -d ' '; }
srcpinshut_stop() {
	local p chain sb
	sb=$(pgrep -x switchboard | head -n 1)
	chain= p=$$
	while [ -n "$p" ] && [ "$p" -gt 1 ]; do
		chain="$chain,$(ps -o comm= -p "$p" | tr -d ' ')"
		p=$(ps -o ppid= -p "$p" | tr -d ' ')
	done
	echo "shut boot=$(sysctl -b kern.boot_id | od -An -tx1 | tr -d ' \n') pid1=$(ps -o comm= -p 1 | tr -d ' ') sb=${sb:-none} chain=${chain#,} gettys=$(count getty) logins=$(count login) native=$(count BSDTime) syslogd=$(count syslogd) at=$(date +%s)" >> /var/db/srcpin.shut
}
run_rc_command "$1"
EOS
	chmod 555 /etc/rc.d/srcpinrc /etc/rc.d/srcpinshut
}

# ---------------------------------------------- case boot: configuration
install_boot_config() {
	sysrc cron_enable=NO syslogd_flags="-ss" jail_enable=YES \
	    jail_list=srcpin "ifconfig_$TAP=DHCP" synchronous_dhclient=YES \
	    > /dev/null
	cat >> /etc/jail.conf <<'EOS'
srcpin {
	path = "/";
	persist;
}
EOS
	cat > /etc/rc.local <<'EOS'
echo "rclocal boot=$(sysctl -b kern.boot_id | od -An -tx1 | tr -d ' \n') pid1=$(ps -o comm= -p 1 | tr -d ' ') at=$(date +%s)" >> /var/db/srcpin.rclocal
EOS
	# The DHCP server on $TAP, before netif configures it (rc_pin_dhcpd.py
	# opens the tap, which gives it its link).
	cat > /etc/rc.d/srcpindhcp <<EOS
#!/bin/sh
# PROVIDE: srcpindhcp
# REQUIRE: FILESYSTEMS
# BEFORE: netif
. /etc/rc.subr
name=srcpindhcp
start_cmd=srcpindhcp_start
stop_cmd=:
srcpindhcp_start() {
	local f l
	[ "\$(ps -o comm= -p 1 | tr -d ' ')" = capsule ] || return 0
	ifconfig $TAP create || return 1
	f=\$(mktemp -u /tmp/srcpindhcp.XXXXXX)
	mkfifo "\$f" || return 1
	/usr/local/bin/python3.12 -I $TESTS/rc_pin_dhcpd.py --forever \\
	    $TAP 192.0.2.1 192.0.2.20 > "\$f" 2>/dev/null < /dev/null &
	read -r l < "\$f"
	rm -f "\$f"
	echo "dhcpd \$l boot=\$(sysctl -b kern.boot_id | od -An -tx1 | tr -d ' \\n')" >> /var/db/srcpin.dhcp
}
run_rc_command "\$1"
EOS
	# Late in /etc/rc: is the lease there yet?
	cat > /etc/rc.d/srcpinlate <<EOS
#!/bin/sh
# PROVIDE: srcpinlate
# REQUIRE: LOGIN cron sshd
. /etc/rc.subr
name=srcpinlate
start_cmd=srcpinlate_start
stop_cmd=:
srcpinlate_start() {
	local lease=no addr=no
	[ -s /var/db/dhclient.leases.$TAP ] && lease=yes
	ifconfig $TAP 2>/dev/null | grep -q 'inet 192.0.2.20 ' && addr=yes
	echo "late boot=\$(sysctl -b kern.boot_id | od -An -tx1 | tr -d ' \\n') pid1=\$(ps -o comm= -p 1 | tr -d ' ') lease=\$lease addr=\$addr" >> /var/db/srcpin.dhcp
}
run_rc_command "\$1"
EOS
	chmod 555 /etc/rc.d/srcpindhcp /etc/rc.d/srcpinlate
}

check_boot_config() {
	local why sl p

	why=
	for p in $(pgrep -x cron); do
		why="$why; cron $p runs with cron_enable=NO (parent $(ps -o comm= -p "$(ps -o ppid= -p "$p")"), jail $(ps -o jid= -p "$p" | tr -d ' '))"
	done
	if [ -n "$why" ] && grep -hq 'switchboard\[[0-9]*\]: rc unit cron: \(started\|adopted\)' \
	    /var/log/daemon.log /var/log/messages 2>/dev/null; then
		why="SwitchBoard's rc_adopt (rc_adopt.conf: cron, devd, ntpd) ran onestart for cron, ignoring cron_enable=NO$why; SwitchBoard: $(grep -h 'rc unit cron' /var/log/daemon.log /var/log/messages 2>/dev/null | tail -n 3 | tr '\n' ' ')"
	fi
	judge cron_disabled_not_running behaviour "$why"

	why=
	sl=$(pgrep -x -j none syslogd | head -n 1)
	if [ -z "$sl" ]; then
		why="syslogd is not running"
	elif ! ps -o args= -p "$sl" | grep -Eq '(^| )-ss( |$)'; then
		why="syslogd runs as '$(ps -o args= -p "$sl")', without -ss"
	fi
	judge flags_respected regression "$why"

	why=
	grep -q "pid1=capsule" /var/db/srcpin.rclocal 2>/dev/null ||
	    why="/etc/rc.local did not run under Capsule ($(cat /var/db/srcpin.rclocal 2>/dev/null))"
	judge rc_local_runs regression "$why"

	why=
	jls -j srcpin jid > /dev/null 2>&1 ||
	    why="jail srcpin of jail_list is not running ($(jls 2>&1 | tr '\n' ' '))"
	judge jail_enable_starts_jail regression "$why"

	why=
	grep -q "^dhcpd ready" /var/db/srcpin.dhcp 2>/dev/null ||
	    why="the test DHCP server did not start ($(cat /var/db/srcpin.dhcp 2>/dev/null))"
	grep -q "^late .*pid1=capsule lease=yes addr=yes" /var/db/srcpin.dhcp 2>/dev/null ||
	    why="$why; no lease and address on $TAP when /etc/rc's late script ran ($(grep '^late' /var/db/srcpin.dhcp 2>/dev/null | tr '\n' ' '))"
	judge dhclient_from_rc_before_rc_ends regression "$why"
}

# ------------------------------------------------ the shutdown record checks
# The rc.shutdown runs recorded during the boot BOOT (its shutdown) under
# Capsule (a reroot keeps the boot id: the plane-off boot's rc.shutdown
# before the reroot has PID 1 init).
shut_lines() { grep "^shut boot=$1 pid1=capsule " $SHUTLOG 2>/dev/null; }

# SwitchBoard ran this rc.shutdown: it was alive and an ancestor of it.
check_sequence_shutdown() {	# check_sequence_shutdown BOOT: prints why
	local n l why
	n=$(shut_lines "$1" | wc -l | tr -d ' ')
	l=$(shut_lines "$1" | tail -n 1)
	why=
	[ "$n" = 1 ] || why="$why; rc.shutdown ran $n times in that shutdown"
	case $l in
	*" sb=none "*) why="$why; SwitchBoard was gone when rc.shutdown ran (Capsule stops it first, then runs rc.shutdown): $l" ;;
	*",switchboard,"*|*",switchboard") ;;
	?*) why="$why; rc.shutdown was not run by SwitchBoard: $l" ;;
	esac
	echo "$why"
}

check_shutdown_order() {	# check_shutdown_order BOOT
	local l why
	why=$(check_sequence_shutdown "$1")
	l=$(shut_lines "$1" | tail -n 1)
	case $l in
	*" gettys=0 logins=0 "*) ;;
	?*) why="$why; logins were not closed before rc.shutdown: $l" ;;
	esac
	case $l in
	*" native=0 "*) ;;
	?*) why="$why; native units still ran during rc.shutdown: $l" ;;
	esac
	case $l in
	*" syslogd=0 "*) why="$why; syslogd was not running during rc.shutdown (it stops last): $l" ;;
	esac
	judge shutdown_order behaviour "$why"
}

check_utx() {
	local why
	why=
	# last(1): the pseudo-user reboot lists the boot time and shutdown
	# time records (utx boot at start, utx shutdown in rc.shutdown).
	last reboot > /tmp/srcpin-last.txt 2>&1
	grep -q '^boot time' /tmp/srcpin-last.txt ||
	    why="no boot time record: $(head -n 3 /tmp/srcpin-last.txt | tr '\n' ' ')"
	grep -q '^shutdown time' /tmp/srcpin-last.txt ||
	    why="$why; no shutdown time record: $(head -n 3 /tmp/srcpin-last.txt | tr '\n' ' ')"
	judge utx_records regression "$why"
}

# ------------------------------------------- case trans: rc.d requester
install_trans_requester() {
	cat > /etc/rc.d/srcpinslow <<'EOS'
#!/bin/sh
# PROVIDE: srcpinslow
# REQUIRE: syslogd
# BEFORE: LOGIN
. /etc/rc.subr
name=srcpinslow
start_cmd=srcpinslow_start
stop_cmd=:
srcpinslow_start() {
	local what
	[ -f /var/db/srcpin.trans ] || return 0
	read -r what < /var/db/srcpin.trans
	rm -f /var/db/srcpin.trans
	sync
	echo "requested $what boot=$(sysctl -b kern.boot_id | od -An -tx1 | tr -d ' \n') at=$(date +%s)" >> /var/db/srcpin.trans.log
	logger -t srcpin "requesting $what during /etc/rc"
	case $what in
	reboot) /sbin/shutdown -r now ;;
	reroot) /sbin/reboot -r ;;
	esac
	echo "request $what returned $? at=$(date +%s)" >> /var/db/srcpin.trans.log
}
run_rc_command "$1"
EOS
	chmod 555 /etc/rc.d/srcpinslow
}

# The checks of a transition requested during /etc/rc of boot BOOT, with the
# logs appended since MARK.
check_transition() {	# check_transition WHAT BOOT MARK STAMPFILE
	local what=$1 boot=$2 why cores
	since "$3" > /tmp/srcpin-since.log
	why=
	grep -q "requested $what boot=$boot" /var/db/srcpin.trans.log 2>/dev/null ||
	    why="$why; the rc.d script did not request the $what during /etc/rc"
	grep -Eq 'switchboard\[[0-9]+\]: .*(reboot|reroot) sequence' /tmp/srcpin-since.log ||
	    why="$why; no SwitchBoard '$what sequence' line (on dev Capsule sends SIGTERM and runs rc.shutdown itself)"
	why="$why$(check_sequence_shutdown "$boot")"
	grep -Eq 'switchboard (died|killed by signal)' /tmp/srcpin-since.log &&
	    why="$why; a SwitchBoard crash was logged: $(grep -E 'switchboard (died|killed by signal)' /tmp/srcpin-since.log | head -n 1)"
	cores=$(find / /var/crash /var/db -maxdepth 1 -name '*switchboard*core*' -newer "$4" 2>/dev/null | tr '\n' ' ')
	[ -z "$cores" ] || why="$why; core files: $cores"
	judge "transition_signals_registered_early:$what" behaviour "$why"
}

# ------------------------------------------------ case bgfsck: getty wrapper
install_getty_wrapper() {
	cat > /root/srcpin-getty <<'EOS'
#!/bin/sh
echo "getty boot=$(sysctl -b kern.boot_id | od -An -tx1 | tr -d ' \n') pid1=$(ps -o comm= -p 1 | tr -d ' ') securelevel=$(sysctl -n kern.securelevel) at=$(date +%s)" >> /var/db/srcpin.getty
exec /usr/libexec/getty "$@"
EOS
	chmod 555 /root/srcpin-getty
	printf 'nmdm58A\t"/root/srcpin-getty std.9600"\tvt100\ton\tinsecure\n' >> /etc/ttys
	sysrc kern_securelevel_enable=YES kern_securelevel=0 \
	    background_fsck=YES background_fsck_delay=0 > /dev/null
}

check_securelevel() {
	local why l
	why=
	kldstat -q -m nmdm || why="nmdm(4) is not loaded (LOADER_EXTRA nmdm_load=\"YES\")"
	l=$(grep "pid1=capsule" /var/db/srcpin.getty 2>/dev/null | head -n 1)
	case $l in
	"") why="$why; the test getty never started" ;;
	*" securelevel=1 "*) ;;
	*) why="$why; securelevel when the first getty ran: $l" ;;
	esac
	judge securelevel_before_getty regression "$why"
}

check_bgfsck() {	# check_bgfsck MARK
	local why st
	since "$1" > /tmp/srcpin-since.log
	dmesg -a > /tmp/srcpin-dmesg.txt
	why=
	grep -Eq 'was not properly dismounted|not clean|unclean' /tmp/srcpin-dmesg.txt ||
	    note "harness_unclean_reboot: the kernel did not report an unclean root"
	st=0
	switchboardctl status bgfsck > /tmp/srcpin-bgfsck.txt 2>&1 || st=$?
	if [ "$st" != 0 ]; then
		why="$why; switchboardctl status bgfsck failed ($st): $(head -n 2 /tmp/srcpin-bgfsck.txt | tr '\n' ' ') (no unit)"
	else
		grep -Eq '(running|done)' /tmp/srcpin-bgfsck.txt ||
		    why="$why; bgfsck is neither running nor done: $(tr '\n' ' ' < /tmp/srcpin-bgfsck.txt)"
		grep -q "$(bootid)" /tmp/srcpin-bgfsck.txt ||
		    why="$why; status bgfsck does not carry kern.boot_id $(bootid)"
	fi
	{ cat /tmp/srcpin-since.log; cat /tmp/srcpin-dmesg.txt; } |
	    grep -Eq 'fsck(\[[0-9]+\])?: |Starting background file system checks' ||
	    why="$why; no background fsck log line"
	judge bgfsck_unit behaviour "$why"
}

# ------------------------------------------------ case single: the checks
check_single() {	# check_single MARK STAMPBOOT
	local why l sbexit
	since "$1" > /tmp/srcpin-since.log
	dmesg -a >> /tmp/srcpin-since.log
	why=
	grep -Eq 'switchboard\[[0-9]+\]: .*stopping for single-user' /tmp/srcpin-since.log ||
	    why="$why; no SwitchBoard 'stopping for single-user' line (on dev SwitchBoard gets a plain SIGTERM)"
	# On dev this line comes from rc.shutdown (death()); it is checked for
	# presence only, so it is never dev's failure reason.
	grep -q 'Stopping cron\.' /tmp/srcpin-since.log ||
	    why="$why; no 'Stopping cron.' line from cron's routed stop (cron died in Capsule's sweep)"
	sbexit=$(grep -n -E 'switchboard( pid [0-9]+)? exited (with )?status 0' /tmp/srcpin-since.log | head -n 1 | cut -d: -f1)
	l=$(grep -n -E 'killing user processes|death_single|sweep' /tmp/srcpin-since.log | head -n 1 | cut -d: -f1)
	if [ -z "$sbexit" ]; then
		why="$why; Capsule logged no SwitchBoard exit with status 0"
	elif [ -n "$l" ] && [ "$l" -lt "$sbexit" ]; then
		why="$why; Capsule's sweep came before SwitchBoard's exit"
	fi
	[ -z "$(shut_lines "$2")" ] ||
	    why="$why; rc.shutdown ran on the way to single-user (on dev Capsule's death() runs it before death_single): $(shut_lines "$2")"
	judge single_user_switchboard_sequence behaviour "$why"
}

# switchboard_env_has_no_config: SwitchBoard's start line (SR1)
# "configuration: <path>; environment overrides: none" for the SwitchBoard
# with pid SB, which lists the names of any SWITCHBOARD_* variable it was
# started with.  Prints why the pin fails, or nothing.
env_overrides_why() {	# env_overrides_why SB
	local l
	[ -n "$1" ] || { echo "no SwitchBoard is running"; return; }
	l=$(grep -h "switchboard\[$1\]: configuration: .*; environment overrides: " \
	    /var/log/daemon.log /var/log/messages 2>/dev/null | tail -n 1)
	case $l in
	"")	echo "SwitchBoard[$1] logged no 'configuration: <path>; environment overrides:' line (SR1 adds it)" ;;
	*"environment overrides: none") ;;
	*)	echo "$l" | grep -Eq 'SWITCHBOARD_(BUNDLE_DIR_[A-Z_]*|RUN_DIR|SKIP_RC|RC_FASTBOOT)' &&
		    echo "SwitchBoard[$1] was started with configuration in its environment: ${l##*environment overrides: }" ;;
	esac
}

summary() {
	local rf bf
	note "results:"
	sed 's/^/SRCPIN_RESULT: /' $RESULTS 2>/dev/null
	rf=$(grep -c '^fail regression' $RESULTS 2>/dev/null)
	bf=$(grep -c '^fail behaviour' $RESULTS 2>/dev/null)
	echo "SRCPIN_SUMMARY case=$case passed=$(grep -c '^pass' $RESULTS 2>/dev/null) regression_failed=${rf:-0} behaviour_failed=${bf:-0} harness_failed=$(grep -c '^fail harness' $RESULTS 2>/dev/null)"
	[ "$(grep -c '^fail' $RESULTS 2>/dev/null)" = 0 ]
}

note "pass ${VM_REROOT:-single-user}, case $case, state $(cat $STATE 2>/dev/null || echo none), pid1=$(pid1), boot $(bootid)"

# --- single-user: this script is the shell PID 1 started (no VM_REROOT).
if [ -z "${VM_REROOT:-}" ]; then
	set -- $(cat $STATE 2>/dev/null)
	if [ "$case:${1:-}" != single:single ]; then
		fail harness harness "single-user in case $case, state ${1:-none}"
	else
		mount -u -o rw / || fail harness harness "cannot mount root read-write"
		check_single "$2 $3 $4 $5" "$6"
	fi
	echo single-done > $STATE
	sync
	[ "$(grep -c '^fail' $RESULTS)" = 0 ] && echo SINGLE_USER_SHELL_PASS
	exit 0
fi

case ${VM_REROOT:-} in
before)
	rm -f $STATE $RESULTS $RCLOG $SHUTLOG /var/db/srcpin.*
	case=$(kenv -q srcpin_case || echo boot)
	echo "$case" > /var/db/srcpin.case
	install_markers
	case $case in
	boot) install_boot_config ;;
	trans) install_trans_requester ;;
	bgfsck) install_getty_wrapper ;;
	single) ;;
	*) echo "SRCPIN_FAIL: unknown srcpin_case $case"; exit 1 ;;
	esac
	note "configured for case $case"
	echo SRCPIN_BEFORE_PASS
	exit 0 ;;
after) ;;
*)
	echo "SRCPIN_FAIL: VM_REROOT=${VM_REROOT:-unset}: run this with vm-provider.sh REROOT=1"
	exit 1 ;;
esac

[ "$(pid1)" = capsule ] || fail harness harness "PID 1 is $(pid1), not capsule"
set -- $(cat $STATE 2>/dev/null)
st=${1:-}
case $case:$st in
boot:)
	check_boot_config
	next_boot_plane_on
	: > /firstboot
	: > /firstboot-reboot
	leave "reboot1 $(bootid) $(wc -l < $RCLOG | tr -d ' ')" /sbin/shutdown -r now ;;
boot:reboot1)
	# $2: the boot that shut down; $3: rc runs recorded before it.
	check_shutdown_order "$2"
	check_utx
	why=
	n=$(tail -n +$(($3 + 1)) $RCLOG | awk '{ print $2 }' | sort -u | wc -l | tr -d ' ')
	[ "$n" -ge 2 ] ||
	    why="the firstboot reboot request did not reboot the guest ($n boot since the sentinel; on dev /etc/rc sends kill -INT 1, which Capsule ignores)"
	[ ! -e /firstboot ] && [ ! -e /firstboot-reboot ] ||
	    why="$why; a firstboot sentinel is left"
	judge firstboot_reboot_reaches_pid1 behaviour "$why"
	summary; exit $? ;;
trans:)
	install_trans_requester
	next_boot_plane_on
	echo reboot > /var/db/srcpin.trans
	: > /var/db/srcpin.stamp
	leave "trans-reboot $(mark)" /sbin/shutdown -r now ;;
trans:trans-reboot)
	b=$(awk '/^requested reboot/ { sub(/boot=/, "", $3); print $3 }' /var/db/srcpin.trans.log | tail -n 1)
	check_transition reboot "${b:-unknown}" "$2 $3 $4 $5" /var/db/srcpin.stamp
	echo reroot > /var/db/srcpin.trans
	: > /var/db/srcpin.stamp
	# The reroot half's verdict needs the reroot to complete: the pass
	# that follows it (its completion event) replaces this provisional
	# failure.  On dev a reroot requested during /etc/rc hangs at "Trying
	# to mount root" (issue 2026-11-26-reroot-during-rc-hangs-at-mount-root); nothing in the guest runs then, so the
	# run deadline (TIMEOUT_S) ends the run, and this line, printed now,
	# is the pin's verdict.
	fail "transition_signals_registered_early:reroot" behaviour \
	    "reroot did not complete (issue 2026-11-26-reroot-during-rc-hangs-at-mount-root)"
	leave "trans-reroot $(mark)" /sbin/shutdown -r now ;;
trans:trans-reroot)
	# The reroot completed: drop the provisional failure, judge it.
	grep -v '^fail behaviour transition_signals_registered_early:reroot reroot did not complete ' \
	    $RESULTS > $RESULTS.new
	mv $RESULTS.new $RESULTS
	note "the reroot completed; its provisional failure is replaced"
	b=$(awk '/^requested reroot/ { sub(/boot=/, "", $3); print $3 }' /var/db/srcpin.trans.log | tail -n 1)
	check_transition reroot "${b:-unknown}" "$2 $3 $4 $5" /var/db/srcpin.stamp
	summary; exit $? ;;
bgfsck:)
	check_securelevel
	next_boot_plane_on
	# harness_unclean_reboot (design 7.3): a write to the root file
	# system, then reboot without sync and without rc.shutdown.  The
	# state and results are synced first; the root stays mounted
	# read-write and unclean.
	echo bgfsck "$(mark)" > $STATE
	tar -cf /var/db/vm-provider-reroot.tar -C /tmp kyua-results
	# sync(2) only schedules the writes: what the next boot needs is
	# written with fsync(1) before the reboot that skips the sync.
	fsync /boot/loader.conf /boot/loader.conf.local /boot $STATE \
	    $RESULTS /var/db/srcpin.case /var/db/vm-provider-reroot.tar \
	    /var/db || fail harness harness "fsync before the unclean reboot"
	echo "dirty $(date +%s)" > /srcpin-dirty
	note "harness_unclean_reboot: reboot -q -n"
	reboot -q -n || fail harness harness "reboot -q -n failed"
	pwait 1
	exit 1 ;;
bgfsck:bgfsck)
	check_bgfsck "$2 $3 $4 $5"
	rm -f /srcpin-dirty
	summary; exit $? ;;
single:)
	leave "single $(mark) $(bootid)" /sbin/shutdown now ;;
single:single-done)
	# switchboard_env_has_no_config for the SwitchBoard that left
	# single-user (on dev Capsule starts it with SWITCHBOARD_RC_FASTBOOT):
	# its start line (SR1) names its environment overrides.
	sb=$(pgrep -x switchboard | head -n 1)
	why=$(env_overrides_why "$sb")
	judge switchboard_env_has_no_config:after-single-user behaviour "$why"
	summary; exit $? ;;
*)
	fail harness harness "case $case in state ${st:-none}"
	summary; exit 1 ;;
esac
