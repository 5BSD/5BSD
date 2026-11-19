#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# DTrace against capprotect-shielded and no-ambient processes: USDT
# registration and matching, ustack() symbols, the pid provider, and
# DTRACEHIOC_ADDDOF for another process.
#
# Design: /home/koryheard/5bsd-designs/dtrace-under-shield-minimal.md
# (section 6).  Each case pins what the running kernel and libdtrace
# answer; the commit that changes an answer changes the case and names it.
#
# Run in a guest only, with DTrace preloaded (the plane refuses a late
# kldload): vm-provider.sh LOADER_EXTRA='dtraceall_load="YES"'.  The
# fixture must run from UFS or ZFS, not tmpfs: DOF registered for another
# process must lie in a file-backed (vnode) mapping, and a tmpfs file maps
# as a swap object.  It is installed under /usr/tests on the root file
# system.
#

FIXTURE=capprotect_usdt_helper
AGENT=capprotect_protector_helper
ADDDOF=capprotect_adddof_helper
FASTTRAP=capprotect_fasttrap_helper

CANARY_SECRET=0x1122334455667788

# An errno, and the flag values of mac_capability_capprotect_proto.h.
EPERM=1
EACCES=13
EFAULT=14
EINVAL=22
ECAPMODE=94
CP_SF_PTRACE=1

require_dtrace()
{
	if ! kldstat -q -m dtrace; then
		atf_skip "dtrace is not loaded; boot with dtraceall_load=YES" \
		    "(the plane refuses a late kldload)"
	fi
}

# common_head [TIMEOUT]: root, dtrace, and a timeout (300 s by default).
common_head()
{
	atf_set "require.user" "root"
	atf_set "require.progs" "dtrace"
	atf_set "timeout" "${1:-300}"
}

# fixture_start MODE [UID]: start the fixture, with its control on fds 3
# (commands) and 4 (replies); sets FXPID and CANARY.
fixture_start()
{
	local mode=$1 uid=${2:-} line

	rm -f fx.in fx.out
	mkfifo fx.in fx.out || atf_fail "mkfifo"
	if [ -n "$uid" ]; then
		chroot -u "$uid" -g "$uid" -G "$uid" / \
		    "$(atf_get_srcdir)/$FIXTURE" "$mode" \
		    <fx.in >fx.out 2>fx.err &
	else
		"$(atf_get_srcdir)/$FIXTURE" "$mode" <fx.in >fx.out 2>fx.err &
	fi
	exec 3>fx.in 4<fx.out
	parse_ready
}

parse_ready()
{
	local line

	read -r line <&4 || atf_fail "fixture did not start: $(cat fx.err | tr "\n" " ")"
	case "$line" in
	READY\ *) ;;
	*) atf_fail "fixture: $line" ;;
	esac
	FXPID=$(echo "$line" | sed -E 's/.*pid=([0-9]+).*/\1/')
	CANARY=$(echo "$line" | sed -E 's/.*canary=(0x[0-9a-f]+).*/\1/')
}

# agent_spawn PDFLAGS PROTECT MODE: the agent pdforks and (if PROTECT is
# not 0) protects the fixture; the fixture's control is on fds 3 and 4, the
# agent's on 5 and 6.
agent_spawn()
{
	local line

	rm -f fx.in fx.out ag.in ag.out
	mkfifo fx.in fx.out ag.in ag.out || atf_fail "mkfifo"
	"$(atf_get_srcdir)/$AGENT" "$(atf_get_srcdir)/$FIXTURE" \
	    <ag.in >ag.out 3<fx.in 4>fx.out 2>ag.err &
	AGPID=$!
	exec 5>ag.in 6<ag.out 3>fx.in 4<fx.out
	echo "spawn $1 $2 $3" >&5
	read -r line <&6
	case "$line" in
	SPAWNED\ *\ 0) ;;
	*) atf_fail "agent: $line $(cat ag.err | tr "\n" " ")" ;;
	esac
	parse_ready
}

# cmd COMMAND: send one fixture command; the reply is in REPLY.
cmd()
{
	echo "$1" >&3
	read -r REPLY <&4 || atf_fail "fixture closed after $1"
}

fixture_stop()
{
	exec 3>&- 4<&-
	exec 5>&- 6<&- 2>/dev/null || true
	wait 2>/dev/null || true
}

# The cpusdt providers that dtrace -l lists for a glob description.
listed()
{
	dtrace -l -n "$1" 2>/dev/null | awk 'NR > 1 { print $2 }' | sort -u
}

# dtrace_once ARGS...: run dtrace with a deadline; output in dt.out and
# dt.err, exit status in DTRC.
dtrace_once()
{
	timeout 60 dtrace "$@" >dt.out 2>dt.err
	DTRC=$?
}

# dtrace_bg SCRIPT [FLAGS]: start a consumer and wait until it runs.
dtrace_bg()
{
	local i

	rm -f dt.out dt.err
	dtrace $2 -q -n 'BEGIN { printf("CONSUMER_READY\n"); }' -n "$1" \
	    >dt.out 2>dt.err &
	DTPID=$!
	i=0
	while ! grep -q CONSUMER_READY dt.out 2>/dev/null; do
		i=$((i + 1))
		[ $i -lt 600 ] || atf_fail "dtrace did not start: $(cat dt.err | tr "\n" " ")"
		sleep 0.1
	done
}

dtrace_wait()
{
	local i=0

	while kill -0 "$DTPID" 2>/dev/null; do
		i=$((i + 1))
		# A background job of a non-interactive shell ignores SIGINT,
		# so a consumer whose exit() never ran is ended with SIGTERM
		# (and SIGKILL), not left for wait to block on.
		case $i in
		300) kill -TERM "$DTPID" 2>/dev/null ;;
		400) kill -KILL "$DTPID" 2>/dev/null; break ;;
		esac
		sleep 0.1
	done
	wait "$DTPID" 2>/dev/null
}

atf_test_case usdt_exact_probe cleanup
usdt_exact_probe_head()
{
	atf_set "descr" "An exact USDT description of a self-shielded process" \
	    "matches its self-registered probes"
	common_head
}
usdt_exact_probe_body()
{
	require_dtrace
	fixture_start self
	# The root fixture registered itself (drti, path 1) before shielding.
	listed 'cpusdt*:::tick' | grep -qx "cpusdt$FXPID" ||
	    atf_fail "the fixture did not register itself"
	# The full match needs no grab (it failed on the shield's refusal of
	# a ptrace grab before).
	dtrace_once -q -n "cpusdt$FXPID:::tick { printf(\"TICK\\n\"); exit(0); }"
	[ "$DTRC" -eq 0 ] && grep -q TICK dt.out ||
	    atf_fail "the exact description did not fire: $(cat dt.err | tr "\n" " ")"
	fixture_stop
}
usdt_exact_probe_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case usdt_glob_provider cleanup
usdt_glob_provider_head()
{
	atf_set "descr" "A glob provider description of a self-shielded" \
	    "process matches its self-registered probes and fires"
	common_head
}
usdt_glob_provider_body()
{
	require_dtrace
	fixture_start self
	listed 'cpusdt*:::tick' | grep -qx "cpusdt$FXPID" ||
	    atf_fail "cpusdt$FXPID is not listed"
	dtrace_once -q -n "cpusdt*:::tick /pid == $FXPID/ { printf(\"TICK\"); exit(0); }"
	[ "$DTRC" -eq 0 ] && grep -q TICK dt.out ||
	    atf_fail "the glob did not fire: rc $DTRC $(cat dt.err | tr "\n" " ")"
	fixture_stop
}
usdt_glob_provider_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case ustack_symbols cleanup
ustack_symbols_head()
{
	atf_set "descr" "ustack() of a self-shielded process is symbolised" \
	    "(kern.proc.vmmap and auxv are inspect-class), as a plain one is"
	common_head
}
ustack_symbols_body()
{
	require_dtrace
	fixture_start plain
	dtrace_once -q -n "syscall::poll:entry /pid == $FXPID/ { ustack(); exit(0); }"
	grep -q 'libc.so.7`' dt.out ||
	    atf_fail "plain: no symbols: $(cat dt.out dt.err | tr "\n" " ")"
	fixture_stop
	fixture_start self
	dtrace_once -q -n "syscall::poll:entry /pid == $FXPID/ { ustack(); exit(0); }"
	[ "$DTRC" -eq 0 ] || atf_fail "dtrace failed: $(cat dt.err | tr "\n" " ")"
	# kern.proc.vmmap and auxv are inspect-class: symbolised (they were
	# raw addresses while refused).
	grep -q 'libc.so.7`' dt.out ||
	    atf_fail "shielded: no symbols: $(cat dt.out dt.err | tr "\n" " ")"
	fixture_stop
}
ustack_symbols_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case kernel_provider_predicate cleanup
kernel_provider_predicate_head()
{
	atf_set "descr" "Kernel providers observe a shielded process: a pid" \
	    "predicate fires and copyin() reads its memory"
	common_head
}
kernel_provider_predicate_body()
{
	require_dtrace
	fixture_start self
	cmd "set $CANARY_SECRET"
	dtrace_once -q -n "syscall::poll:entry /pid == $FXPID/ {
	    printf(\"CANARY %x\n\", *(uint64_t *)copyin($CANARY, 8)); exit(0); }"
	grep -q "CANARY ${CANARY_SECRET#0x}" dt.out ||
	    atf_fail "copyin: $(cat dt.out dt.err | tr "\n" " ")"
	fixture_stop
}
kernel_provider_predicate_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

# ptrace_calls ARGS...: run dtrace ARGS under ktrace; the exit status is in
# DTRC, the number of ptrace(2) calls dtrace made in PTRACE_CALLS, and the
# number of times it opened the helper device (to register DOF with
# DTRACEHIOC_ADDDOF) in HELPER_OPENS.
ptrace_calls()
{
	rm -f kt.out
	timeout 60 ktrace -i -t cn -f kt.out dtrace "$@" >dt.out 2>dt.err
	DTRC=$?
	PTRACE_CALLS=$(kdump -f kt.out 2>/dev/null | grep -c 'CALL  ptrace(')
	HELPER_OPENS=$(kdump -f kt.out 2>/dev/null |
	    grep -c 'NAMI  "/dev/dtrace/helper"')
}

# One usdt_unregistered_target target.  The fixture did not register itself
# (it cannot: unprivileged or capability mode).  libdtrace registers it
# through a read-only handle and the kernel's DTRACEHIOC_ADDDOF for another
# process: no ptrace(2), no stop.  REGISTERED is "yes" when the exact
# description lists; GRABBED is "yes" when dtrace called ptrace(2).
unregistered_check()
{
	local label=$1 registered=$2 grabbed=$3 t0

	if listed 'cpusdt*:::tick' | grep -qx "cpusdt$FXPID"; then
		atf_fail "$label: the fixture registered itself"
	fi
	ptrace_calls -l -n "cpusdt$FXPID:::tick"
	# dtrace -l can exit 0 having listed nothing: count the probe lines.
	if [ "$(awk 'NR > 1' dt.out | wc -l)" -gt 0 ]; then
		[ "$registered" = yes ] || atf_fail "$label: registered"
	else
		[ "$registered" = no ] ||
		    atf_fail "$label: not registered: $(cat dt.err | tr "\n" " ")"
	fi
	if [ "$PTRACE_CALLS" -gt 0 ]; then
		[ "$grabbed" = yes ] || atf_fail "$label: dtrace called ptrace"
	else
		[ "$grabbed" = no ] || atf_fail "$label: dtrace did not grab"
	fi
	[ "$registered" = yes ] || return 0
	# The probes fire, and the process kept running throughout.
	cmd ticks
	t0=${REPLY#TICKS }
	dtrace_once -q -n "cpusdt$FXPID:::tick { printf(\"TICK\\n\"); exit(0); }"
	grep -q TICK dt.out || atf_fail "$label: did not fire: $(cat dt.err | tr "\n" " ")"
	cmd ticks
	[ "${REPLY#TICKS }" -gt "$t0" ] || atf_fail "$label: ticks stopped"
}

atf_test_case usdt_unregistered_target cleanup
usdt_unregistered_target_head()
{
	atf_set "descr" "USDT of processes that did not register themselves:" \
	    "unprivileged, capability mode, protected"
	common_head
}
usdt_unregistered_target_body()
{
	require_dtrace
	# Registered without a grab (before, through a ptrace grab that
	# stopped the process, or not at all under the shield).
	fixture_start plain 65534
	unregistered_check "plain unprivileged" yes no
	fixture_stop
	fixture_start capmode 65534
	unregistered_check "capmode unprivileged" yes no
	fixture_stop
	# The agent's child execs the fixture as root, so drti registers it
	# unless it cannot: run it in capability mode.
	agent_spawn 0 $CP_SF_PTRACE capmode
	unregistered_check "protected capmode" yes no
	fixture_stop
}
usdt_unregistered_target_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
	pkill -f "$AGENT" 2>/dev/null || true
}

atf_test_case usdt_full_match_no_grab cleanup
usdt_full_match_no_grab_head()
{
	atf_set "descr" "An exact USDT description of a self-registered process" \
	    "makes dtrace neither call ptrace(2) nor register DOF; a partial one" \
	    "registers again"
	common_head
}
usdt_full_match_no_grab_body()
{
	local mod func base

	require_dtrace
	fixture_start self
	listed 'cpusdt*:::tick' | grep -qx "cpusdt$FXPID" ||
	    atf_fail "the fixture did not register itself"
	set -- $(dtrace -l -n "cpusdt$FXPID:::tick" 2>/dev/null |
	    awk 'NR == 2 { print $3, $4 }')
	mod=$1 func=$2
	[ -n "$func" ] || atf_fail "no tick probe listed"
	echo "exact description: cpusdt$FXPID:$mod:$func:tick"
	# dtrace's own libraries register their DOF when it starts: count the
	# helper opens of a listing that registers nothing (a globbed provider).
	ptrace_calls -l -n 'cpusdt*:::tick'
	base=$HELPER_OPENS
	# All four fields, no glob: a probe that matches it needs nothing more.
	ptrace_calls -l -n "cpusdt$FXPID:$mod:$func:tick"
	atf_check_equal 0 "$PTRACE_CALLS"
	atf_check_equal "$base" "$HELPER_OPENS"
	[ "$DTRC" -eq 0 ] || atf_fail "not listed: $(cat dt.err | tr "\n" " ")"
	# A partial description may name probes of objects not registered
	# yet: it registers again (it skipped the registration when anything
	# matched), still without ptrace(2).
	ptrace_calls -l -n "cpusdt$FXPID:::tick"
	atf_check_equal 0 "$PTRACE_CALLS"
	[ "$HELPER_OPENS" -gt "$base" ] || atf_fail "no registration"
	fixture_stop
}
usdt_full_match_no_grab_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case pid_provider_still_refused cleanup
pid_provider_still_refused_head()
{
	atf_set "descr" "The pid provider needs a full grab, which the shield" \
	    "refuses"
	common_head
}
pid_provider_still_refused_body()
{
	require_dtrace
	fixture_start self
	dtrace_once -l -n "pid$FXPID::main:entry"
	[ "$DTRC" -ne 0 ] || atf_fail "pid probes created: $(cat dt.out | tr "\n" " ")"
	grep -q 'the pid provider needs permission to debug it' dt.err ||
	    atf_fail "unexpected error: $(cat dt.err | tr "\n" " ")"
	fixture_stop
}
pid_provider_still_refused_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

# adddof_child: the ADDDOF errno that capprotect_adddof_helper reports when
# it registers its own untraced plain child, run through "$@" (a chroot or
# jail wrapper).
adddof_child()
{
	"$@" "$(atf_get_srcdir)/$ADDDOF" child "$(atf_get_srcdir)/$FIXTURE" \
	    >ad.out 2>ad.err || atf_fail "adddof helper: $(cat ad.err | tr "\n" " ")"
	sed -n 's/^ADDDOF //p' ad.out
}

atf_test_case adddof_other_pid_priv cleanup
adddof_other_pid_priv_head()
{
	atf_set "descr" "A non-root wheel member that can open the helper" \
	    "device registers DOF for its untraced child"
	common_head
}
adddof_other_pid_priv_body()
{
	require_dtrace
	[ "$(stat -f %Sg /dev/dtrace/helper)" = wheel ] ||
	    atf_fail "/dev/dtrace/helper is not group wheel"
	# Refused: PRIV_DTRACE_PROC is root's (it was EINVAL, not a stopped,
	# traced child, before DTRACEHIOC_ADDDOF accepted other processes).
	atf_check_equal $EPERM \
	    "$(adddof_child chroot -u 6501 -g 6501 -G wheel /)"
}
adddof_other_pid_priv_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case adddof_other_pid_jail cleanup
adddof_other_pid_jail_head()
{
	atf_set "descr" "Jailed root that can open the helper device registers" \
	    "DOF for its untraced child"
	common_head
}
adddof_other_pid_jail_body()
{
	require_dtrace
	# The jail shares the host's root and /dev, so the helper device is
	# reachable inside it.
	jail -c path=/ name=capprotect_adddof \
	    command="$(atf_get_srcdir)/$ADDDOF" child \
	    "$(atf_get_srcdir)/$FIXTURE" >ad.out 2>ad.err ||
	    atf_fail "jailed adddof helper: $(cat ad.err | tr "\n" " ")"
	# Refused: a jail has no PRIV_DTRACE_PROC (it was EINVAL before).
	atf_check_equal "ADDDOF $EPERM" "$(cat ad.out)"
}
adddof_other_pid_jail_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
	jail -r capprotect_adddof 2>/dev/null || true
}

atf_test_case adddof_heap_address cleanup
adddof_heap_address_head()
{
	atf_set "descr" "Root registers DOF that another, untraced process" \
	    "copied into its heap"
	common_head
}
adddof_heap_address_body()
{
	local base heap

	require_dtrace
	fixture_start plain 65534
	cmd dof
	base=${REPLY##* }
	cmd heapdof
	heap=${REPLY#HEAPDOF }
	[ "$heap" != 0 ] || atf_fail "no DOF in the fixture"
	"$(atf_get_srcdir)/$ADDDOF" "$FXPID" "$heap" "$base" >ad.out 2>ad.err ||
	    atf_fail "adddof helper: $(cat ad.err | tr "\n" " ")"
	# Refused: not a read-only file mapping (it was EINVAL, not a stopped,
	# traced child, before).  Nothing is registered.
	atf_check_equal "ADDDOF $EFAULT" "$(cat ad.out)"
	listed 'cpusdt*:::tick' | grep -qx "cpusdt$FXPID" &&
	    atf_fail "the heap DOF was registered"
	fixture_stop
}
adddof_heap_address_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

# adddof_fixture N: register the fixture's own DOF from root, N times;
# prints the errnos, one per line.
adddof_fixture()
{
	local dof base i=0

	cmd dof
	set -- "$1" $REPLY
	dof=$3 base=$4
	[ "$dof" != 0 ] || atf_fail "no DOF in the fixture"
	while [ $i -lt "$1" ]; do
		"$(atf_get_srcdir)/$ADDDOF" "$FXPID" "$dof" "$base" 2>>ad.err |
		    sed -n 's/^ADDDOF //p'
		i=$((i + 1))
	done
}

# The number of probes the kernel has for the fixture's provider.  The
# provider is globbed, so that dtrace does not register the fixture's DOF
# itself (a description naming the pid would).
fixture_probes()
{
	dtrace -l -n 'cpusdt*:::' 2>/dev/null |
	    awk -v p="cpusdt$FXPID" 'NR > 1 && $2 == p' | wc -l | tr -d ' '
}

atf_test_case adddof_other_pid_registers cleanup
adddof_other_pid_registers_head()
{
	atf_set "descr" "Root registers the DOF in an unprivileged process's" \
	    "read-only file mapping, without a stop"
	common_head
}
adddof_other_pid_registers_body()
{
	require_dtrace
	fixture_start plain 65534
	listed 'cpusdt*:::tick' | grep -qx "cpusdt$FXPID" &&
	    atf_fail "the fixture registered itself"
	atf_check_equal 0 "$(adddof_fixture 1)"
	atf_check_equal 2 "$(fixture_probes)"
	# Registering again creates nothing more (EALREADY in the kernel).
	atf_check_equal 0 "$(adddof_fixture 1)"
	atf_check_equal 2 "$(fixture_probes)"
	fixture_stop
}
adddof_other_pid_registers_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case adddof_system_process
adddof_system_process_head()
{
	atf_set "descr" "DTRACEHIOC_ADDDOF for a kernel process is refused" \
	    "with EINVAL"
	common_head
}
adddof_system_process_body()
{
	require_dtrace
	# PID 0 is the kernel's process (P_SYSTEM).
	"$(atf_get_srcdir)/$ADDDOF" 0 1000 0 >ad.out 2>ad.err ||
	    atf_fail "adddof helper: $(cat ad.err | tr "\n" " ")"
	atf_check_equal "ADDDOF $EINVAL" "$(cat ad.out)"
}

atf_test_case adddof_cow_modified cleanup
adddof_cow_modified_head()
{
	atf_set "descr" "DOF in pages the process made private (writable," \
	    "written, read-only again) is refused"
	common_head
}
adddof_cow_modified_body()
{
	require_dtrace
	fixture_start plain 65534
	cmd cowdof
	atf_check_equal "COWDOF 0" "$REPLY"
	atf_check_equal $EFAULT "$(adddof_fixture 1)"
	atf_check_equal 0 "$(fixture_probes)"
	fixture_stop
}
adddof_cow_modified_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

# loop_registrations MODE N: run the fixture's MODE loop while root
# registers its DOF N times; the errnos are in reg.out.
loop_registrations()
{
	cmd "loop $1"
	atf_check_equal "LOOP 0" "$REPLY"
	adddof_fixture "$2" >reg.out
	cmd stop
	case "$REPLY" in
	STOP\ [1-9]*) ;;
	*) atf_fail "the $1 loop did not run: $REPLY" ;;
	esac
}

atf_test_case adddof_check_copy_race cleanup
adddof_check_copy_race_head()
{
	atf_set "descr" "A process that swaps crafted anonymous DOF in and out" \
	    "of its DOF pages never gets the crafted DOF registered"
	common_head 600
}
adddof_check_copy_race_body()
{
	require_dtrace
	fixture_start plain 65534
	loop_registrations crafted 100
	# Each call registered the file's DOF or failed with EFAULT.
	grep -qvx "0\|$EFAULT" reg.out &&
	    atf_fail "unexpected errno: $(sort reg.out | uniq -c)"
	[ "$(wc -l < reg.out)" -eq 100 ] || atf_fail "missing results"
	if listed 'cpusdx*:::tick' | grep -q cpusdx; then
		atf_fail "the crafted DOF was registered"
	fi
	echo "results: $(sort reg.out | uniq -c | tr '\n' ' ')"
	fixture_stop
}
adddof_check_copy_race_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case adddof_unmap_race cleanup
adddof_unmap_race_head()
{
	atf_set "descr" "A process that unmaps and remaps its DOF pages while" \
	    "root registers them: each call registers or fails with EFAULT"
	common_head 600
}
adddof_unmap_race_body()
{
	require_dtrace
	fixture_start plain 65534
	loop_registrations unmap 100
	grep -qvx "0\|$EFAULT" reg.out &&
	    atf_fail "unexpected errno: $(sort reg.out | uniq -c)"
	# Providers are created once, however often the DOF registered.
	case "$(fixture_probes)" in
	0|2) ;;
	*) atf_fail "probes multiplied: $(fixture_probes)" ;;
	esac
	echo "results: $(sort reg.out | uniq -c | tr '\n' ' ')"
	fixture_stop
}
adddof_unmap_race_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case adddof_map_churn_retries cleanup
adddof_map_churn_retries_head()
{
	atf_set "descr" "Unrelated mmap/munmap in the target while root" \
	    "registers its DOF: the kernel reads the DOF from the file and" \
	    "registers"
	common_head 600
}
adddof_map_churn_retries_body()
{
	require_dtrace
	fixture_start plain 65534
	loop_registrations churn 50
	atf_check_equal 50 "$(grep -cx 0 reg.out)"
	atf_check_equal 2 "$(fixture_probes)"
	fixture_stop
}
adddof_map_churn_retries_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

concurrent_adddof()
{
	local i=0

	while [ $i -lt 50 ]; do
		"$(atf_get_srcdir)/$ADDDOF" "$FXPID" "$1" "$2" |
		    sed -n 's/^ADDDOF //p'
		i=$((i + 1))
	done
}

atf_test_case adddof_concurrent_dedupe cleanup
adddof_concurrent_dedupe_head()
{
	atf_set "descr" "Two consumers register a self-registered process's" \
	    "DOF at once: providers are created once"
	common_head 600
}
adddof_concurrent_dedupe_body()
{
	local dof base c1 c2

	require_dtrace
	# A root fixture: drti registered it at start-up.
	fixture_start plain
	atf_check_equal 2 "$(fixture_probes)"
	cmd dof
	set -- $REPLY
	dof=$2 base=$3
	concurrent_adddof "$dof" "$base" >con1.out &
	c1=$!
	concurrent_adddof "$dof" "$base" >con2.out &
	c2=$!
	wait $c1 $c2
	cat con1.out con2.out >reg.out
	atf_check_equal 100 "$(grep -cx 0 reg.out)"
	atf_check_equal 2 "$(fixture_probes)"
	fixture_stop
}
adddof_concurrent_dedupe_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case adddof_wrong_base cleanup
adddof_wrong_base_head()
{
	atf_set "descr" "DTRACEHIOC_ADDDOF for another process with a load base" \
	    "that is not the object's is refused with EINVAL"
	common_head
}
adddof_wrong_base_body()
{
	local dof base

	require_dtrace
	fixture_start plain 65534
	cmd dof
	set -- $REPLY
	dof=$2 base=$3
	[ "$dof" != 0 ] || atf_fail "no DOF in the fixture"
	"$(atf_get_srcdir)/$ADDDOF" "$FXPID" "$dof" \
	    "$(printf %x $((base + 0x10000)))" >ad.out 2>ad.err ||
	    atf_fail "adddof helper: $(cat ad.err | tr "\n" " ")"
	# The kernel derives the base (the caller's relocated the probe
	# sites before).  Nothing is registered.
	atf_check_equal "ADDDOF $EINVAL" "$(cat ad.out)"
	atf_check_equal 0 "$(fixture_probes)"
	fixture_stop
}
adddof_wrong_base_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

# copy_registration PATCH: the fixture maps a copy of its executable as an
# object of its own (PATCH 1 moves a probe site of the copy's DOF out of
# the copy's text); root registers the copy's DOF.  Prints the errno.
copy_registration()
{
	local copy dof base

	copy=/var/tmp/capprotect_copy.$$
	rm -f "$copy"
	cmd "copy $copy $1"
	set -- $REPLY
	[ "$2" = 0 ] || atf_fail "copy: $REPLY"
	dof=$3 base=$4
	"$(atf_get_srcdir)/$ADDDOF" "$FXPID" "${dof#0x}" "${base#0x}" \
	    2>ad.err | sed -n 's/^ADDDOF //p'
	rm -f "$copy"
}

atf_test_case adddof_copy_registers cleanup
adddof_copy_registers_head()
{
	atf_set "descr" "The DOF of a second object mapped from a file, whose" \
	    "probe sites lie in its own text, registers"
	common_head
}
adddof_copy_registers_body()
{
	require_dtrace
	fixture_start plain 65534
	atf_check_equal 0 "$(copy_registration 0)"
	atf_check_equal 2 "$(fixture_probes)"
	fixture_stop
}
adddof_copy_registers_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
	rm -f /var/tmp/capprotect_copy.*
}

atf_test_case adddof_site_outside cleanup
adddof_site_outside_head()
{
	atf_set "descr" "A DOF whose probe site lies outside its object's text" \
	    "is refused with EFAULT"
	common_head
}
adddof_site_outside_body()
{
	require_dtrace
	fixture_start plain 65534
	# Every site must lie in an executable mapping of the object (no site
	# was checked before).  Nothing is registered.
	atf_check_equal $EFAULT "$(copy_registration 1)"
	atf_check_equal 0 "$(fixture_probes)"
	fixture_stop
}
adddof_site_outside_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
	rm -f /var/tmp/capprotect_copy.*
}

atf_test_case adddof_capmode cleanup
adddof_capmode_head()
{
	atf_set "descr" "DTRACEHIOC_ADDDOF for another process from capability" \
	    "mode is refused with ECAPMODE"
	common_head
}
adddof_capmode_body()
{
	local dof base

	require_dtrace
	fixture_start plain 65534
	cmd dof
	set -- $REPLY
	dof=$2 base=$3
	[ "$dof" != 0 ] || atf_fail "no DOF in the fixture"
	"$(atf_get_srcdir)/$ADDDOF" capmode "$FXPID" "$dof" "$base" \
	    >ad.out 2>ad.err ||
	    atf_fail "adddof helper: $(cat ad.err | tr "\n" " ")"
	# It was accepted before.
	atf_check_equal "ADDDOF $ECAPMODE" "$(cat ad.out)"
	atf_check_equal 0 "$(fixture_probes)"
	fixture_stop
}
adddof_capmode_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case adddof_exit_race
adddof_exit_race_head()
{
	atf_set "descr" "DTRACEHIOC_ADDDOF for processes that are exiting: no" \
	    "provider outlives its process"
	common_head 600
}
adddof_exit_race_body()
{
	local pid left

	require_dtrace
	"$(atf_get_srcdir)/$ADDDOF" exitrace "$(atf_get_srcdir)/$FIXTURE" 200 \
	    >race.out 2>ad.err ||
	    atf_fail "adddof helper: $(cat ad.err | tr "\n" " ")"
	atf_check_equal 200 "$(grep -c '^PID ' race.out)"
	echo "results: $(awk '{ print $3 }' race.out | sort | uniq -c |
	    tr '\n' ' ')"
	listed 'cpusdt*:::' >providers.out
	left=0
	for pid in $(awk '{ print $2 }' race.out); do
		if grep -qx "cpusdt$pid" providers.out; then
			echo "cpusdt$pid outlived its process" >&2
			left=$((left + 1))
		fi
	done
	atf_check_equal 0 "$left"
}

# makeprobe PID: the errno of a raw FASTTRAPIOC_MAKEPROBE on fixture_func.
makeprobe()
{
	local addr

	cmd func
	addr=${REPLY#FUNC }
	"$(atf_get_srcdir)/$FASTTRAP" "$1" "$FIXTURE" fixture_func "$addr" \
	    >mp.out 2>mp.err || atf_fail "fasttrap helper: $(cat mp.err | tr "\n" " ")"
	sed -n 's/^MAKEPROBE //p' mp.out
}

atf_test_case pid_provider_raw_makeprobe cleanup
pid_provider_raw_makeprobe_head()
{
	atf_set "descr" "FASTTRAPIOC_MAKEPROBE without a grab, on a plain and" \
	    "on a ptrace-shielded process: refused for the shielded one"
	common_head
}
pid_provider_raw_makeprobe_body()
{
	require_dtrace
	fixture_start plain
	atf_check_equal 0 "$(makeprobe $FXPID)"
	fixture_stop
	fixture_start self
	# p_candebug(9): the shield refuses it (it was made, unchecked, before).
	atf_check_equal $EACCES "$(makeprobe $FXPID)"
	fixture_stop
}
pid_provider_raw_makeprobe_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case pid_provider_preshield_enable cleanup
pid_provider_preshield_enable_head()
{
	atf_set "descr" "A pid probe made on a plain process, enabled after the" \
	    "process shields itself, still fires (documented residual)"
	common_head
}
pid_provider_preshield_enable_body()
{
	require_dtrace
	fixture_start plain
	atf_check_equal 0 "$(makeprobe $FXPID)"
	cmd "shield $CP_SF_PTRACE"
	atf_check_equal "SHIELD 0" "$REPLY"
	# The glob provider does not make libdtrace grab the process.
	dtrace_bg "pid*:$FIXTURE:fixture_func:entry /pid == $FXPID/ { printf(\"FIRED\n\"); exit(0); }"
	kill -USR1 "$FXPID"
	dtrace_wait
	# The residual: FASTTRAPIOC_MAKEPROBE is the only check, so the probe
	# made before the shield is enabled and fires.
	grep -q FIRED dt.out || atf_fail "did not fire: $(cat dt.err | tr "\n" " ")"
	fixture_stop
}
pid_provider_preshield_enable_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case usdt_glob_later_dlopen cleanup
usdt_glob_later_dlopen_head()
{
	atf_set "descr" "A globbed USDT description after the process loaded" \
	    "another object with probes registers the new object"
	common_head
}
usdt_glob_later_dlopen_body()
{
	require_dtrace
	fixture_start plain 65534
	# The first description registers the objects loaded so far.
	dtrace_once -l -n "cpusdt$FXPID:::tick"
	[ "$(awk 'NR > 1' dt.out | wc -l)" -gt 0 ] ||
	    atf_fail "not registered: $(cat dt.err | tr "\n" " ")"
	cmd "dlopen $(atf_get_srcdir)/libcapprotect_usdt.so"
	atf_check_equal "DLOPEN 0" "$REPLY"
	# A glob that cannot match the pid provider's name (pidPID), which
	# would make dtrace grab the process for pid probes.
	dtrace_once -l -n "cpu*$FXPID:::"
	# The glob is not an exact description: libdtrace registers the
	# process's objects again (it skipped them because cpusdt matched).
	grep -q "cpulib$FXPID" dt.out ||
	    atf_fail "the late object's probes were not registered: $(cat dt.err | tr "\n" " ")"
	fixture_stop
}
usdt_glob_later_dlopen_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_init_test_cases()
{
	atf_add_test_case usdt_exact_probe
	atf_add_test_case usdt_glob_provider
	atf_add_test_case ustack_symbols
	atf_add_test_case kernel_provider_predicate
	atf_add_test_case usdt_unregistered_target
	atf_add_test_case usdt_full_match_no_grab
	atf_add_test_case pid_provider_still_refused
	atf_add_test_case adddof_other_pid_priv
	atf_add_test_case adddof_other_pid_jail
	atf_add_test_case adddof_heap_address
	atf_add_test_case adddof_other_pid_registers
	atf_add_test_case adddof_system_process
	atf_add_test_case adddof_cow_modified
	atf_add_test_case adddof_check_copy_race
	atf_add_test_case adddof_unmap_race
	atf_add_test_case adddof_map_churn_retries
	atf_add_test_case adddof_concurrent_dedupe
	atf_add_test_case adddof_wrong_base
	atf_add_test_case adddof_copy_registers
	atf_add_test_case adddof_site_outside
	atf_add_test_case adddof_capmode
	atf_add_test_case adddof_exit_race
	atf_add_test_case pid_provider_raw_makeprobe
	atf_add_test_case pid_provider_preshield_enable
	atf_add_test_case usdt_glob_later_dlopen
}
