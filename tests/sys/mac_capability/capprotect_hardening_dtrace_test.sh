#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# DTrace's debugger-like powers against capprotect-shielded processes:
# the pid provider's raw FASTTRAPIOC_MAKEPROBE, and the process-destructive
# actions of dtrace -w (copyout, raise, stop), also from a vfork child and
# from an aio daemon running on the shielded process's memory.
#
# Design: /home/koryheard/5bsd-designs/shield-hardening.md (section 4).
# Each case pins what the running kernel answers; the commit that changes
# an answer changes the case and names it.
#
# Run in a guest only, with DTrace preloaded (the plane refuses a late
# kldload): vm-provider.sh LOADER_EXTRA='dtraceall_load="YES"'.
#

FIXTURE=capprotect_share_helper
AGENT=capprotect_protector_helper
FASTTRAP=capprotect_fasttrap_helper

CANARY_SECRET=0x1122334455667788
CANARY_WRITTEN=0xbadc0de0badc0de

# The flag values of mac_capability_capprotect_proto.h.
CP_SF_PTRACE=1
EACCES=13
EBUSY=16
PD_PROTECTED=10

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
		chroot -u "$uid" / "$(atf_get_srcdir)/$FIXTURE" "$mode" \
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

canary()
{
	cmd canary
	echo "${REPLY#CANARY }"
}

fixture_stop()
{
	exec 3>&- 4<&-
	exec 5>&- 6<&- 2>/dev/null || true
	wait 2>/dev/null || true
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

atf_test_case pid_provider_raw_ioctl cleanup
pid_provider_raw_ioctl_head()
{
	atf_set "descr" "FASTTRAPIOC_MAKEPROBE needs permission to debug the" \
	    "process: refused for a shielded process and its vfork child"
	common_head
}
pid_provider_raw_ioctl_body()
{
	local child n0

	require_dtrace
	fixture_start plain
	atf_check_equal 0 "$(makeprobe $FXPID)"
	fixture_stop
	# p_candebug(9): the shield refuses it (it was made, unchecked,
	# before), and so does the shield the vfork child inherits.
	fixture_start self
	atf_check_equal $EACCES "$(makeprobe $FXPID)"
	cmd vfork
	child=${REPLY#CHILD }
	atf_check_equal $EACCES "$(makeprobe $child)"
	fixture_stop
}
pid_provider_raw_ioctl_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case pid_provider_preshield_enable cleanup
pid_provider_preshield_enable_head()
{
	atf_set "descr" "A pid probe made on a plain process can still be" \
	    "enabled after the process shields itself (documented residual)"
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
	# The residual: the probe made before the shield still fires.
	grep -q FIRED dt.out || atf_fail "did not fire: $(cat dt.err | tr "\n" " ")"
	fixture_stop
}
pid_provider_preshield_enable_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case pid_provider_protector_passes cleanup
pid_provider_protector_passes_head()
{
	atf_set "descr" "The protector of a ptrace-shielded process may make" \
	    "pid probes on it"
	common_head
}
pid_provider_protector_passes_body()
{
	require_dtrace
	"$(atf_get_srcdir)/$FASTTRAP" protect "$(atf_get_srcdir)/$FIXTURE" \
	    >mp.out 2>mp.err || atf_fail "fasttrap helper: $(cat mp.err | tr "\n" " ")"
	atf_check_equal "MAKEPROBE 0" "$(cat mp.out)"
}
pid_provider_protector_passes_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case pid_provider_exec_race cleanup
pid_provider_exec_race_head()
{
	atf_set "descr" "FASTTRAPIOC_MAKEPROBE against a process that executes" \
	    "itself in a loop: each call makes the probe or fails with EBUSY"
	common_head 600
}
pid_provider_exec_race_body()
{
	require_dtrace
	"$(atf_get_srcdir)/$FASTTRAP" execrace "$(atf_get_srcdir)/$FIXTURE" \
	    200 >mp.out 2>mp.err || atf_fail "fasttrap helper: $(cat mp.err | tr "\n" " ")"
	sed -n 's/^MAKEPROBE //p' mp.out >errs
	atf_check_equal 200 "$(wc -l < errs | tr -d ' ')"
	# The target is held with exec blocked from the check to the probe.
	if grep -qvx "0\|$EBUSY" errs; then
		atf_fail "unexpected errno: $(sort errs | uniq -c)"
	fi
	echo "results: $(sort errs | uniq -c | tr '\n' ' ')"
}
pid_provider_exec_race_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

# copyout_into PID: dtrace -w copyout of CANARY_WRITTEN into the canary,
# from the poll(2) entry of PID.
copyout_into()
{
	dtrace_once -w -q -n "syscall::poll:entry /pid == $1/ {
	    this->b = (uint64_t *)alloca(8); *this->b = $CANARY_WRITTEN;
	    copyout(this->b, $CANARY, 8); exit(0); }"
}

atf_test_case destructive_copyout cleanup
destructive_copyout_head()
{
	atf_set "descr" "dtrace -w copyout() is refused in a ptrace-shielded" \
	    "process and in its vfork child"
	common_head
}
destructive_copyout_body()
{
	local child n0

	require_dtrace
	fixture_start self
	cmd "set $CANARY_SECRET"
	n0=$(refusals)
	# Refused (it wrote the canary before).
	copyout_into $FXPID
	atf_check_equal "$CANARY_SECRET" "$(canary)"
	cmd vfork
	child=${REPLY#CHILD }
	copyout_into "$child"
	# The child serves; it sees the parent's memory, unchanged.
	atf_check_equal "$CANARY_SECRET" "$(canary)"
	[ "$(refusals)" -ge $((n0 + 2)) ] ||
	    atf_fail "refusals not counted: $n0 -> $(refusals)"
	fixture_stop
}
destructive_copyout_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

refusals()
{
	sysctl -n debug.dtrace.protected_proc_refusals
}

sigcount()
{
	cmd sigcount
	echo "${REPLY#SIGCOUNT }"
}

proc_state()
{
	ps -o state= -p "$1" | cut -c1
}

atf_test_case destructive_raise cleanup
destructive_raise_head()
{
	atf_set "descr" "dtrace -w raise() is refused in a signal-shielded" \
	    "process"
	common_head
}
destructive_raise_body()
{
	require_dtrace
	fixture_start self-signal-only
	atf_check_equal 0 "$(sigcount)"
	# Shielded against signals from other processes.
	kill -USR1 "$FXPID" 2>/dev/null && atf_fail "kill was not refused"
	dtrace_once -w -q -n "syscall::poll:entry /pid == $FXPID/ { raise(SIGUSR1); exit(0); }"
	sleep 0.5
	# Refused (it was delivered before).
	atf_check_equal 0 "$(sigcount)"
	fixture_stop
}
destructive_raise_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case destructive_stop cleanup
destructive_stop_head()
{
	atf_set "descr" "dtrace -w stop() is refused in a signal-shielded" \
	    "process"
	common_head
}
destructive_stop_body()
{
	require_dtrace
	fixture_start self-signal-only
	dtrace_once -w -q -n "syscall::poll:entry /pid == $FXPID/ { stop(); exit(0); }"
	sleep 0.5
	# Refused (it stopped the process before).
	[ "$(proc_state $FXPID)" != T ] || atf_fail "stopped"
	fixture_stop
}
destructive_stop_cleanup()
{
	pkill -CONT -f "$FIXTURE" 2>/dev/null || true
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case destructive_aio_context cleanup
destructive_aio_context_head()
{
	atf_set "descr" "dtrace -w copyout() from an aio daemon running on a" \
	    "ptrace-shielded process's memory still writes it (documented" \
	    "residual, Q-B2)"
	common_head
}
destructive_aio_context_body()
{
	require_dtrace
	dd if=/dev/zero of=aio.data bs=4k count=4 2>/dev/null
	fixture_start self
	cmd "set $CANARY_SECRET"
	# aio_process_rw() runs in an aio daemon and switches it to the job's
	# vmspace; the daemon's VOP_READ that follows runs on that vmspace.
	dtrace_bg "fbt::aio_process_rw:entry /args[0]->userproc->p_pid == $FXPID/ {
	    self->on = 1; }
	    fbt::VOP_READ_APV:entry /self->on/ { self->on = 0;
	    this->b = (uint64_t *)alloca(8); *this->b = $CANARY_WRITTEN;
	    copyout(this->b, $CANARY, 8);
	    printf(\"AIOD %s\n\", execname); exit(0); }" -w
	echo "aio $(pwd)/aio.data" >&3
	if ! read -t 60 -r REPLY <&4; then
		{ procstat -kk "$FXPID"; procstat -kk -a | grep aio
		    sysctl vfs.aio; cat dt.out dt.err; } >&2 2>&1
		atf_fail "the aio read did not complete in 60 s (state on stderr)"
	fi
	atf_check_equal "AIO 0" "$REPLY"
	dtrace_wait
	grep -q 'AIOD aiod' dt.out ||
	    atf_fail "the probe did not fire in an aio daemon: $(cat dt.out dt.err | tr "\n" " ")"
	# The residual: the daemon is not shielded, and its copyout writes
	# the shielded process's memory.
	atf_check_equal "$CANARY_WRITTEN" "$(canary)"
	fixture_stop
}
destructive_aio_context_cleanup()
{
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_test_case destructive_plain_control cleanup
destructive_plain_control_head()
{
	atf_set "descr" "dtrace -w copyout(), raise() and stop() take effect" \
	    "in an unprotected process"
	common_head
}
destructive_plain_control_body()
{
	require_dtrace
	fixture_start plain
	cmd "set $CANARY_SECRET"
	copyout_into $FXPID
	atf_check_equal "$CANARY_WRITTEN" "$(canary)"
	dtrace_once -w -q -n "syscall::poll:entry /pid == $FXPID/ { raise(SIGUSR1); exit(0); }"
	sleep 0.5
	atf_check_equal 1 "$(sigcount)"
	dtrace_once -w -q -n "syscall::poll:entry /pid == $FXPID/ { stop(); exit(0); }"
	sleep 0.5
	atf_check_equal T "$(proc_state $FXPID)"
	kill -CONT "$FXPID"
	fixture_stop
}
destructive_plain_control_cleanup()
{
	pkill -CONT -f "$FIXTURE" 2>/dev/null || true
	pkill -f "$FIXTURE" 2>/dev/null || true
}

atf_init_test_cases()
{
	atf_add_test_case pid_provider_raw_ioctl
	atf_add_test_case pid_provider_protector_passes
	atf_add_test_case pid_provider_exec_race
	atf_add_test_case pid_provider_preshield_enable
	atf_add_test_case destructive_copyout
	atf_add_test_case destructive_raise
	atf_add_test_case destructive_stop
	atf_add_test_case destructive_aio_context
	atf_add_test_case destructive_plain_control
}
