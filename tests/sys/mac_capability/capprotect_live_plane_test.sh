#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Inspect, debug and USDT answers for the live capability plane: Capsule
# (PID 1), SwitchBoard and a protected unprivileged unit (bsdlog).
#
# Design: /home/koryheard/5bsd-designs/dtrace-under-shield-minimal.md
# (section 6).  Each case pins what the running system answers; the
# commit that changes an answer changes the case and names it.
#
# Plane-on guest only: every case skips, saying why, unless PID 1 is
# Capsule.  The DTrace cases need dtraceall preloaded.  The securelevel
# case raises kern.securelevel, which cannot be lowered: it runs only when
# the configuration variable live_securelevel is "yes", in a guest of its
# own (vm-provider.sh KYUA_VARS=test_suites.FreeBSD.live_securelevel=yes
# SYSCTL_WRITE=kern.securelevel, with only that case selected).
#

AGENT=capprotect_protector_helper
FIXTURE=capprotect_usdt_helper

# KERN_PROC_* numbers (sys/sysctl.h).
KERN_PROC_KSTACK=15
KERN_PROC_VMMAP=32

EACCES=13

require_plane()
{
	if [ "$(ps -o comm= -p 1)" != "capsule" ]; then
		atf_skip "PID 1 is not Capsule: run in a plane-on guest"
	fi
}

require_dtrace()
{
	if ! kldstat -q -m dtrace; then
		atf_skip "dtrace is not loaded; boot with dtraceall_load=YES"
	fi
}

common_head()
{
	atf_set "require.user" "root"
	atf_set "timeout" "180"
}

switchboard_pid()
{
	local pid

	pid=$(pgrep -x switchboard | head -1)
	[ -n "$pid" ] || atf_fail "no switchboard process"
	echo "$pid"
}

# The pid of the running system.Log/bsdlog unit, or nothing.
bsdlog_pid()
{
	switchboardctl status 2>/dev/null |
	    awk '$1 == "system.Log/bsdlog" && $2 == "running" { print $4 }'
}

# agent COMMAND: run one capprotect_protector_helper command; prints the
# errno it reports.
agent()
{
	local line

	line=$(echo "$1" | "$(atf_get_srcdir)/$AGENT" \
	    "$(atf_get_srcdir)/$FIXTURE")
	echo "$line" | awk '{ print $2 }'
}

atf_test_case live_capsule_procstat_v_k
live_capsule_procstat_v_k_head()
{
	atf_set "descr" "kern.proc.vmmap and kern.proc.kstack of Capsule"
	common_head
}
live_capsule_procstat_v_k_body()
{
	require_plane
	# Inspect class: the shield refuses debug, not inspect (EACCES before).
	atf_check_equal 0 "$(agent "proc $KERN_PROC_VMMAP 1")"
	atf_check_equal 0 "$(agent "proc $KERN_PROC_KSTACK 1")"
}

atf_test_case live_switchboard_procstat_v_k
live_switchboard_procstat_v_k_head()
{
	atf_set "descr" "kern.proc.vmmap and kern.proc.kstack of SwitchBoard"
	common_head
}
live_switchboard_procstat_v_k_body()
{
	local sb

	require_plane
	sb=$(switchboard_pid)
	atf_check_equal 0 "$(agent "proc $KERN_PROC_VMMAP $sb")"
	atf_check_equal 0 "$(agent "proc $KERN_PROC_KSTACK $sb")"
}

atf_test_case live_ptrace_refused
live_ptrace_refused_head()
{
	atf_set "descr" "PT_ATTACH to Capsule and SwitchBoard is refused"
	common_head
}
live_ptrace_refused_body()
{
	require_plane
	atf_check_equal $EACCES "$(agent "attach 1")"
	atf_check_equal $EACCES "$(agent "attach $(switchboard_pid)")"
}

# usdt_exact PROVIDER PROBE: dtrace -l of an exact description; true when
# it lists a probe (dtrace -l can exit 0 having listed nothing).
usdt_exact()
{
	timeout 60 dtrace -l -n "$1:::$2" >dt.out 2>dt.err
	[ "$(awk 'NR > 1' dt.out | wc -l)" -gt 0 ]
}

atf_test_case live_switchboard_usdt_exact
live_switchboard_usdt_exact_head()
{
	atf_set "descr" "An exact USDT description of SwitchBoard"
	common_head
	atf_set "require.progs" "dtrace"
}
live_switchboard_usdt_exact_body()
{
	local sb

	require_plane
	require_dtrace
	sb=$(switchboard_pid)
	# SwitchBoard registered itself (drti, as root, before its shield).
	dtrace -l -n 'switchboard*:::startup-begin' 2>/dev/null |
	    grep -q "switchboard$sb" || atf_fail "switchboard$sb not registered"
	# Today: the exact description re-grabs and the shield refuses it.
	if usdt_exact "switchboard$sb" startup-begin; then
		atf_fail "exact description matched: $(cat dt.out | tr "\n" " ")"
	fi
	grep -q 'failed to grab process' dt.err ||
	    atf_fail "unexpected error: $(cat dt.err | tr "\n" " ")"
}

atf_test_case live_capsule_usdt_exact
live_capsule_usdt_exact_head()
{
	atf_set "descr" "An exact USDT description of Capsule"
	common_head
	atf_set "require.progs" "dtrace"
}
live_capsule_usdt_exact_body()
{
	require_plane
	require_dtrace
	dtrace -l -n 'capsule*:::startup' 2>/dev/null | grep -q 'capsule1' ||
	    atf_fail "capsule1 not registered"
	if usdt_exact capsule1 startup; then
		atf_fail "exact description matched: $(cat dt.out | tr "\n" " ")"
	fi
	grep -q 'failed to grab process' dt.err ||
	    atf_fail "unexpected error: $(cat dt.err | tr "\n" " ")"
}

atf_test_case live_switchboard_ustack_symbols
live_switchboard_ustack_symbols_head()
{
	atf_set "descr" "ustack() in SwitchBoard is symbolised"
	common_head
	atf_set "require.progs" "dtrace switchboardctl"
}
live_switchboard_ustack_symbols_body()
{
	local sb dt

	require_plane
	require_dtrace
	sb=$(switchboard_pid)
	timeout 60 dtrace -q -n "syscall:::entry /pid == $sb/ { ustack(); exit(0); }" \
	    >dt.out 2>dt.err &
	dt=$!
	sleep 2
	switchboardctl status >/dev/null 2>&1 || true
	wait $dt
	grep -q '0x[0-9a-f]' dt.out || atf_fail "no frames: $(cat dt.out dt.err | tr "\n" " ")"
	# kern.proc.vmmap is inspect-class: frames are symbolised (they were
	# raw addresses while it was refused).
	grep -q '`' dt.out || atf_fail "not symbolised: $(cat dt.out | tr "\n" " ")"
}

atf_test_case live_unit_usdt_exact
live_unit_usdt_exact_head()
{
	atf_set "descr" "The USDT probes of a protected unprivileged unit" \
	    "(bsdlog) are not registered"
	common_head
	atf_set "require.progs" "dtrace"
}
live_unit_usdt_exact_body()
{
	local pid

	require_plane
	require_dtrace
	pid=$(bsdlog_pid)
	[ -n "$pid" ] || atf_skip "no system.Log/bsdlog unit is running"
	# It runs as an unprivileged user in capability mode: drti cannot
	# register it.
	if dtrace -l -n 'bsdlog*:::pool-start' 2>/dev/null |
	    grep -q "bsdlog$pid"; then
		atf_fail "bsdlog$pid registered itself"
	fi
	# Today: the exact description needs a grab, which its shield refuses.
	if usdt_exact "bsdlog$pid" pool-start; then
		atf_fail "exact description matched: $(cat dt.out | tr "\n" " ")"
	fi
	grep -q 'failed to grab process' dt.err ||
	    atf_fail "unexpected error: $(cat dt.err | tr "\n" " ")"
}

atf_test_case live_capsule_securelevel1
live_capsule_securelevel1_head()
{
	atf_set "descr" "At securelevel 1, Capsule (init) allows kern.proc.vmmap" \
	    "and refuses PT_ATTACH; this case raises the securelevel for good"
	common_head
	atf_set "is.exclusive" "true"
}
live_capsule_securelevel1_body()
{
	require_plane
	if [ "$(atf_config_get live_securelevel no)" != yes ]; then
		atf_skip "raises kern.securelevel for good: set live_securelevel=yes" \
		    "in a guest of its own"
	fi
	if [ "$(sysctl -n kern.securelevel)" -lt 1 ]; then
		sysctl kern.securelevel=1 >/dev/null ||
		    atf_fail "cannot raise kern.securelevel"
	fi
	atf_check_equal 1 "$(sysctl -n kern.securelevel)"
	# Q11: init is inspectable at securelevel 1, and debug stays refused
	# (inspect was EACCES while it asked the debug question).
	atf_check_equal 0 "$(agent "proc $KERN_PROC_VMMAP 1")"
	atf_check_equal $EACCES "$(agent "attach 1")"
}

atf_init_test_cases()
{
	atf_add_test_case live_capsule_procstat_v_k
	atf_add_test_case live_switchboard_procstat_v_k
	atf_add_test_case live_ptrace_refused
	atf_add_test_case live_switchboard_usdt_exact
	atf_add_test_case live_capsule_usdt_exact
	atf_add_test_case live_switchboard_ustack_symbols
	atf_add_test_case live_unit_usdt_exact
	atf_add_test_case live_capsule_securelevel1
}
