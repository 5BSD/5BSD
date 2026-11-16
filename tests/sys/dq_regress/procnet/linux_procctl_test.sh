# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# The Linux-ABI half of procnet_control_test: linux_procctl.c is a
# freestanding static amd64 Linux program (no Linux libc) built here, as
# fdops/linux_fdops.c is, and run under linux64.ko.  Every row expects the
# behaviour of the kernel before the supervisor-control series (commit
# a9935859e88) for a process that is not attached to a dq(4) controller.
#
# Modules: the capability plane refuses a late kldload, so linux64 must be
# preloaded, e.g. LOADER_EXTRA='linux64_load="YES"' for
# tools/build/fuchsia/vm-provider.sh.

atf_test_case linux_procctl
linux_procctl_head()
{
	atf_set "descr" "Linux fork, clone, exec, exit, wait and kill, unattached"
	atf_set "require.arch" "amd64"
	atf_set "require.user" "root"
	atf_set "timeout" "300"
}
linux_procctl_body()
{
	# A pin does not skip: what it needs is there, or it fails.
	for prog in clang ld.lld brandelf; do
		command -v $prog >/dev/null ||
		    atf_fail "$prog is needed to build the Linux program"
	done
	kldstat -q -m linux64elf ||
	    atf_fail "the 64-bit Linux ABI (linux64) is not loaded"

	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o linux_procctl \
	    "$(atf_get_srcdir)/linux_procctl.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux linux_procctl

	./linux_procctl "$(pwd)/linux_procctl" >out.txt 2>&1; rc=$?
	cat out.txt
	[ $rc -eq 0 ] || atf_fail "rows not as recorded (exit $rc); see stdout"
}

# The Linux ptrace programs of tests/sys/kern (PTRACE_SEIZE, INTERRUPT and
# LISTEN), the other Linux half of the unattached baseline.  Their own
# wrappers there belong to the Linuxulator gate, which refuses any guest
# whose root is not ZFS; this guest's root is UFS, so they fail in it by
# design.  The programs themselves do not care, and are built and run
# here the same way, from the installed sources.
atf_test_case linux_ptrace
linux_ptrace_head()
{
	atf_set "descr" "Linux PTRACE_SEIZE, INTERRUPT and LISTEN, unattached"
	atf_set "require.arch" "amd64"
	atf_set "require.user" "root"
	atf_set "timeout" "600"
}
linux_ptrace_body()
{
	for prog in clang ld.lld brandelf; do
		command -v $prog >/dev/null ||
		    atf_fail "$prog is needed to build the Linux programs"
	done
	kldstat -q -m linux64elf ||
	    atf_fail "the 64-bit Linux ABI (linux64) is not loaded"
	kern="$(atf_get_srcdir)/../../kern"

	for t in seize interrupt listen; do
		[ -f "$kern/linux_ptrace_$t.c" ] ||
		    atf_fail "$kern/linux_ptrace_$t.c is not installed"
		atf_check -s exit:0 -o empty -e empty \
		    clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib \
		    -static -fno-stack-protector -fno-builtin -O2 -Wall \
		    -Wextra -Werror -o ptrace_$t "$kern/linux_ptrace_$t.c"
		atf_check -s exit:0 brandelf -t Linux ptrace_$t
	done
	atf_check -s exit:0 -o empty -e empty ./ptrace_seize
	atf_check -s exit:0 -o empty -e empty ./ptrace_interrupt
	atf_check -s exit:0 -o empty -e match:'^ok target_errors' \
	    ./ptrace_listen
}

# The other ptrace programs of the linuxulator gate.  That gate
# (tools/test/linuxulator) stages them by hand into ZFS images and runs
# them from guest-ptrace.sh, guest-peer-events.sh, guest-xstate-mcast.sh
# and guest-signal-modes.sh; no kyua case ran them.  The two cases below
# run each of those invocations once (the gate does three rounds), and
# go on after a failure so that the result names every program that
# failed.  Not run: "linux_ptrace_registers no_xsave" and
# "linux_ptrace_xstate no_xsave", which the gate runs in a separate
# guest whose CPU has no XSAVE.
gate_build()	# output source [flag ...]
{
	gate_out=$1
	gate_src=$2
	shift 2
	[ -f "$gate_src" ] || atf_fail "$gate_src is not installed"
	atf_check -s exit:0 -o empty -e empty \
	    clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib \
	    -static -fno-stack-protector -fno-builtin -O2 -Wall \
	    -Wextra -Werror "$@" -o "$gate_out" "$gate_src"
	atf_check -s exit:0 brandelf -t Linux "$gate_out"
}

gate_run()	# seconds program [argument ...]
{
	gate_secs=$1
	shift
	gate_label="$(basename "$1")"
	gate_first=1
	for gate_arg; do
		[ "$gate_first" = 1 ] || gate_label="$gate_label $gate_arg"
		gate_first=0
	done
	if timeout -k 3 "$gate_secs" "$@" > gate.out 2>&1; then
		echo "ok: $gate_label"
	else
		echo "FAILED ($?): $gate_label"
		cat gate.out
		echo "$gate_label" >> gate.failed
	fi
}

gate_result()
{
	[ ! -s gate.failed ] ||
	    atf_fail "failed: $(tr '\n' ';' < gate.failed)"
}

atf_test_case linux_ptrace_gate cleanup
linux_ptrace_gate_head()
{
	atf_set "descr" "The Linux ptrace programs of the linuxulator gate"
	atf_set "require.arch" "amd64"
	atf_set "require.user" "root"
	atf_set "timeout" "3600"
}
linux_ptrace_gate_body()
{
	for prog in clang ld.lld brandelf; do
		command -v $prog >/dev/null ||
		    atf_fail "$prog is needed to build the Linux programs"
	done
	kldstat -q -m linux64elf ||
	    atf_fail "the 64-bit Linux ABI (linux64) is not loaded"
	kern="$(atf_get_srcdir)/../../kern"

	# The unprivileged cases must be able to reach the programs.
	dir="$(mktemp -d /tmp/linux_ptrace_gate.XXXXXX)" ||
	    atf_fail "no directory for the programs"
	echo "$dir" > gate.dir
	chmod 0755 "$dir"
	for t in ptrace_registers ptrace_lifecycle ptrace_user \
	    ptrace_metadata ptrace_sigmask proc_task ptrace_events \
	    ptrace_xstate ptrace_pending ptrace_exit_lifecycle; do
		gate_build "$dir/linux_$t" "$kern/linux_$t.c"
	done

	# guest-ptrace.sh
	for c in fp_read fp_write fp_setregset fp_bad_mxcsr gpr_read \
	    gpr_write gpr_partial gpr_rax gpr_bad_base lengths faults \
	    unknown xstate_read protected_memory bounds permissions \
	    unprivileged gpr_fault_progress tls_write thread_target \
	    repeated; do
		gate_run 60 "$dir/linux_ptrace_registers" $c
	done
	for t in ptrace_lifecycle ptrace_user ptrace_metadata \
	    ptrace_sigmask proc_task; do
		gate_run 60 "$dir/linux_$t"
	done
	gate_run 60 "$dir/linux_ptrace_user" unprivileged
	for user in root unprivileged; do
		# guest-xstate-mcast.sh
		for c in roundtrip write_resume lengths invalid init_state \
		    faults metadata; do
			gate_run 30 "$dir/linux_ptrace_xstate" $c $user
		done
		# guest-peer-events.sh
		for c in exec fork vfork clone exit signal vfork_done \
		    selective isolation waitid; do
			gate_run 60 "$dir/linux_ptrace_events" $c $user
		done
		# guest-signal-modes.sh
		for c in shared thread standard validation faults reattach \
		    lifetime; do
			gate_run 60 "$dir/linux_ptrace_pending" $c $user
		done
	done
	# In no gate script; its source says how it is run.
	gate_run 60 "$dir/linux_ptrace_exit_lifecycle"
	gate_result
}
linux_ptrace_gate_cleanup()
{
	[ ! -s gate.dir ] || rm -rf "$(cat gate.dir)"
}

atf_test_case linux_ptrace_gate_native
linux_ptrace_gate_native_head()
{
	atf_set "descr" "The native ptrace programs of the linuxulator gate"
	atf_set "require.arch" "amd64"
	atf_set "require.user" "root"
	atf_set "timeout" "600"
}
linux_ptrace_gate_native_body()
{
	for prog in clang ld.lld brandelf; do
		command -v $prog >/dev/null ||
		    atf_fail "$prog is needed to build the Linux probe"
	done
	kldstat -q -m linux64elf ||
	    atf_fail "the 64-bit Linux ABI (linux64) is not loaded"
	kern="$(atf_get_srcdir)/../../kern"
	for t in linux_ptrace_kill_native linux_ptrace_native \
	    linux_ptrace_capmode ptrace_exit_native; do
		[ -x "$kern/$t" ] || atf_fail "$kern/$t is not installed"
	done
	gate_build "$(pwd)/ptrace_capmode_probe" \
	    "$kern/linux_ptrace_capmode.c" -DLINUX_PROBE

	gate_run 60 "$kern/linux_ptrace_kill_native"
	gate_run 60 "$kern/linux_ptrace_native"
	gate_run 60 "$kern/linux_ptrace_capmode" "$(pwd)/ptrace_capmode_probe"
	gate_run 60 "$kern/ptrace_exit_native"
	gate_result
}

atf_init_test_cases()
{
	atf_add_test_case linux_procctl
	atf_add_test_case linux_ptrace
	atf_add_test_case linux_ptrace_gate
	atf_add_test_case linux_ptrace_gate_native
}
