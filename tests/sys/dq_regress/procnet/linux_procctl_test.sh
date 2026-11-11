# SPDX-License-Identifier: BSD-2-Clause
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

atf_init_test_cases()
{
	atf_add_test_case linux_procctl
	atf_add_test_case linux_ptrace
}
