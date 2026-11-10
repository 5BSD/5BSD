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
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "300"
}
linux_procctl_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o linux_procctl \
	    "$(atf_get_srcdir)/linux_procctl.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux linux_procctl

	./linux_procctl "$(pwd)/linux_procctl" >out.txt 2>&1; rc=$?
	cat out.txt
	[ $rc -eq 0 ] || atf_fail "rows not as recorded (exit $rc); see stdout"
}

atf_init_test_cases()
{
	atf_add_test_case linux_procctl
}
