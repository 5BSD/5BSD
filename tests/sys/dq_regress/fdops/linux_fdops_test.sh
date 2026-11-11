# SPDX-License-Identifier: BSD-2-Clause
#
# The Linux-ABI half of the fdops regression test: linux_fdops.c is a
# freestanding static amd64 Linux program (no Linux libc) built here, as the
# tests/sys/kern/linux_*_test.sh programs are, and run under linux64.ko.
# Every cell expects FreeBSD's behaviour at 3b9f9873d291; see the list at
# the top of linux_fdops.c for the cells ux-0 slice 1 restored.
#
# Modules: the capability plane refuses a late kldload, so linux64 (and,
# for the O_PATH reopen of a pipe, linprocfs) must be preloaded, e.g.
#   LOADER_EXTRA='linux64_load="YES"
#   linprocfs_load="YES"'
# for tools/build/fuchsia/vm-provider.sh.  Without linprocfs the opath_pipe
# kind is reported as skipped and its cells are not run.

atf_test_case linux_fdops cleanup
linux_fdops_head()
{
	atf_set "descr" "Linux-ABI calls rewired through fileops, on every kind"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "600"
}
linux_fdops_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o linux_fdops \
	    "$(atf_get_srcdir)/linux_fdops.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux linux_fdops

	lproc=-
	mkdir lproc
	if mount -t linprocfs linprocfs lproc 2>/dev/null; then
		lproc="$(pwd)/lproc"
	else
		echo "linprocfs not mounted: opath_pipe cells not run" >&2
	fi
	flags=-
	pre1c=$(atf_config_get pre1c no)
	case "$pre1c" in
	[Yy][Ee][Ss]|[Tt][Rr][Uu][Ee]|1)
		if [ "$(sysctl -n kern.features.invariants 2>/dev/null)" = 1 ]
		then
			flags=skipfsyncfifo
		fi
		;;
	esac
	./linux_fdops "$lproc" "$flags" >out.txt 2>&1; rc=$?
	cat out.txt
	[ $rc -eq 0 ] || atf_fail "cells not as base (exit $rc); see stdout"
}
linux_fdops_cleanup()
{
	umount -f "$(pwd)/lproc" 2>/dev/null || true
}

atf_init_test_cases()
{
	atf_add_test_case linux_fdops
}
