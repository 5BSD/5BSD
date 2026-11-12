# SPDX-License-Identifier: BSD-2-Clause
#
# The Linux-ABI half of the boundary pins (dq-boundary design, part b0,
# section 6.1 items 1, 3, 6 and 18): linux_boundary.c is a freestanding
# static amd64 Linux program (no Linux libc) built here, as
# fdops/linux_fdops.c is, and run under linux64.ko as an unprivileged
# uid that is not attached to a dq(4) controller.  It prints one row per
# call; linux_boundary_main.exp is what it printed on the kernel of
# commit f52f6da3d34.  No boundary slice may change a row: they are the
# unattached side.  The attached target is
# procnet_outside_test:linux_probe_attached_target.
#
# Modules: the capability plane refuses a late kldload, so linux64 and
# linprocfs must be preloaded and linprocfs mounted on /compat/linux/proc
# (LOADER_EXTRA and LINUX_COMPAT_DIR of tools/build/fuchsia/vm-provider.sh).

atf_test_case linux_boundary cleanup
linux_boundary_head()
{
	atf_set "descr" "Linux by-pid calls, TIOCSTI and System V IPC, unattached"
	atf_set "require.arch" "amd64"
	atf_set "require.user" "root"
	atf_set "timeout" "900"
}
linux_boundary_body()
{
	# A pin does not skip: what it needs is there, or it fails.
	for prog in clang ld.lld brandelf; do
		command -v $prog >/dev/null ||
		    atf_fail "$prog is needed to build the Linux program"
	done
	kldstat -q -m linux64elf ||
	    atf_fail "the 64-bit Linux ABI (linux64) is not loaded"
	[ -e /compat/linux/proc/sysvipc/shm ] ||
	    atf_fail "linprocfs is not mounted on /compat/linux/proc"

	# The kyua work directory may be private to root.
	dir=/tmp/procnet.linux_boundary
	rm -rf $dir
	mkdir -m 755 $dir || atf_fail "mkdir $dir"
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o $dir/linux_boundary \
	    "$(atf_get_srcdir)/linux_boundary.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux \
	    $dir/linux_boundary

	# The rows go to a file the cleanup can still show if the body is
	# cut short.
	$dir/linux_boundary run $dir/linux_boundary >$dir/out.txt 2>&1; rc=$?
	cp $dir/out.txt out.txt
	cat out.txt
	[ $rc -eq 0 ] || atf_fail "the program failed (exit $rc)"
	cmp -s out.txt "$(atf_get_srcdir)/linux_boundary_main.exp" || {
		diff -u "$(atf_get_srcdir)/linux_boundary_main.exp" out.txt
		atf_fail "rows not as recorded; see the diff on stdout"
	}
}
linux_boundary_cleanup()
{
	[ ! -e out.txt ] && [ -e /tmp/procnet.linux_boundary/out.txt ] &&
	    cat /tmp/procnet.linux_boundary/out.txt
	rm -rf /tmp/procnet.linux_boundary
}

atf_init_test_cases()
{
	atf_add_test_case linux_boundary
}
