# SPDX-License-Identifier: BSD-2-Clause
atf_test_case peerpidfd
peerpidfd_head()
{
	atf_set "descr" "Linux SO_PEERPIDFD, SOL_UDP options, SHM/SEM_STAT_ANY, TIOCOUTQ/TCSBRK/TIOCSTI"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
peerpidfd_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o peerpidfd \
	    "$(atf_get_srcdir)/linux_peerpidfd.c"
	./peerpidfd 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
atf_init_test_cases()
{
	atf_add_test_case peerpidfd
}
