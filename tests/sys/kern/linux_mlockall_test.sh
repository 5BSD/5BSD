# SPDX-License-Identifier: BSD-2-Clause
atf_test_case mlockall
mlockall_head()
{
	atf_set "descr" "Linux mlockall MCL_ONFAULT and getrandom GRND_INSECURE flag handling"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
mlockall_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o mlockall \
	    "$(atf_get_srcdir)/linux_mlockall.c"
	./mlockall 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
atf_init_test_cases()
{
	atf_add_test_case mlockall
}
