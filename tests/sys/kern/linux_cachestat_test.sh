# SPDX-License-Identifier: BSD-2-Clause
atf_test_case cachestat
cachestat_head()
{
	atf_set "descr" "Linux cachestat(2): residency, sub-range, beyond-EOF, validation, EFAULT"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
cachestat_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o cachestat \
	    "$(atf_get_srcdir)/linux_cachestat.c"
	./cachestat 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
atf_init_test_cases()
{
	atf_add_test_case cachestat
}
