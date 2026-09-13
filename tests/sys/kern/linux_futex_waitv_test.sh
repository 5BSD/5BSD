# SPDX-License-Identifier: BSD-2-Clause
atf_test_case futex_waitv
futex_waitv_head()
{
	atf_set "descr" "Linux futex_waitv: validation, index return, timeouts, signals, shared/private, 128 entries, storms"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "300"
}
futex_waitv_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o futex_waitv \
	    "$(atf_get_srcdir)/linux_futex_waitv.c"
	./futex_waitv 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
atf_init_test_cases()
{
	atf_add_test_case futex_waitv
}
