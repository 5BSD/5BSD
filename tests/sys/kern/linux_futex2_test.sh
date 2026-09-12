# SPDX-License-Identifier: BSD-2-Clause
atf_test_case futex2
futex2_head()
{
	atf_set "descr" "Linux futex_wait/futex_wake/futex_requeue and futex(2) requeue semantics"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
	atf_set "timeout" "120"
}
futex2_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o futex2 \
	    "$(atf_get_srcdir)/linux_futex2.c"
	atf_check -s exit:0 -o empty -e empty ./futex2
}
atf_init_test_cases()
{
	atf_add_test_case futex2
}
