# SPDX-License-Identifier: BSD-2-Clause
atf_test_case evsig
evsig_head()
{
	atf_set "descr" "Linux epoll_ctl flag rules, rt_sigaction flag masking, clone3 validation"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
}
evsig_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o evsig \
	    "$(atf_get_srcdir)/linux_evsig.c"
	atf_check -s exit:0 -o empty -e empty ./evsig
}
atf_init_test_cases()
{
	atf_add_test_case evsig
}
