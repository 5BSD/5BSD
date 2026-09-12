# SPDX-License-Identifier: BSD-2-Clause
atf_test_case pidfd
pidfd_head()
{
	atf_set "descr" "Linux pidfd_open/pidfd_send_signal/pidfd_getfd: exit readiness, signals, fd theft"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
	atf_set "timeout" "60"
}
pidfd_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o pidfd \
	    "$(atf_get_srcdir)/linux_pidfd.c"
	atf_check -s exit:0 -o empty -e empty ./pidfd
}
atf_init_test_cases()
{
	atf_add_test_case pidfd
}
