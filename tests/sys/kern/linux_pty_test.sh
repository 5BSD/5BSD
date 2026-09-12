# SPDX-License-Identifier: BSD-2-Clause
atf_test_case pty
pty_head()
{
	atf_set "descr" "Linux TIOCGPTPEER opens the slave of a pty master"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
}
pty_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o pty \
	    "$(atf_get_srcdir)/linux_pty.c"
	atf_check -s exit:0 -o empty -e empty ./pty
}
atf_init_test_cases()
{
	atf_add_test_case pty
}
