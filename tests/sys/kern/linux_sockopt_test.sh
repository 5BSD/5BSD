# SPDX-License-Identifier: BSD-2-Clause
atf_test_case sockopt
sockopt_head()
{
	atf_set "descr" "Linux setsockopt/getsockopt and IP ancillary data translation"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
}
sockopt_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o sockopt \
	    "$(atf_get_srcdir)/linux_sockopt.c"
	atf_check -s exit:0 -o empty -e empty ./sockopt
}
atf_init_test_cases()
{
	atf_add_test_case sockopt
}
