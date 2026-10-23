# SPDX-License-Identifier: BSD-2-Clause
atf_test_case cookie
cookie_head()
{
	atf_set "descr" "Linux32 SO_COOKIE identity and optlen"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux"
}
cookie_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=i386-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector \
	    -O2 -Wall -Wextra -Werror -o linux32_cookie \
	    "$(atf_get_srcdir)/linux32_socket_cookie.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux linux32_cookie
	atf_check -s exit:0 -o empty -e empty ./linux32_cookie
}
atf_init_test_cases()
{
	atf_add_test_case cookie
}
