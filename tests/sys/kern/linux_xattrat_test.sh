# SPDX-License-Identifier: BSD-2-Clause
atf_test_case xattrat
xattrat_head()
{
	atf_set "descr" "Linux setxattrat/getxattrat/listxattrat/removexattrat"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
}
xattrat_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o xattrat \
	    "$(atf_get_srcdir)/linux_xattrat.c"
	# stderr carries a note when the filesystem has no extattr support.
	atf_check -s exit:0 -o empty -e ignore ./xattrat
}
atf_init_test_cases()
{
	atf_add_test_case xattrat
}
