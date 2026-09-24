# SPDX-License-Identifier: BSD-2-Clause
atf_test_case fileattr
fileattr_head()
{
	atf_set "descr" "Linux file_getattr and file_setattr ABI, file flags, path resolution, and negative cases"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
}
fileattr_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o fileattr \
	    "$(atf_get_srcdir)/linux_fileattr.c"
	atf_check -s exit:0 -o empty -e empty ./fileattr
}
atf_init_test_cases()
{
	atf_add_test_case fileattr
}
