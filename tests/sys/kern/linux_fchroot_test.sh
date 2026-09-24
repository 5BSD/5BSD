# SPDX-License-Identifier: BSD-2-Clause
atf_test_case fchroot
fchroot_head()
{
	atf_set "descr" "Linux fchroot descriptor, flag, permission, and isolation semantics"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
}
fchroot_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o fchroot \
	    "$(atf_get_srcdir)/linux_fchroot.c"
	atf_check -s exit:0 -o empty -e empty ./fchroot
}
atf_init_test_cases()
{
	atf_add_test_case fchroot
}
