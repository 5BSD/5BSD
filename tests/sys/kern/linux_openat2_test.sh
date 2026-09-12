# SPDX-License-Identifier: BSD-2-Clause
atf_test_case openat2
openat2_head()
{
	atf_set "descr" "Linux openat2 flags/resolve scoping, fchmodat2 and execveat"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
}
openat2_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o openat2 \
	    "$(atf_get_srcdir)/linux_openat2.c"
	atf_check -s exit:0 -o empty -e empty ./openat2
}
atf_init_test_cases()
{
	atf_add_test_case openat2
}
