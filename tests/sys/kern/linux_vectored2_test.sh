# SPDX-License-Identifier: BSD-2-Clause
atf_test_case vectored2
vectored2_head()
{
	atf_set "descr" "Linux preadv2/pwritev2 offsets, vectors, flags and pipes"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
}
vectored2_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o vectored2 \
	    "$(atf_get_srcdir)/linux_vectored2.c"
	atf_check -s exit:0 -o empty -e empty ./vectored2
}
atf_init_test_cases()
{
	atf_add_test_case vectored2
}
