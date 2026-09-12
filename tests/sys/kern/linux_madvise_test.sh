# SPDX-License-Identifier: BSD-2-Clause
atf_test_case madvise
madvise_head()
{
	atf_set "descr" "Linux madvise hints: COLD/PAGEOUT preserve contents, KSM/THP hints, rejected advice"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
}
madvise_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o madvise \
	    "$(atf_get_srcdir)/linux_madvise.c"
	atf_check -s exit:0 -o empty -e empty ./madvise
}
atf_init_test_cases()
{
	atf_add_test_case madvise
}
