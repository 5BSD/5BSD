# SPDX-License-Identifier: BSD-2-Clause
atf_test_case parity
parity_head()
{
	atf_set "descr" "Linux arm64 AIO, quota, remap, statx and thread-name parity"
	atf_set "require.arch" "arm64 aarch64"
	atf_set "require.progs" "clang ld.lld brandelf timeout"
	atf_set "require.kmods" "linux64"
}
parity_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=aarch64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o parity \
	    "$(atf_get_srcdir)/linux_arm64_parity.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux parity
	atf_check -s exit:0 -o empty -e empty timeout 30 ./parity
}
atf_init_test_cases()
{
	atf_add_test_case parity
}
