# SPDX-License-Identifier: BSD-2-Clause
atf_test_case smoke
smoke_head()
{
	atf_set "descr" "Linux riscv64 syscall, hwprobe, icache and signal ABI smoke"
	atf_set "require.arch" "riscv64"
	atf_set "require.progs" "clang ld.lld brandelf timeout"
	atf_set "require.kmods" "linux64"
}
smoke_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=riscv64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o smoke \
	    "$(atf_get_srcdir)/linux_riscv64_smoke.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux smoke
	atf_check -s exit:0 -o empty -e empty timeout 30 ./smoke
}
atf_init_test_cases()
{
	atf_add_test_case smoke
}
