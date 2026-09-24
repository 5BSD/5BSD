# SPDX-License-Identifier: BSD-2-Clause
atf_test_case ptrace_interrupt
ptrace_interrupt_head()
{
	atf_set "descr" "Linux PTRACE_INTERRUPT seized-stop lifecycle and negative cases"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf df awk"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
ptrace_interrupt_body()
{
	df -T / | awk 'NR == 2 && $2 == "zfs" {ok=1} END {exit !ok}' ||
	    atf_fail "requires the disposable ZFS-root VM"
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o ptrace_interrupt \
	    "$(atf_get_srcdir)/linux_ptrace_interrupt.c"
	atf_check -s exit:0 brandelf -t Linux ptrace_interrupt
	atf_check -s exit:0 -o empty -e empty ./ptrace_interrupt
}
atf_init_test_cases()
{
	atf_add_test_case ptrace_interrupt
}
