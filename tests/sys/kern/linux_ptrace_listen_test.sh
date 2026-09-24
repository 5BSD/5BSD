# SPDX-License-Identifier: BSD-2-Clause
atf_test_case ptrace_listen
ptrace_listen_head()
{
	atf_set "descr" "Linux PTRACE_LISTEN group-stop, visibility, and wakeup semantics"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf df awk"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "90"
}
ptrace_listen_body()
{
	df -T / | awk 'NR == 2 && $2 == "zfs" {ok=1} END {exit !ok}' ||
	    atf_fail "requires the disposable ZFS-root VM"
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o ptrace_listen \
	    "$(atf_get_srcdir)/linux_ptrace_listen.c"
	atf_check -s exit:0 brandelf -t Linux ptrace_listen
	atf_check -s exit:0 -o empty -e match:'^ok target_errors' \
	    ./ptrace_listen
}
atf_init_test_cases()
{
	atf_add_test_case ptrace_listen
}
