# SPDX-License-Identifier: BSD-2-Clause
quickwins_head()
{
	atf_set "descr" "$1"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux64"
	atf_set "timeout" "60"
}
quickwins_run()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o quickwins \
	    "$(atf_get_srcdir)/linux_quickwins.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux quickwins
	atf_check -s exit:0 -o empty -e empty ./quickwins "$1"
}
atf_test_case no_new_privs
no_new_privs_head() { quickwins_head "Linux no-new-privileges argument validation and irreversible state"; }
no_new_privs_body() { quickwins_run no_new_privs; }
atf_test_case memfd_exec
memfd_exec_head() { quickwins_head "Linux executable memfd flags, mode, mappings and seals"; }
memfd_exec_body() { quickwins_run memfd_exec; }
atf_test_case memfd_noexec
memfd_noexec_head() { quickwins_head "Linux no-execute memfd mode, mmap and seals"; }
memfd_noexec_body() { quickwins_run memfd_noexec; }
atf_test_case vma_name
vma_name_head() { quickwins_head "Linux anonymous VMA names and inheritance"; }
vma_name_body() { quickwins_proc vma_name; }
quickwins_proc()
{
	[ -r /compat/linux/proc/self/cgroup ] || [ -r /proc/self/cgroup ] || \
	    atf_skip "linprocfs must be mounted at /compat/linux/proc or /proc"
	quickwins_run "$1"
}
atf_test_case thread_cgroup
thread_cgroup_head() { quickwins_head "Linux cgroup views for leader and nonleader threads"; }
thread_cgroup_body() { quickwins_proc thread_cgroup; }
atf_test_case thread_cpuset
thread_cpuset_head() { quickwins_head "Linux cpuset views for leader and nonleader threads"; }
thread_cpuset_body() { quickwins_proc thread_cpuset; }
atf_init_test_cases()
{
	atf_add_test_case no_new_privs
	atf_add_test_case memfd_exec
	atf_add_test_case memfd_noexec
	atf_add_test_case vma_name
	atf_add_test_case thread_cgroup
	atf_add_test_case thread_cpuset
}
