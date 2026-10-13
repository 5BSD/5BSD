# SPDX-License-Identifier: BSD-2-Clause
hints_head()
{
	atf_set "descr" "$1"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux64"
	atf_set "timeout" "60"
}
hints_run()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o timerhints \
	    "$(atf_get_srcdir)/linux_timerhints.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux timerhints
	atf_check -s exit:0 -o empty -e empty ./timerhints "$1"
}
atf_test_case slack_state
slack_state_head() { hints_head "Linux timer slack set/get, full-width values and reset"; }
slack_state_body() { hints_run slack_state; }
atf_test_case slack_fork
slack_fork_head() { hints_head "Linux timer slack fork inherits current value as default"; }
slack_fork_body() { hints_run slack_fork; }
atf_test_case slack_thread
slack_thread_head() { hints_head "Linux timer slack is per-thread and follows the forking thread"; }
slack_thread_body() { hints_run slack_thread; }
atf_test_case slack_exec
slack_exec_head() { hints_head "Linux timer slack current and default values survive exec"; }
slack_exec_body() { hints_run slack_exec; }
atf_test_case slack_realtime
slack_realtime_head()
{
	hints_head "Linux timer slack follows local and remote scheduler transitions"
	atf_set "require.user" "root"
}
slack_realtime_body() { hints_run slack_realtime; }
atf_test_case slack_sleep
slack_sleep_head() { hints_head "Linux timer slack does not allow early nanosleep expiry"; }
slack_sleep_body() { hints_run slack_sleep; }
hints_sysfs()
{
	[ -r /compat/linux/sys/kernel/mm/transparent_hugepage/enabled ] || \
	    [ -r /sys/kernel/mm/transparent_hugepage/enabled ] || \
	    atf_skip "linsysfs must be mounted at /compat/linux/sys or /sys"
	hints_run "$1"
}
atf_test_case thp_read
thp_read_head() { hints_head "Linux THP status reports never with stable partial reads and seeks"; }
thp_read_body() { hints_sysfs thp_read; }
atf_test_case thp_readonly
thp_readonly_head() { hints_head "Unsupported Linux THP cannot be enabled through sysfs"; }
thp_readonly_body() { hints_sysfs thp_readonly; }
atf_init_test_cases()
{
	atf_add_test_case slack_state
	atf_add_test_case slack_fork
	atf_add_test_case slack_thread
	atf_add_test_case slack_exec
	atf_add_test_case slack_realtime
	atf_add_test_case slack_sleep
	atf_add_test_case thp_read
	atf_add_test_case thp_readonly
}
