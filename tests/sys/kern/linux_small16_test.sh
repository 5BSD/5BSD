# SPDX-License-Identifier: BSD-2-Clause
small_head()
{
 atf_set descr "Linux proc/sysfs compatibility: $1"
 atf_set require.arch amd64
 atf_set require.progs "clang ld.lld brandelf"
 atf_set require.kmods "linux64 linprocfs linsysfs"
 atf_set timeout 60
}
small_run()
{
 [ -r /compat/linux/proc/self/status ] || [ -r /proc/self/status ] || atf_skip "linprocfs must be mounted"
 if [ "$1" = cpu_discovery ]; then
  [ -r /compat/linux/sys/devices/system/cpu/kernel_max ] || [ -r /sys/devices/system/cpu/kernel_max ] || atf_skip "linsysfs must be mounted"
 fi
 atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror -o small16 "$(atf_get_srcdir)/linux_small16.c"
 atf_check -s exit:0 -o empty -e empty brandelf -t Linux small16
 atf_check -s exit:0 -o empty -e empty ./small16 "$1"
}
atf_test_case slack_file
slack_file_head() { small_head slack_file; }
slack_file_body() { small_run slack_file; }
atf_test_case slack_thread
slack_thread_head() { small_head slack_thread; }
slack_thread_body() { small_run slack_thread; }
atf_test_case slack_permissions
slack_permissions_head() { small_head slack_permissions; atf_set require.user root; }
slack_permissions_body() { small_run slack_permissions; }
atf_test_case slack_rt
slack_rt_head() { small_head slack_rt; atf_set require.user root; }
slack_rt_body() { small_run slack_rt; }
atf_test_case oom_views
oom_views_head() { small_head oom_views; atf_set require.user root; }
oom_views_body() { small_run oom_views; }
atf_test_case oom_parse
oom_parse_head() { small_head oom_parse; atf_set require.user root; }
oom_parse_body() { small_run oom_parse; }
atf_test_case oom_permissions
oom_permissions_head() { small_head oom_permissions; atf_set require.user root; }
oom_permissions_body() { small_run oom_permissions; }
atf_test_case oom_lifecycle
oom_lifecycle_head() { small_head oom_lifecycle; atf_set require.user root; }
oom_lifecycle_body() { small_run oom_lifecycle; }
atf_test_case status_umask
status_umask_head() { small_head status_umask; }
status_umask_body() { small_run status_umask; }
atf_test_case status_nnp
status_nnp_head() { small_head status_nnp; }
status_nnp_body() { small_run status_nnp; }
atf_test_case status_affinity
status_affinity_head() { small_head status_affinity; }
status_affinity_body() { small_run status_affinity; }
atf_test_case status_fdsize
status_fdsize_head() { small_head status_fdsize; }
status_fdsize_body() { small_run status_fdsize; }
atf_test_case status_switches
status_switches_head() { small_head status_switches; }
status_switches_body() { small_run status_switches; }
atf_test_case status_hwm
status_hwm_head() { small_head status_hwm; }
status_hwm_body() { small_run status_hwm; }
atf_test_case status_caps
status_caps_head() { small_head status_caps; }
status_caps_body() { small_run status_caps; }
atf_test_case thp_state
thp_state_head() { small_head thp_state; }
thp_state_body() { small_run thp_state; }
atf_test_case thp_lifecycle
thp_lifecycle_head() { small_head thp_lifecycle; }
thp_lifecycle_body() { small_run thp_lifecycle; }
atf_test_case stat_rsslim
stat_rsslim_head() { small_head stat_rsslim; }
stat_rsslim_body() { small_run stat_rsslim; }
atf_test_case stat_exitsignal
stat_exitsignal_head() { small_head stat_exitsignal; }
stat_exitsignal_body() { small_run stat_exitsignal; }
atf_test_case cpu_discovery
cpu_discovery_head() { small_head cpu_discovery; }
cpu_discovery_body() { small_run cpu_discovery; }
atf_init_test_cases()
{
 atf_add_test_case slack_file
 atf_add_test_case slack_thread
 atf_add_test_case slack_permissions
 atf_add_test_case slack_rt
 atf_add_test_case oom_views
 atf_add_test_case oom_parse
 atf_add_test_case oom_permissions
 atf_add_test_case oom_lifecycle
 atf_add_test_case status_umask
 atf_add_test_case status_nnp
 atf_add_test_case status_affinity
 atf_add_test_case status_fdsize
 atf_add_test_case status_switches
 atf_add_test_case status_hwm
 atf_add_test_case status_caps
 atf_add_test_case thp_state
 atf_add_test_case thp_lifecycle
 atf_add_test_case stat_rsslim
 atf_add_test_case stat_exitsignal
 atf_add_test_case cpu_discovery
}
