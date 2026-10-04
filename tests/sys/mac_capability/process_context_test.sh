# SPDX-License-Identifier: BSD-2-Clause
require_context()
{
 [ "$(sysctl -n kern.features.cap_process 2>/dev/null)" = 1 ] ||
     atf_skip "kernel process context support is unavailable"
}
atf_test_case lifecycle
lifecycle_head()
{
 atf_set descr "Kernel discovery reference lifetime, exec, UID isolation and attenuation"
 atf_set require.user root
 atf_set timeout 120
}
lifecycle_body()
{
 require_context
 atf_check -s exit:0 -o match:PROCESS_CONTEXT_KERNEL_PASS "$(atf_get_srcdir)/process_context_helper"
}
atf_test_case edge_cases
edge_cases_head()
{
 atf_set descr "Subtree isolation, rfork/pdfork, exhaustion, jail and concurrent replacement"
 atf_set require.user root
 atf_set timeout 120
}
edge_cases_body()
{
 require_context
 atf_check -s exit:0 -o match:PROCESS_CONTEXT_EDGE_PASS "$(atf_get_srcdir)/process_context_edge_helper"
}
atf_test_case ipc_attribution
ipc_attribution_head()
{
 atf_set descr "IPC process lifetime identity, responsibility and old receive ABI"
 atf_set timeout 60
}
ipc_attribution_body()
{
 require_context
 atf_check -s exit:0 -o match:PROCESS_CONTEXT_IPC_PASS "$(atf_get_srcdir)/process_context_ipc_helper"
}
atf_init_test_cases()
{
 atf_add_test_case lifecycle
 atf_add_test_case edge_cases
 atf_add_test_case ipc_attribution
}
