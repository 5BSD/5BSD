#
# SPDX-License-Identifier: BSD-2-Clause
#
# A short bidirectional soak on every test run; run ipc_soak directly with a
# longer duration (for example 3600 seconds) for sustained validation.

atf_test_case short_soak
short_soak_head()
{
	atf_set "descr" "15 s of bidirectional traffic with descriptors, every size class, cancellation and reconnects"
	atf_set "require.user" "root"
	atf_set "require.kmods" "mac_capability mac_capability_channel"
	atf_set "timeout" "120"
}
short_soak_body()
{
	atf_check -s exit:0 -o match:'ipc_soak: PASS' \
	    "$(atf_get_srcdir)/ipc_soak" 15 0x5bd
}

atf_init_test_cases()
{
	atf_add_test_case short_soak
}
