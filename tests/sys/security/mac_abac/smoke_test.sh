#!/usr/libexec/atf-sh

atf_test_case status
status_head()
{
	atf_set "descr" "mac_abac module and control utility expose their basic ABI"
}
status_body()
{
	atf_check -s exit:0 -o match:'security.mac.mac_abac.mode' \
		sysctl security.mac.mac_abac.mode
	atf_check -s exit:0 /usr/sbin/mac_abac_ctl status
}

atf_init_test_cases()
{
	atf_add_test_case status
}
