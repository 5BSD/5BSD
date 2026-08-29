# SPDX-License-Identifier: BSD-2-Clause

atf_test_case config
config_body()
{
	tool="$(atf_get_srcdir)/networkcmpctl_test_bin"
	atf_check -s exit:0 -o inline:'descriptors { network {} }\n' \
	    -e empty "$tool" config
}

atf_test_case arguments
arguments_body()
{
	tool="$(atf_get_srcdir)/networkcmpctl_test_bin"
	atf_check -s exit:64 -e match:'usage: networkcmpctl' "$tool"
	atf_check -s exit:64 -e match:'usage: networkcmpctl' "$tool" info extra
	atf_check -s exit:64 -e match:'usage: networkcmpctl' "$tool" resolve
}

atf_test_case unavailable
unavailable_body()
{
	tool="$(atf_get_srcdir)/networkcmpctl_test_bin"
	atf_check -s exit:69 -e match:'open system.Network' "$tool" info
}

atf_test_case successful_commands
successful_commands_body()
{
	tool="$(atf_get_srcdir)/networkcmpctl_success_bin"
	atf_check -s exit:0 -o match:'version=1 features=0x0000000b' \
	    -o match:'max_resolve_results=16' -e empty "$tool" info
	atf_check -s exit:0 -o match:'count=1 ttl_seconds=60 canonname=localhost' \
	    -o match:'family=inet4 address=127.0.0.1 port=80' \
	    -o match:'socket_type=1 protocol=6' -e empty \
	    "$tool" resolve localhost 80
}

atf_test_case failures_and_cleanup
failures_and_cleanup_body()
{
	tool="$(atf_get_srcdir)/networkcmpctl_success_bin"
	atf_check -s exit:76 -e match:'limits: Input/output error' \
	    -e match:'client-closed' env CMP_TEST_FAIL=limits \
	    CMP_TEST_TRACE_CLOSE=1 "$tool" info
	atf_check -s exit:69 -e match:'resolve localhost: Input/output error' \
	    -e match:'client-closed' env CMP_TEST_FAIL=resolve \
	    CMP_TEST_TRACE_CLOSE=1 "$tool" resolve localhost
	atf_check -s exit:76 -e match:'malformed resolve result' \
	    -e match:'client-closed' env CMP_TEST_BAD_FAMILY=1 \
	    CMP_TEST_TRACE_CLOSE=1 "$tool" resolve localhost
}

atf_init_test_cases()
{
	atf_add_test_case config
	atf_add_test_case arguments
	atf_add_test_case unavailable
	atf_add_test_case successful_commands
	atf_add_test_case failures_and_cleanup
}
