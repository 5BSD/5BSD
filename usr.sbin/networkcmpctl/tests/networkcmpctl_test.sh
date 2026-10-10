# SPDX-License-Identifier: BSD-2-Clause

atf_test_case config
config_body()
{
	tool="$(atf_get_srcdir)/networkcmpctl_test_bin"
	atf_check -s exit:0 -o match:'No manifest declaration is required' \
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
	atf_check -s exit:69 -e match:'open system.Network' \
	    env -u SERVICE_LOOKUP_FD "$tool" info 3>&-
}

atf_test_case successful_commands
successful_commands_body()
{
	tool="$(atf_get_srcdir)/networkcmpctl_success_bin"
	atf_check -s exit:0 -o match:'features=0x0000000b' \
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

atf_test_case state_watch
state_watch_body()
{
	tool="$(atf_get_srcdir)/networkcmpctl_success_bin"
	atf_check -s exit:0 -o match:'generation=2 source_error=0 count=1' \
	    -o match:'name=v\\x0a0' -o match:'mtu=1500 link=up' -e empty \
	    env CMP_TEST_TIMEOUT=1 "$tool" state-watch 2 17
	atf_check -s exit:0 -o match:'source_error=5 count=0' -e empty \
	    env CMP_TEST_SOURCE_ERROR=1 "$tool" state-watch
	atf_check -s exit:69 -e match:'state-client-closed' \
	    -e match:'state-watch: Input/output error' \
	    env CMP_TEST_FAIL=state-watch CMP_TEST_TRACE_CLOSE=1 \
	    "$tool" state-watch
	atf_check -s exit:69 -e match:'open system.Network.State' \
	    env CMP_TEST_FAIL=state-open "$tool" state-watch
	for value in 0 -1 +1 ' 1' 4294967296 1x; do
		atf_check -s exit:64 -e match:'invalid number' \
		    "$tool" state-watch "$value"
	done
	atf_check -s exit:64 -e match:'invalid number' \
	    "$tool" state-watch 1 -1
	atf_check -s exit:64 -e match:'usage:' "$tool" state-watch 1 2 3
}

atf_test_case resolve_selection
resolve_selection_body()
{
	tool="$(atf_get_srcdir)/networkcmpctl_success_bin"
	atf_check -s exit:0 -o match:'family=inet4 address=127.0.0.1' -e empty \
	    env CMP_TEST_FAMILY=1 "$tool" resolve -4 localhost 80
	atf_check -s exit:0 -o match:'family=inet6 address=::1' -e empty \
	    env CMP_TEST_FAMILY=2 "$tool" resolve -6 localhost
	atf_check -s exit:0 -o match:'family=inet6 address=::ffff:127.0.0.1' -e empty \
	    env CMP_TEST_FAMILY=2 CMP_TEST_FLAGS=34 "$tool" resolve -6 -m localhost
	atf_check -s exit:0 -o match:'family=inet6' -e empty \
	    env CMP_TEST_FAMILY=2 CMP_TEST_FLAGS=98 "$tool" resolve -6 -m -a localhost
	atf_check -s exit:0 -o match:'count=1' -e empty "$tool" resolve -- localhost
	atf_check -s exit:64 -e match:'usage:' "$tool" resolve -4 -6 localhost
	atf_check -s exit:64 -e match:'usage:' "$tool" resolve -m localhost
	atf_check -s exit:64 -e match:'usage:' "$tool" resolve -6 -a localhost
	atf_check -s exit:64 -e match:'usage:' "$tool" resolve -6
	atf_check -s exit:64 -e match:'usage:' "$tool" resolve -x localhost
}

atf_init_test_cases()
{
	atf_add_test_case resolve_selection
	atf_add_test_case state_watch
	atf_add_test_case config
	atf_add_test_case arguments
	atf_add_test_case unavailable
	atf_add_test_case successful_commands
	atf_add_test_case failures_and_cleanup
}
