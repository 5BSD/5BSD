# SPDX-License-Identifier: BSD-2-Clause

atf_test_case config
config_body()
{
	tool="$(atf_get_srcdir)/filesystemcmpctl_test_bin"
	atf_check -s exit:0 \
	    -o inline:'storage = [{ name = "data"; scope = "unit"; flavor = "native"; lifetime = "persistent"; rights = "mount"; }];\ndescriptors { filesystem { storage = "data"; } }\n' \
	    -e empty "$tool" config
}

atf_test_case arguments
arguments_body()
{
	tool="$(atf_get_srcdir)/filesystemcmpctl_test_bin"
	atf_check -s exit:64 -e match:'usage: filesystemcmpctl' "$tool"
	atf_check -s exit:64 -e match:'usage: filesystemcmpctl' "$tool" info extra
	atf_check -s exit:64 -e match:'usage: filesystemcmpctl' "$tool" stat scratch
}

atf_test_case unavailable
unavailable_body()
{
	tool="$(atf_get_srcdir)/filesystemcmpctl_test_bin"
	atf_check -s exit:69 -e match:'open system.Filesystem' "$tool" info
}

atf_test_case successful_commands
successful_commands_body()
{
	tool="$(atf_get_srcdir)/filesystemcmpctl_success_bin"
	atf_check -s exit:0 -o match:'version=1 features=0x00000007' \
	    -o match:'max_bytes=4096 max_objects=16' -e empty "$tool" info
	atf_check -s exit:0 -o match:'namespace=persistent path=/data' \
	    -o match:'type=1 mode=0600 size=11 inode=12 modified_sec=13' \
	    -e empty "$tool" stat persistent /data
}

atf_test_case failures_and_cleanup
failures_and_cleanup_body()
{
	tool="$(atf_get_srcdir)/filesystemcmpctl_success_bin"
	atf_check -s exit:64 -e match:'invalid namespace' \
	    "$tool" stat invalid /data
	atf_check -s exit:69 -e match:'hello: Input/output error' \
	    -e match:'client-closed' env CMP_TEST_FAIL=hello \
	    CMP_TEST_TRACE_CLOSE=1 "$tool" info
	atf_check -s exit:66 -e match:'/data: Input/output error' \
	    -e match:'context-closed' env CMP_TEST_FAIL=lookup \
	    CMP_TEST_TRACE_CONTEXT_CLOSE=1 "$tool" stat scratch /data
	atf_check -s exit:74 -e match:'stat /data: Input/output error' \
	    -e match:'context-closed' env CMP_TEST_FAIL=stat \
	    CMP_TEST_TRACE_CONTEXT_CLOSE=1 "$tool" stat bundle /data
	atf_check -s exit:74 -e match:'close /data: Input/output error' \
	    -e match:'context-closed' env CMP_TEST_FAIL=close-handle \
	    CMP_TEST_TRACE_CONTEXT_CLOSE=1 "$tool" stat scratch /data
}

atf_init_test_cases()
{
	atf_add_test_case config
	atf_add_test_case arguments
	atf_add_test_case unavailable
	atf_add_test_case successful_commands
	atf_add_test_case failures_and_cleanup
}
