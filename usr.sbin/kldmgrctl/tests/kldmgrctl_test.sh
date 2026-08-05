# SPDX-License-Identifier: BSD-2-Clause

atf_test_case configtest
configtest_body()
{
	tool="$(atf_get_srcdir)/kldmgrctl_test_bin"
	printf '%s\n' org.test.loader > valid
	atf_check -s exit:0 -o match:'labels=1, default=explicit-allow' \
	    "$tool" configtest valid
	: > empty
	atf_check -s exit:0 -o match:'labels=0, default=deny' \
	    "$tool" configtest empty
}

atf_test_case config_errors
config_errors_body()
{
	tool="$(atf_get_srcdir)/kldmgrctl_test_bin"
	atf_check -s exit:0 -o match:'labels=0, default=deny' \
	    "$tool" configtest missing
	printf '%s\n' '*' > invalid
	atf_check -s exit:65 -e match:invalid "$tool" configtest invalid
	printf '%s\n' org.test.same org.test.same > duplicate
	atf_check -s exit:65 -e match:duplicate "$tool" configtest duplicate
}

atf_test_case list_success
list_success_body()
{
	tool="$(atf_get_srcdir)/kldmgrctl_test_bin"
	atf_check -s exit:0 -o match:'3.*zfs.ko' -o match:'9.*dtrace.ko' \
	    "$tool" list

}

atf_test_case discovery_failure
discovery_failure_body()
{
	tool="$(atf_get_srcdir)/kldmgrctl_test_bin"
	for arguments in 'list' 'load if_test.ko' 'unload if_test.ko'; do
		atf_check -s exit:69 -e match:'open org.5bsd.system.kldmgr' \
		    env CMP_TEST_FAIL=open "$tool" $arguments
	done
}

atf_test_case module_operations
module_operations_body()
{
	tool="$(atf_get_srcdir)/kldmgrctl_test_bin"
	atf_check -s exit:0 -o inline:'id=17\tmodule=if_test.ko\n' \
	    "$tool" load if_test.ko
	atf_check -s exit:0 -o inline:'id=23\tmodule=if_test.ko\n' \
	    "$tool" unload if_test.ko
	atf_check -s exit:69 -e match:'load if_test.ko: Input/output error' \
	    env CMP_TEST_FAIL=load "$tool" load if_test.ko
	atf_check -s exit:69 -e match:'unload if_test.ko: Input/output error' \
	    env CMP_TEST_FAIL=unload "$tool" unload if_test.ko
}

atf_test_case operation_failure
operation_failure_body()
{
	tool="$(atf_get_srcdir)/kldmgrctl_test_bin"
	atf_check -s exit:69 -e match:'list: Input/output error' \
	    env CMP_TEST_FAIL=list "$tool" list
}

atf_test_case arguments
arguments_body()
{
	tool="$(atf_get_srcdir)/kldmgrctl_test_bin"
	atf_check -s exit:64 -e match:'usage: kldmgrctl' "$tool"
	atf_check -s exit:64 -e match:'usage: kldmgrctl' "$tool" list extra
	atf_check -s exit:64 -e match:'usage: kldmgrctl' "$tool" load
	atf_check -s exit:64 -e match:'usage: kldmgrctl' "$tool" unload
	atf_check -s exit:64 -e match:'usage: kldmgrctl' "$tool" unknown
}

atf_init_test_cases()
{
	atf_add_test_case configtest
	atf_add_test_case config_errors
	atf_add_test_case list_success
	atf_add_test_case module_operations
	atf_add_test_case discovery_failure
	atf_add_test_case operation_failure
	atf_add_test_case arguments
}
