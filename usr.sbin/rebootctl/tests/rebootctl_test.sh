# SPDX-License-Identifier: BSD-2-Clause

atf_test_case configtest
configtest_body()
{
	tool="$(atf_get_srcdir)/rebootctl_test_bin"
	printf '%s\n' org.test.power > valid
	atf_check -s exit:0 -o match:'labels=1, default=explicit-allow' \
	    "$tool" configtest valid
	: > empty
	atf_check -s exit:0 -o match:'labels=0, default=deny' \
	    "$tool" configtest empty
}

atf_test_case config_errors
config_errors_body()
{
	tool="$(atf_get_srcdir)/rebootctl_test_bin"
	atf_check -s exit:0 -o match:'labels=0, default=deny' \
	    "$tool" configtest missing
	printf '%s\n' '*' > invalid
	atf_check -s exit:65 -e match:invalid "$tool" configtest invalid
}

atf_test_case status
status_body()
{
	tool="$(atf_get_srcdir)/rebootctl_test_bin"
	atf_check -s exit:0 -o match:'pending=no' "$tool" status
	atf_check -s exit:1 -o match:'pending=yes' \
	    env CMP_TEST_PENDING=1 "$tool" status
}

atf_test_case discovery_failure
discovery_failure_body()
{
	tool="$(atf_get_srcdir)/rebootctl_test_bin"
	for operation in status cancel reboot reroot shutdown; do
		atf_check -s exit:69 -e match:'open org.5bsd.system.reboot' \
		    env CMP_TEST_FAIL=open "$tool" "$operation"
	done
}

atf_test_case cancel
cancel_body()
{
	tool="$(atf_get_srcdir)/rebootctl_test_bin"
	atf_check -s exit:0 -o inline:'cancelled=yes\n' "$tool" cancel
	atf_check -s exit:69 -e match:'cancel: Input/output error' \
	    env CMP_TEST_FAIL=cancel "$tool" cancel
}

atf_test_case mutating_operations
mutating_operations_body()
{
	tool="$(atf_get_srcdir)/rebootctl_test_bin"
	for operation in reboot reroot shutdown; do
		atf_check -s exit:0 -o inline:"requested=${operation}\n" \
		    "$tool" "$operation"
		atf_check -s exit:69 -e match:"${operation}: Input/output error" \
		    env CMP_TEST_FAIL="$operation" "$tool" "$operation"
		atf_check -s exit:0 -o inline:"requested=${operation}\n" \
		    "$tool" "$operation" 0
	done
}

atf_test_case operation_failure
operation_failure_body()
{
	tool="$(atf_get_srcdir)/rebootctl_test_bin"
	atf_check -s exit:69 -e match:'status: Input/output error' \
	    env CMP_TEST_FAIL=status "$tool" status
}

atf_test_case arguments
arguments_body()
{
	tool="$(atf_get_srcdir)/rebootctl_test_bin"
	atf_check -s exit:64 -e match:'usage: rebootctl' "$tool"
	atf_check -s exit:64 -e match:'usage: rebootctl' "$tool" status extra
	atf_check -s exit:64 -e match:'delay-seconds.*invalid' \
	    "$tool" reboot extra
	atf_check -s exit:64 -e match:'delay-seconds.*too large' \
	    "$tool" shutdown 86401
	atf_check -s exit:64 -e match:'usage: rebootctl' "$tool" unknown
}

atf_init_test_cases()
{
	atf_add_test_case configtest
	atf_add_test_case config_errors
	atf_add_test_case status
	atf_add_test_case mutating_operations
	atf_add_test_case cancel
	atf_add_test_case discovery_failure
	atf_add_test_case operation_failure
	atf_add_test_case arguments
}
