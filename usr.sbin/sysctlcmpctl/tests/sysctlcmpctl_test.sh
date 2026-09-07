#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause

atf_test_case arguments
arguments_body()
{
	tool="$(atf_get_srcdir)/sysctlcmpctl_success_bin"
	atf_check -s exit:64 -e match:'usage: sysctlcmpctl' "$tool"
	atf_check -s exit:64 -e match:'usage: sysctlcmpctl' "$tool" get
	atf_check -s exit:64 -e match:'usage: sysctlcmpctl' "$tool" get x extra
	atf_check -s exit:64 -e match:'usage: sysctlcmpctl' "$tool" list a b
	atf_check -s exit:64 -e match:'usage: sysctlcmpctl' "$tool" unknown
}

atf_test_case commands
commands_body()
{
	tool="$(atf_get_srcdir)/sysctlcmpctl_success_bin"
	atf_check -s exit:0 -o inline:'test-value\n' -e empty \
	    "$tool" get test.text
	atf_check -s exit:0 -o inline:'42\n' -e empty \
	    "$tool" get test.number
	atf_check -s exit:0 -o inline:'deadbe\n' -e empty \
	    "$tool" get test.bytes
	atf_check -s exit:0 -o empty -e empty \
	    "$tool" set test.write enabled
	atf_check -s exit:0 -o inline:'kind=0x1234 fmt=A\n' -e empty \
	    "$tool" fmt test.text
	atf_check -s exit:0 -o inline:'test description\n' -e empty \
	    "$tool" descr test.text
}

atf_test_case list_start
list_start_body()
{
	tool="$(atf_get_srcdir)/sysctlcmpctl_success_bin"
	atf_check -s exit:0 -o inline:'test.alpha\ntest.omega\n' -e empty \
	    "$tool" list
	atf_check -s exit:0 -o inline:'test.omega\n' -e empty \
	    "$tool" list test.beta
}

atf_test_case failures
failures_body()
{
	tool="$(atf_get_srcdir)/sysctlcmpctl_success_bin"
	atf_check -s exit:69 -e match:'open system.Sysctl: Input/output error' \
	    env SYSCTLCMP_TEST_FAIL=open "$tool" get test.text
	for spec in get:test.text set:test.write fmt:test.text descr:test.text \
	    list:none; do
		op=${spec%:*}
		name=${spec#*:}
		case "$op" in
		set) args='test.write enabled' ;;
		list) args='' ;;
		*) args=$name ;;
		esac
		atf_check -s exit:69 -e match:'Input/output error' \
		    env SYSCTLCMP_TEST_FAIL="$op" "$tool" "$op" $args
	done
}

atf_init_test_cases()
{
	atf_add_test_case arguments
	atf_add_test_case commands
	atf_add_test_case list_start
	atf_add_test_case failures
}
