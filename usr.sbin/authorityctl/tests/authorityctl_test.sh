#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#

atf_test_case arguments
arguments_body()
{
	tool="$(atf_get_srcdir)/authorityctl_test_bin"
	atf_check -s exit:64 -e match:'usage: authorityctl' "$tool"
	atf_check -s exit:64 -e match:'usage: authorityctl' "$tool" unknown
	atf_check -s exit:64 -e match:'usage: authorityctl' \
	    "$tool" status extra
}

atf_test_case unavailable
unavailable_body()
{
	tool="$(atf_get_srcdir)/authorityctl_test_bin"
	atf_check -s exit:69 \
	    -e match:'cannot reach the authority control capability' \
	    env -u SERVICE_LOOKUP_FD "$tool" status 3>&-
}

atf_test_case successful_commands
successful_commands_body()
{
	tool="$(atf_get_srcdir)/authorityctl_success_bin"

	for spec in reboot:4 halt:5 poweroff:6 powercycle:10 single:11 \
	    reroot:12 rescan:13 catatonia:14; do
		verb=${spec%:*}
		op=${spec#*:}
		atf_check -s exit:0 -o empty -e empty \
		    env AUTHCTL_EXPECT_OP="$op" AUTHCTL_REPLY=nosummary \
		    "$tool" "$verb"
	done
	atf_check -s exit:0 -o inline:'authority-ready\n' -e empty \
	    env AUTHCTL_EXPECT_OP=2 "$tool" status
	atf_check -s exit:0 -o inline:'authority-ready\n' -e empty \
	    env AUTHCTL_EXPECT_OP=3 "$tool" reload
}

atf_test_case failures_close_session
failures_close_session_body()
{
	tool="$(atf_get_srcdir)/authorityctl_success_bin"

	atf_check -s exit:69 -e match:'No such file or directory' \
	    env AUTHCTL_FAIL=open "$tool" status
	atf_check -s exit:69 -e match:'authority session: Input/output error' \
	    env AUTHCTL_FAIL=session "$tool" status
	atf_check -s exit:69 -e match:'authority request: Input/output error' \
	    -e match:'session-closed' env AUTHCTL_FAIL=call \
	    AUTHCTL_TRACE_CLOSE=1 "$tool" status
	atf_check -s exit:1 -e match:'status: Device busy' \
	    -e match:'session-closed' env AUTHCTL_REPLY=status \
	    AUTHCTL_TRACE_CLOSE=1 "$tool" status
}

atf_test_case malformed_replies
malformed_replies_body()
{
	tool="$(atf_get_srcdir)/authorityctl_success_bin"

	atf_check -s exit:76 -e match:'short authority reply' \
	    -e match:'session-closed' env AUTHCTL_REPLY=short \
	    AUTHCTL_TRACE_CLOSE=1 "$tool" status
	for mode in oversize trailing badstatus; do
		atf_check -s exit:76 -e match:'malformed authority reply' \
		    -e match:'session-closed' env AUTHCTL_REPLY="$mode" \
		    AUTHCTL_TRACE_CLOSE=1 "$tool" status
	done
}

atf_init_test_cases()
{
	atf_add_test_case arguments
	atf_add_test_case unavailable
	atf_add_test_case successful_commands
	atf_add_test_case failures_close_session
	atf_add_test_case malformed_replies
}
