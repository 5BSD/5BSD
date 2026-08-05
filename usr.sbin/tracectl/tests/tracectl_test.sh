# SPDX-License-Identifier: BSD-2-Clause

atf_test_case valid_policy
valid_policy_body()
{
	tool="$(atf_get_srcdir)/tracectl_test_bin"
	printf '%s\n' 'org.test.trace' 'org.test.second # comment' > valid
	atf_check -s exit:0 -o match:'labels=2, default=explicit-allow' \
	    "$tool" configtest valid
}

atf_test_case empty_is_default_deny
empty_is_default_deny_body()
{
	tool="$(atf_get_srcdir)/tracectl_test_bin"
	: > empty
	atf_check -s exit:0 -o match:'labels=0, default=deny' \
	    "$tool" configtest empty
}

atf_test_case policy_errors
policy_errors_body()
{
	tool="$(atf_get_srcdir)/tracectl_test_bin"
	atf_check -s exit:0 -o match:'labels=0, default=deny' \
	    "$tool" configtest missing
	printf '%s\n' '*' > invalid
	atf_check -s exit:65 -e match:invalid "$tool" configtest invalid
	printf '%s\n' org.test.same org.test.same > duplicate
	atf_check -s exit:65 -e match:duplicate "$tool" configtest duplicate
	jot -b x -s '' 80 > oversized
	atf_check -s exit:65 -e match:oversized "$tool" configtest oversized
}

atf_test_case arguments
arguments_body()
{
	tool="$(atf_get_srcdir)/tracectl_test_bin"
	atf_check -s exit:64 -e match:'usage: tracectl' "$tool"
	atf_check -s exit:64 -e match:'usage: tracectl' "$tool" configtest a b
	atf_check -s exit:64 -e match:'usage: tracectl' "$tool" unknown
}

atf_init_test_cases()
{
	atf_add_test_case valid_policy
	atf_add_test_case empty_is_default_deny
	atf_add_test_case policy_errors
	atf_add_test_case arguments
}
