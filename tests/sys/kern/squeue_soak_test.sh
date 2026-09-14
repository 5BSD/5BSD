# SPDX-License-Identifier: BSD-2-Clause
atf_test_case squeue_soak
squeue_soak_head()
{
	atf_set "descr" "native squeue combinatorial op/flag/chain churn + ring-lifecycle leak check"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "cc"
	atf_set "require.user" "root"
	atf_set "timeout" "600"
}
squeue_soak_body()
{
	atf_check -s exit:0 -o empty -e empty cc -O2 -static \
	    -Wall -Wextra -Werror -I/usr/src/sys -o squeue_soak \
	    "$(atf_get_srcdir)/squeue_soak.c"
	timeout 540 ./squeue_soak 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "check $rc failed"
}
atf_init_test_cases()
{
	atf_add_test_case squeue_soak
}
