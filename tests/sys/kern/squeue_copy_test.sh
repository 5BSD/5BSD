# SPDX-License-Identifier: BSD-2-Clause
atf_test_case squeue_copy
squeue_copy_head()
{
	atf_set "descr" "copy a file through a squeue ring via libsqueue (real workload)"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "cc"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
squeue_copy_body()
{
	atf_check -s exit:0 -o empty -e empty cc -O2 -static \
	    -Wall -Wextra -Werror -o squeue_copy \
	    "$(atf_get_srcdir)/squeue_copy.c"
	./squeue_copy 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "check $rc failed"
}
atf_init_test_cases()
{
	atf_add_test_case squeue_copy
}
