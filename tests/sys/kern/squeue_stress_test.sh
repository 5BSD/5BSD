# SPDX-License-Identifier: BSD-2-Clause
atf_test_case squeue_stress
squeue_stress_head()
{
	atf_set "descr" "native squeue concurrency + lifecycle-race stress (close vs in-flight timeout/async/poll, concurrent rings)"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "cc"
	atf_set "require.user" "root"
	atf_set "timeout" "300"
}
squeue_stress_body()
{
	atf_check -s exit:0 -o empty -e empty cc -O2 -static \
	    -Wall -Wextra -Werror -o squeue_stress \
	    "$(atf_get_srcdir)/squeue_stress.c" -lpthread
	timeout 240 ./squeue_stress 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "check $rc failed"
}
atf_init_test_cases()
{
	atf_add_test_case squeue_stress
}
