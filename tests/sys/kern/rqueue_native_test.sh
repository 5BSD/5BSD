# SPDX-License-Identifier: BSD-2-Clause
atf_test_case rqueue_native
rqueue_native_head()
{
	atf_set "descr" "native 5BSD rqueue engine: setup/enter/register, NOP, WRITE/READ roundtrip, negative errnos, TIMEOUT"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "cc"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
rqueue_native_body()
{
	atf_check -s exit:0 -o empty -e empty cc -O2 -static \
	    -Wall -Wextra -Werror -o rqueue_native \
	    "$(atf_get_srcdir)/rqueue_native.c"
	./rqueue_native 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "check $rc failed"
}
atf_init_test_cases()
{
	atf_add_test_case rqueue_native
}
