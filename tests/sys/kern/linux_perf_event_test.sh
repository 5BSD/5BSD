# SPDX-License-Identifier: BSD-2-Clause
atf_test_case perf_event
perf_event_head()
{
	atf_set "descr" "Linux perf_event_open software counters, fd lifecycle, and rejection contracts"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf timeout"
	atf_set "require.kmods" "linux64"
	atf_set "timeout" "180"
}
perf_event_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o linux_perf_event \
	    "$(atf_get_srcdir)/linux_perf_event.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux linux_perf_event
	atf_check -s exit:0 -o save:perf-cases.txt -e empty ./linux_perf_event -l
	[ "$(wc -l <perf-cases.txt | tr -d ' ')" -eq 13 ] ||
	    atf_fail "missing perf_event cases"
	while read -r name; do
		timeout 30 ./linux_perf_event "$name" 2>stderr.txt
		rc=$?
		cat stderr.txt >&2
		[ "$rc" -eq 0 ] || atf_fail "$name: exit status $rc"
	done <perf-cases.txt
}

atf_init_test_cases()
{
	atf_add_test_case perf_event
}
