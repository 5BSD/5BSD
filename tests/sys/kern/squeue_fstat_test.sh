# SPDX-License-Identifier: BSD-2-Clause
atf_test_case squeue_fstat
squeue_fstat_head()
{
	atf_set "descr" "a squeue ring descriptor is reported as [squeue] by fstat/procstat"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "cc fstat procstat"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
squeue_fstat_body()
{
	atf_check -s exit:0 -o empty -e empty cc -O2 -static \
	    -Wall -Wextra -Werror -o squeue_hold \
	    "$(atf_get_srcdir)/squeue_hold.c"
	./squeue_hold > hold.out 2>&1 &
	pid=$!
	# wait for the ring to be created
	for i in 1 2 3 4 5 6 7 8 9 10; do
		grep -q READY hold.out && break
		sleep 0.3
	done
	fstat -p "$pid" > fstat.out 2>&1 || true
	procstat -f "$pid" > procstat.out 2>&1 || true
	kill "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
	cat fstat.out procstat.out >&2
	# fstat prints the full type name "[squeue]" for the ring descriptor
	grep -q "squeue" fstat.out || atf_fail "fstat did not report the ring as squeue"
}
atf_init_test_cases()
{
	atf_add_test_case squeue_fstat
}
