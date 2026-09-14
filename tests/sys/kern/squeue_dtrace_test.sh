# SPDX-License-Identifier: BSD-2-Clause
atf_test_case squeue_dtrace
squeue_dtrace_head()
{
	atf_set "descr" "the squeue DTrace provider fires submit/complete probes"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "cc dtrace"
	atf_set "require.user" "root"
	atf_set "timeout" "240"
}
squeue_dtrace_body()
{
	# A standalone workload that submits/reaps NOPs for ~8s, long enough
	# for a concurrently running dtrace to enable its probes and observe
	# them fire -- even under a slow TCG-emulated guest.
	atf_check -s exit:0 -o empty -e empty cc -O2 -static \
	    -Wall -Wextra -Werror -o w \
	    "$(atf_get_srcdir)/squeue_dtrace_workload.c"

	# The provider is a built-in kernel SDT provider; skip if DTrace cannot
	# see it (e.g. dtrace modules unavailable in this environment).
	if [ "$(dtrace -ln 'squeue:::' 2>/dev/null | wc -l)" -le 1 ]; then
		atf_skip "squeue DTrace provider not available"
	fi

	# Do NOT use "dtrace -c": grabbing/controlling the child process can
	# fail under an emulated guest ("failed to control pid ...").  The
	# squeue probes are global kernel SDT probes, so run dtrace in the
	# background collecting counts, run the workload separately, and let
	# dtrace exit on its own tick.
	dtrace -x switchrate=10hz \
	    -n 'squeue:::submit   { @sub = count(); }
	        squeue:::complete { @cmp = count(); }
	        tick-1s /++n >= 20/ { exit(0); }
	        END { printa("SUB=%@u\n", @sub); printa("CMP=%@u\n", @cmp); }' \
	    -o dt.out 2>dt.err &
	dpid=$!

	# Give dtrace time to compile and enable the probes before generating
	# load; the workload then runs long enough to overlap regardless.
	sleep 4
	./w 8
	wait "$dpid"

	cat dt.out dt.err >&2
	grep -qE 'SUB=[1-9]' dt.out || atf_fail "no squeue:::submit probes fired"
	grep -qE 'CMP=[1-9]' dt.out || \
	    atf_fail "no squeue:::complete probes fired"
}
atf_init_test_cases()
{
	atf_add_test_case squeue_dtrace
}
