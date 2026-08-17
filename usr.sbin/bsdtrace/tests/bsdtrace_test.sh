#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# No-root, no-hardware tests for bsdtrace: CLI surface, list output,
# and offline-decode robustness against missing/corrupt inputs.
# Live tracing (exec/trace) requires root + Intel PT and is covered
# by the hardware integration suite.
#

# Run a command that is allowed to fail but must not die on a signal
# (crash).  $1..$n = command.
check_no_crash()
{
	"$@" > out.txt 2> err.txt
	rc=$?
	if [ $rc -ge 128 ]; then
		cat out.txt err.txt
		atf_fail "'$*' died with signal $((rc - 128))"
	fi
}

atf_test_case usage_surface
usage_surface_head()
{
	atf_set descr "top-level and per-command usage output"
}
usage_surface_body()
{
	atf_check -s not-exit:0 -e match:"usage: bsdtrace" bsdtrace
	atf_check -s not-exit:0 -e match:"unknown command" \
	    -e match:"usage: bsdtrace" bsdtrace bogus-subcommand
}

atf_test_case list_runs
list_runs_head()
{
	atf_set descr "bsdtrace list reports HWT availability either way"
}
list_runs_body()
{
	# Must succeed whether or not /dev/hwt exists; output names
	# the framework and reports device availability.
	atf_check -o match:"HWT" -o match:"/dev/hwt" bsdtrace list
}

atf_test_case decode_missing_files
decode_missing_files_head()
{
	atf_set descr "decode of nonexistent trace fails cleanly"
}
decode_missing_files_body()
{
	atf_check -s not-exit:0 -e match:"meta" \
	    bsdtrace decode /nonexistent/trace.pt
}

atf_test_case decode_empty_trace
decode_empty_trace_head()
{
	atf_set descr "decode of an empty .pt + valid-shaped .meta is clean"
}
decode_empty_trace_body()
{
	: > empty.pt
	: > empty.meta
	check_no_crash bsdtrace decode empty.pt
}

atf_test_case decode_corrupt_meta
decode_corrupt_meta_head()
{
	atf_set descr "corrupt/adversarial .meta lines never crash decode"
}
decode_corrupt_meta_body()
{
	printf 'garbage-not-pt-data' > t.pt
	# A grab-bag of malformed JSONL records in the CURRENT formats.
	cat > t.meta <<'EOF'
{"type":"mmap"
not json at all
{"type":"mmap","path":"/nonexistent","addr":"0xzzz","base":"bad"}
{"type":"exec","path":"/nonexistent/binary","addr":"0xffffffffffffffff","base":"0x0"}
{"type":"munmap","addr":"0x0"}
{"type":"munmap","addr":"nothex"}
{"type":"capture_env","family":99999,"model":300,"stepping":300,"cpuid15_eax":1,"cpuid15_ebx":1,"nom_freq":999}
{"type":"addr_range","a":"0x2000","b":"0x1000","cfg":9}
{"type":"mmap","path":"/x","addr":"0x1000","base":"0x0","pgoff":"0xzz","len":"0x0"}
{}
EOF
	check_no_crash bsdtrace decode t.pt
}

atf_test_case decode_truncated_pt
decode_truncated_pt_head()
{
	atf_set descr "decode of garbage .pt bytes fails without crashing"
}
decode_truncated_pt_body()
{
	# 4 KiB of 0xff never syncs to a PSB.
	dd if=/dev/zero bs=1k count=4 2>/dev/null | \
	    tr '\0' '\377' > junk.pt
	: > junk.meta
	check_no_crash bsdtrace decode junk.pt
}

atf_test_case exec_requires_command
exec_requires_command_head()
{
	atf_set descr "exec without a command is a usage error"
}
exec_requires_command_body()
{
	atf_check -s not-exit:0 -e ignore bsdtrace exec
}

atf_test_case trace_requires_pid
trace_requires_pid_head()
{
	atf_set descr "trace without a pid is a usage error"
}
trace_requires_pid_body()
{
	atf_check -s not-exit:0 -e ignore bsdtrace trace
}

atf_test_case ptwrite_header_compiles
ptwrite_header_compiles_head()
{
	atf_set descr "installed bsdtrace_ptwrite.h compiles standalone"
	atf_set require.progs cc
}
ptwrite_header_compiles_body()
{
	hdr=/usr/include/bsdtrace_ptwrite.h
	[ -r "$hdr" ] || atf_skip "bsdtrace_ptwrite.h not installed"
	cat > t.c <<EOF
#include <bsdtrace_ptwrite.h>
int main(void) { return 0; }
EOF
	atf_check cc -Wall -Werror -c t.c -o t.o
}


atf_test_case option_validation
option_validation_head()
{
	atf_set descr "numeric options reject garbage instead of atoi(0)"
}
option_validation_body()
{
	atf_check -s not-exit:0 -e match:"invalid -s size" \
	    bsdtrace exec -s garbage -- true
	atf_check -s not-exit:0 -e match:"invalid duration" \
	    bsdtrace exec -d abc -- true
	atf_check -s not-exit:0 -e match:"invalid thread id" \
	    bsdtrace exec -T lol -- true
	atf_check -s not-exit:0 -e match:"invalid record count" \
	    bsdtrace trace -m -5 123
	atf_check -s not-exit:0 -e match:"must be greater than" \
	    bsdtrace exec -r 0x2000:0x1000 -- true
}

atf_test_case decode_capture_env
decode_capture_env_head()
{
	atf_set descr "capture_env meta record is consumed; absence noted"
}
decode_capture_env_body()
{
	printf 'notptdata' > t.pt
	cat > t.meta <<'EOF2'
{"type":"capture_env","family":6,"model":151,"stepping":2,"cpuid15_eax":2,"cpuid15_ebx":188,"nom_freq":24}
{"type":"addr_range","a":"0x1000","b":"0x2000","cfg":1}
EOF2
	bsdtrace decode t.pt > out.txt 2> err.txt
	atf_check -s exit:1 grep -q "no capture_env" err.txt

	printf 'notptdata' > t2.pt
	: > t2.meta
	bsdtrace decode t2.pt > out2.txt 2> err2.txt
	atf_check grep -q "no capture_env" err2.txt
}

atf_test_case decode_extended_meta
decode_extended_meta_head()
{
	atf_set descr "extended mmap records (pgoff/len) and munmap parse"
}
decode_extended_meta_body()
{
	printf 'notptdata' > t.pt
	cat > t.meta <<'EOF2'
{"type":"mmap","path":"/nonexistent/lib.so","addr":"0x800000","base":"0x0","pgoff":"0x3000","len":"0x2000"}
{"type":"munmap","addr":"0x800000"}
{"type":"mmap","path":"/nonexistent/lib2.so","addr":"0x800000","base":"0x0"}
EOF2
	bsdtrace decode t.pt > out.txt 2> err.txt
	rc=$?
	if [ $rc -ge 128 ]; then
		atf_fail "decode crashed on extended meta (signal $((rc - 128)))"
	fi
}


atf_test_case meta_unparsable_warns
meta_unparsable_warns_head()
{
	atf_set descr "malformed section-looking meta lines produce a warning"
}
meta_unparsable_warns_body()
{
	printf 'notptdata' > t.pt
	cat > t.meta <<'EOF2'
{"type":"mmap","path":"/no/lib.so","addr":"0xZZ","base":"0xQQ"}
{"type":"exec","broken":true}
{"type":"kernel","path":"/boot/kernel/kernel","addr":"0x1000","base":"0x0"}
EOF2
	bsdtrace decode t.pt > out.txt 2> err.txt || true
	atf_check grep -q "unparsable section record" err.txt
	# The well-formed kernel line must still load (1 binary).
	atf_check grep -q "1 binaries" err.txt
}

atf_init_test_cases()
{
	atf_add_test_case usage_surface
	atf_add_test_case list_runs
	atf_add_test_case decode_missing_files
	atf_add_test_case decode_empty_trace
	atf_add_test_case decode_corrupt_meta
	atf_add_test_case decode_truncated_pt
	atf_add_test_case exec_requires_command
	atf_add_test_case trace_requires_pid
	atf_add_test_case ptwrite_header_compiles
	atf_add_test_case option_validation
	atf_add_test_case decode_capture_env
	atf_add_test_case decode_extended_meta
	atf_add_test_case meta_unparsable_warns
}
