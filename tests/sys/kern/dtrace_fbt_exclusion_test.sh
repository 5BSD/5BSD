#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# fbt must not instrument DTrace itself.  Code that runs in probe context, or
# on the breakpoint path that leads to it, cannot carry an fbt probe: the
# probe's own breakpoint re-enters DTrace from inside DTrace.  With
# fbt:kinst:kinst_invop:entry enabled every breakpoint recursed through
# dtrace_invop() until the thread's stack ran out (panic: double fault).
#
# fbt_provide_module() refuses the modules that declare a dependency on the
# dtrace module.  That has to hold when DTrace is compiled into the kernel
# too, where such a module depends on the file "kernel" rather than on
# dtrace.ko, and where the providers that are compiled in leave their
# probe-context methods in the kernel proper.
#
# Both cases read the fbt probe listing first (dtrace -l enables nothing) and
# fbt_entry_with_kinst_probe enables probes only when the listing shows that
# the exclusion is in force, so on a kernel without the fix this program
# fails; it does not panic the machine.
#

# The kernel linker files that are part of DTrace; each of them declares
# MODULE_DEPEND(..., dtrace, ...).  vmm declares it too, but it only uses
# DTrace and has to keep its fbt probes.
dtrace_modules="dtaudit dtmalloc dtnfscl dtrace dtrace_test dtraceall \
fasttrap fbt hypertrace kinst profile prototype sdt systrace systrace_linux \
virtio_dtrace"

# Functions of the kernel proper that DTrace calls in probe context and that
# do not carry the dtrace_ prefix: the dtps_getargval methods of the providers
# that can be compiled into the kernel.
probe_context_functions="sdt_getargval systrace_getargval"

# The modules of that list which stay loadable modules when DTrace is
# compiled into the kernel.
dtrace_klds="kinst fasttrap hypertrace"

# "module function name" for every fbt probe; nothing is enabled.
list_fbt_probes()
{
	dtrace -l -P fbt > fbt.list 2> fbt.err ||
	    atf_fail "dtrace -l -P fbt failed: $(cat fbt.err)"
	awk 'NR > 1 && $2 == "fbt" { print $3, $4, $5 }' fbt.list > fbt.probes
}

# fbt probes that must not exist.
list_unsafe_probes()
{
	awk -v mods="$dtrace_modules" -v funcs="$probe_context_functions" '
	    BEGIN {
		n = split(mods, a, " "); for (i = 1; i <= n; i++) m[a[i]] = 1
		n = split(funcs, a, " "); for (i = 1; i <= n; i++) f[a[i]] = 1
	    }
	    ($1 in m) || ($2 in f)' fbt.probes > unsafe.probes
}

require_separate_dtrace_kld()
{
	for m in $dtrace_klds; do
		kldstat -q -n "$m.ko" && return
	done
	atf_skip "none of $dtrace_klds is loaded as a module"
}

atf_test_case dtrace_modules_not_instrumented
dtrace_modules_not_instrumented_head()
{
	atf_set descr "fbt provides no probes in DTrace's modules and probe-context methods"
	atf_set require.user root
	atf_set require.progs dtrace
}
dtrace_modules_not_instrumented_body()
{
	require_separate_dtrace_kld
	list_fbt_probes
	list_unsafe_probes
	if [ -s unsafe.probes ]; then
		awk '{ c[$1]++ } END { for (m in c) print m, c[m] }' unsafe.probes
		head -n 20 unsafe.probes
		atf_fail "fbt instruments DTrace itself"
	fi

	# The exclusion must not take the ordinary modules with it.
	n=$(awk '$1 == "kernel"' fbt.probes | wc -l)
	[ "$n" -ge 1000 ] || atf_fail "only $n fbt probes in the kernel"
	for m in vmm linux64 linux_common; do
		kldstat -q -n "$m.ko" || continue
		n=$(awk -v m="$m" '$1 == m' fbt.probes | wc -l)
		[ "$n" -ge 1 ] || atf_fail "no fbt probes in $m.ko"
	done
}

atf_test_case fbt_entry_with_kinst_probe cleanup
fbt_entry_with_kinst_probe_head()
{
	atf_set descr "every fbt entry probe, a kinst probe and system calls together"
	atf_set require.user root
	atf_set require.progs dtrace
	atf_set timeout 900
}
fbt_entry_with_kinst_probe_body()
{
	kldstat -q -n kinst.ko || atf_skip "kinst.ko is not loaded"

	# The guard: enable nothing unless fbt keeps out of DTrace.
	list_fbt_probes
	list_unsafe_probes
	[ -s unsafe.probes ] && atf_fail "not enabling fbt: it instruments" \
	    "DTrace itself ($(wc -l < unsafe.probes | tr -d ' ') probes)"

	# One kinst probe inside vm_fault(), away from the first instruction,
	# which the fbt entry probe patches.
	dtrace -l -n 'kinst::vm_fault:' > kinst.list 2> kinst.err ||
	    atf_skip "no kinst probes for vm_fault(): $(cat kinst.err)"
	off=$(awk 'NR > 1 && $2 == "kinst" { print $5 }' kinst.list | sed -n 4p)
	[ -n "$off" ] || atf_skip "no kinst probes for vm_fault()"

	# Page faults and system calls.  arg5 is fetched through the
	# provider's dtps_getargval method, in probe context.
	( while :; do ls -la / > /dev/null 2>&1; done ) &
	echo $! > traffic.pid

	atf_check -s exit:0 -o save:dtrace.out -e save:dtrace.err dtrace -q \
	    -n 'fbt:::entry { @fbt = count(); }' \
	    -n "kinst::vm_fault:$off { @kinst = count(); }" \
	    -n 'syscall::mmap:entry { @mmap = count(); @off = max(arg5); }' \
	    -n 'tick-5s { exit(0); }' \
	    -n 'END { printa("fbt %@d\n", @fbt); printa("kinst %@d\n", @kinst);
		printa("mmap %@d\n", @mmap); }'
	kill "$(cat traffic.pid)" 2> /dev/null
	cat dtrace.out

	for p in fbt kinst mmap; do
		n=$(awk -v p="$p" '$1 == p { print $2 }' dtrace.out)
		[ "${n:-0}" -gt 0 ] || atf_fail "no $p probe fired"
	done
}
fbt_entry_with_kinst_probe_cleanup()
{
	[ -f traffic.pid ] && kill "$(cat traffic.pid)" 2> /dev/null
	return 0
}

atf_init_test_cases()
{
	atf_add_test_case dtrace_modules_not_instrumented
	atf_add_test_case fbt_entry_with_kinst_probe
}
