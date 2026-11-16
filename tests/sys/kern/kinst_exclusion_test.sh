#
# SPDX-License-Identifier: BSD-2-Clause
#
# kinst refuses what fbt refuses: functions DTrace calls in probe context,
# the breakpoint handlers of the providers, and DTrace's own modules.  A
# kinst probe there fires inside dtrace_probe() (a panic) or inside its own
# trap.  These cases only list probes; nothing is enabled.
#

kinst_list()
{
	dtrace -l -n "kinst::$1:" 2>&1
}

atf_test_case refused
refused_head()
{
	atf_set "descr" "kinst creates no probe in probe-context code"
	atf_set "require.user" "root"
	atf_set "require.kmods" "kinst"
	atf_set "require.progs" "dtrace"
}
refused_body()
{
	failed=
	for f in fbt_invop kinst_invop dtrace_probe sdt_getargval \
	    systrace_getargval fill_regs fill_frame_regs X_db_search_symbol \
	    linker_ddb_lookup kobj_lookup_method link_elf_search_symbol \
	    fasttrap_pid_probe; do
		if kinst_list $f | grep -q "^ *[0-9][0-9]* *kinst "; then
			failed="$failed $f"
		fi
	done
	[ -z "$failed" ] || atf_fail "kinst probes created in:$failed"
}

atf_test_case allowed
allowed_head()
{
	atf_set "descr" "kinst still instruments ordinary kernel functions"
	atf_set "require.user" "root"
	atf_set "require.kmods" "kinst"
	atf_set "require.progs" "dtrace"
}
allowed_body()
{
	kinst_list vm_fault | grep -q "^ *[0-9][0-9]* *kinst " ||
	    atf_fail "no kinst probe in vm_fault"
}

atf_init_test_cases()
{
	atf_add_test_case refused
	atf_add_test_case allowed
}
