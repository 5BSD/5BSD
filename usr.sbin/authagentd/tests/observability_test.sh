#!/usr/libexec/atf-sh

atf_test_case dtrace_contract
dtrace_contract_head()
{
	atf_set "descr" \
	    "AuthAgent exposes request outcome and latency probes to bsdinstruments"
}
dtrace_contract_body()
{
	local binary profile provider source

	test -d "@SRCTOP@" ||
	    atf_skip "source tree (@SRCTOP@) required for contract checks"
	provider="@SRCTOP@/usr.sbin/authagentd/authagentd_provider.d"
	source="@SRCTOP@/usr.sbin/authagentd/authagentd.c"
	profile="@SRCTOP@/cddl/usr.sbin/bsdinstruments/profiles/capability-services.d"
	for probe in request__start request__done; do
		atf_check -s exit:0 -o ignore grep -F "probe ${probe}" "${provider}"
	done
	for macro in AUTHAGENT_PROBE_REQUEST_START \
	    AUTHAGENT_PROBE_REQUEST_DONE; do
		atf_check -s exit:0 -o ignore grep -F "${macro}" "${source}"
	done
	for clause in 'authagent*:::request-start' \
	    'authagent*:::request-done' authagent_latency_ns; do
		atf_check -s exit:0 -o ignore grep -F "${clause}" "${profile}"
	done
	if [ "@MK_DTRACE@" = "yes" ]; then
		binary="@OBJTOP@/usr.sbin/authagentd/authagentd"
		test -x "${binary}" ||
		    atf_fail "missing AuthAgent binary: ${binary}"
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S "${binary}"
	fi
}

atf_init_test_cases()
{
	atf_add_test_case dtrace_contract
}
