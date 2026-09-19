#!/usr/libexec/atf-sh

atf_test_case dtrace_contract
dtrace_contract_head()
{
	atf_set "descr" \
	    "LocalSysctl exposes request outcome and latency probes to bsdinstruments"
}
dtrace_contract_body()
{
	local binary profile provider source

	test -d "@SRCTOP@" ||
	    atf_skip "source tree (@SRCTOP@) required for contract checks"
	provider="@SRCTOP@/usr.sbin/localsysctl/localsysctl_provider.d"
	source="@SRCTOP@/usr.sbin/localsysctl/localsysctl.c"
	profile="@SRCTOP@/cddl/usr.sbin/bsdinstruments/profiles/capability-services.d"
	for probe in request__start request__done; do
		atf_check -s exit:0 -o ignore grep -F "probe ${probe}" "${provider}"
	done
	for macro in LOCALSYSCTL_PROBE_REQUEST_START \
	    LOCALSYSCTL_PROBE_REQUEST_DONE; do
		atf_check -s exit:0 -o ignore grep -F "${macro}" "${source}"
	done
	for clause in 'localsysctl*:::request-start' \
	    'localsysctl*:::request-done' localsysctl_latency_ns; do
		atf_check -s exit:0 -o ignore grep -F "${clause}" "${profile}"
	done
	if [ "@MK_DTRACE@" = "yes" ]; then
		binary="@OBJTOP@/usr.sbin/localsysctl/localsysctl"
		test -x "${binary}" ||
		    atf_fail "missing LocalSysctl binary: ${binary}"
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S "${binary}"
	fi
}

atf_init_test_cases()
{
	atf_add_test_case dtrace_contract
}
