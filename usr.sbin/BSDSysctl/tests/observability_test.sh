#!/usr/libexec/atf-sh

atf_test_case dtrace_contract
dtrace_contract_head()
{
	atf_set "descr" \
	    "LocalSysctl exposes request outcome and latency probes to bsdinstruments"
}
dtrace_contract_body()
{
	local binary profile provider source srctree

	# The test package stages the contract sources beneath srctree/.
	srctree="$(atf_get_srcdir)/srctree"
	test -d "${srctree}" ||
	    atf_skip "staged source files (${srctree}) required for contract checks"
	provider="${srctree}/usr.sbin/BSDSysctl/bsdsysctl_provider.d"
	source="${srctree}/usr.sbin/BSDSysctl/bsdsysctl.c"
	profile="${srctree}/cddl/usr.sbin/bsdinstruments/profiles/capability-services.d"
	for probe in request__start request__done; do
		atf_check -s exit:0 -o ignore grep -F "probe ${probe}" "${provider}"
	done
	for macro in BSDSYSCTL_PROBE_REQUEST_START \
	    BSDSYSCTL_PROBE_REQUEST_DONE; do
		atf_check -s exit:0 -o ignore grep -F "${macro}" "${source}"
	done
	for clause in 'bsdsysctl*:::request-start' \
	    'bsdsysctl*:::request-done' bsdsysctl_latency_ns; do
		atf_check -s exit:0 -o ignore grep -F "${clause}" "${profile}"
	done
	if [ "@MK_DTRACE@" = "yes" ]; then
		binary="/Capabilities/System/Sysctl.cap/Units/bsdsysctl.unit/bin/BSDSysctl"
		test -x "${binary}" ||
		    atf_fail "missing LocalSysctl binary: ${binary}"
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S "${binary}"
	fi
}

atf_init_test_cases()
{
	atf_add_test_case dtrace_contract
}
