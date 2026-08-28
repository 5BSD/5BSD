#!/usr/libexec/atf-sh

# These cases assert source- and object-tree contracts (grep the daemon
# sources, syscall tables and DTrace providers; inspect the built binary).
# Those trees are absent on an installed system, so skip cleanly there rather
# than failing on missing files.
require_srctree()
{
	test -d "@SRCTOP@" ||
	    atf_skip "source tree (@SRCTOP@) required for contract checks"
}

atf_test_case manifest cleanup
manifest_head()
{
	atf_set "descr" "Bloodhound is a verified, explicitly privileged .cap bundle"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/traced"
	objdir="@OBJTOP@/usr.sbin/traced"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	bundle="${PWD}/Trace.cap"
	unit="${bundle}/Units/traced.unit"

	test -x "${servicectl}" || atf_skip "test servicectl is required"
	mkdir -p "${unit}/bin"
	cp "${srcdir}/capbundle/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "${objdir}/traced" "${unit}/bin/traced"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S "${objdir}/traced"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' readelf -S "${objdir}/traced"
	fi
	cp "${srcdir}/capbundle/traced.ucl" "${unit}/Unit.ucl"
	chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" "${unit}/bin" \
	    "${unit}/bin/traced"
	chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/Trace.cap" 2>/dev/null || true
	rm -rf "${PWD}/Trace.cap"
}

atf_test_case security_contract
security_contract_head()
{
	atf_set "descr" "Bloodhound delegates only to explicit labels with bounded descriptor authority"
}

atf_test_case observability_contract
observability_contract_head()
{
	atf_set "descr" "Bloodhound declares and fires session, delegation, rejection, and client-open probes"
}

atf_test_case bounded_worker_lifecycle
bounded_worker_lifecycle_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/traced/tracecmp.c"
	for token in TRACECMP_MAX_WORKERS EVFILT_PROCDESC NOTE_EXIT \
	    service_provider_quiescing service_provider_quiesce_complete \
	    pdkill pdwait; do
		atf_check -s exit:0 -o ignore grep "${token}" "${source}"
	done
}
observability_contract_body()
{
	require_srctree
	provider="@SRCTOP@/usr.sbin/traced/traced_provider.d"
	client="@SRCTOP@/lib/libtracecmp/tracecmp_provider.d"
	for probe in session__start session__end delegate reject; do
		atf_check -s exit:0 -o ignore grep "probe ${probe}" "$provider"
	done
	for macro in TRACED_PROBE_SESSION_START TRACED_PROBE_SESSION_END \
	    TRACED_PROBE_DELEGATE TRACED_PROBE_REJECT; do
		atf_check -s exit:0 -o ignore grep "$macro" \
		    "@SRCTOP@/usr.sbin/traced/tracecmp.c"
	done
	for probe in open send receive reject; do
		atf_check -s exit:0 -o ignore grep "probe ${probe}" "$client"
	done
	for macro in TRACECMP_PROBE_OPEN TRACECMP_PROBE_SEND \
	    TRACECMP_PROBE_RECEIVE TRACECMP_PROBE_REJECT; do
		atf_check -s exit:0 -o ignore grep "$macro" \
		    "@SRCTOP@/lib/libtracecmp/tracecmp.c"
	done
}
security_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/traced/tracecmp.c"
	for token in CAP_XFER_ONCE CAP_CLOFORK_LOCKED cap_enter \
	    SERVICE_PROTECT_NOFORK \
	    AUE_TRACECMP_POLICY TRACED_PROBE_REJECT \
	    TRACECMP_POLICY_PATH cap_ioctls_limit \
	    raw-dtrace-fd-delegated AU_DEFAUDITID TRACECMP_CLIENT_TIMEOUT_MS
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	for forbidden in DTRACEIOC_REPLICATE SERVICE_PROTECT_NOPRIVS
	do
		atf_check -s exit:1 -o empty grep -F "${forbidden}" "${source}"
	done
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case security_contract
	atf_add_test_case observability_contract
	atf_add_test_case bounded_worker_lifecycle
}
