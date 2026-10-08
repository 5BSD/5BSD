#!/usr/libexec/atf-sh

# The contract cases grep the daemon sources and DTrace providers.  The test
# package installs those files beneath srctree/ next to this program, so an
# installed test needs no build machine source tree.  The manifest case
# assembles a bundle from the installed artifacts.
require_srctree()
{
	SRCTREE="$(atf_get_srcdir)/srctree"
	test -d "${SRCTREE}" ||
	    atf_skip "staged source files (${SRCTREE}) required for contract checks"
}

atf_test_case manifest cleanup
manifest_head()
{
	atf_set "descr" "Bloodhound is a verified, explicitly privileged .cap bundle"
}
manifest_body()
{
	installed="/Capabilities/System/Trace.cap"
	installed_unit="${installed}/Units/bsdtrace.unit"
	switchboardctl="${SWITCHBOARDCTL:-$(atf_get_srcdir)/../switchboardctl/switchboardctl_test_bin}"
	bundle="${PWD}/Trace.cap"
	unit="${bundle}/Units/bsdtrace.unit"

	test -x "${switchboardctl}" || atf_skip "test switchboardctl is required"
	test -x "${installed_unit}/bin/BSDTrace" ||
	    atf_skip "installed Trace.cap bundle is required"
	mkdir -p "${unit}/bin"
	cp "${installed}/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "${installed_unit}/bin/BSDTrace" "${unit}/bin/BSDTrace"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' \
		    readelf -S "${installed_unit}/bin/BSDTrace"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' \
		    readelf -S "${installed_unit}/bin/BSDTrace"
	fi
	cp "${installed_unit}/Unit.ucl" "${unit}/Unit.ucl"
	chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" "${unit}/bin" \
	    "${unit}/bin/BSDTrace"
	chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${switchboardctl}" verify "${bundle}"
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
	source="${SRCTREE}/usr.sbin/BSDTrace/tracecmp.c"
	for token in TRACECMP_MAX_WORKERS EVFILT_PROCDESC NOTE_EXIT \
	    service_provider_quiescing service_provider_quiesce_complete \
	    pdkill pdwait; do
		atf_check -s exit:0 -o ignore grep "${token}" "${source}"
	done
}
observability_contract_body()
{
	require_srctree
	provider="${SRCTREE}/usr.sbin/BSDTrace/bsdtrace_provider.d"
	client="${SRCTREE}/lib/libtracecmp/tracecmp_provider.d"
	for probe in session__start session__end delegate reject; do
		atf_check -s exit:0 -o ignore grep "probe ${probe}" "$provider"
	done
	for macro in BSDTRACE_PROBE_SESSION_START BSDTRACE_PROBE_SESSION_END \
	    BSDTRACE_PROBE_DELEGATE BSDTRACE_PROBE_REJECT; do
		atf_check -s exit:0 -o ignore grep "$macro" \
		    "${SRCTREE}/usr.sbin/BSDTrace/tracecmp.c"
	done
	for probe in open send receive reject; do
		atf_check -s exit:0 -o ignore grep "probe ${probe}" "$client"
	done
	for macro in TRACECMP_PROBE_OPEN TRACECMP_PROBE_SEND \
	    TRACECMP_PROBE_RECEIVE TRACECMP_PROBE_REJECT; do
		atf_check -s exit:0 -o ignore grep "$macro" \
		    "${SRCTREE}/lib/libtracecmp/tracecmp.c"
	done
}
security_contract_body()
{
	require_srctree
	source="${SRCTREE}/usr.sbin/BSDTrace/tracecmp.c"
	for token in CAP_XFER_ONCE CAP_CLOFORK_LOCKED \
	    service_worker_enter_capability_mode \
	    service_provider_enter_capability_mode \
	    SERVICE_PROTECT_NOFORK \
	    AUE_TRACECMP_POLICY BSDTRACE_PROBE_REJECT \
	    cap_ioctls_limit \
	    raw-dtrace-fd-delegated AU_DEFAUDITID TRACECMP_CLIENT_TIMEOUT_MS
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	for forbidden in DTRACEIOC_REPLICATE
	do
		atf_check -s exit:1 -o empty grep -F "${forbidden}" "${source}"
	done
	atf_check -s exit:0 -o match:'TRACECMP_POLICY_PATH' \
	    grep TRACECMP_POLICY_PATH \
	    "${SRCTREE}/usr.sbin/BSDTrace/tracecmp_policy.h"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case security_contract
	atf_add_test_case observability_contract
	atf_add_test_case bounded_worker_lifecycle
}
