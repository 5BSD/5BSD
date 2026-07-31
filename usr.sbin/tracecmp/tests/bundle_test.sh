#!/usr/libexec/atf-sh

atf_test_case manifest cleanup
manifest_head()
{
	atf_set "descr" "TraceCmp is a verified, explicitly privileged .cap bundle"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/tracecmp"
	objdir="@OBJTOP@/usr.sbin/tracecmp"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	bundle="${PWD}/TraceCmp.cap"

	test -x "${servicectl}" || atf_skip "test servicectl is required"
	mkdir -p "${bundle}/bin" "${bundle}/etc"
	cp "${objdir}/tracecmp" "${bundle}/bin/tracecmp"
	cp "${srcdir}/capbundle/tracecmp.ucl" "${bundle}/etc/tracecmp.ucl"
	chmod 0555 "${bundle}" "${bundle}/bin" "${bundle}/etc" \
	    "${bundle}/bin/tracecmp"
	chmod 0444 "${bundle}/etc/tracecmp.ucl"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/TraceCmp.cap" 2>/dev/null || true
	rm -rf "${PWD}/TraceCmp.cap"
}

atf_test_case security_contract
security_contract_head()
{
	atf_set "descr" "TraceCmp denies raw delegation and uses cap mode, audit, and DTrace probes"
}
security_contract_body()
{
	source="@SRCTOP@/usr.sbin/tracecmp/tracecmp.c"
	for token in CAP_XFER_NONE cap_enter SERVICE_PROTECT_NOFORK \
	    AUE_TRACECMP_POLICY TRACECMPD_PROBE_REJECT \
	    'hello.features = 0'
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	for forbidden in '/dev/dtrace' DTRACEIOC raw-dtrace-fd-delegated
	do
		atf_check -s exit:1 -o empty grep -F "${forbidden}" "${source}"
	done
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case security_contract
}
