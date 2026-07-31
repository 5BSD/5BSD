#!/usr/libexec/atf-sh

atf_test_case manifest cleanup
manifest_head()
{
	atf_set "descr" "LogCmp is a verified system .cap bundle"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/logcmp"
	objdir="@OBJTOP@/usr.sbin/logcmp"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	bundle="${PWD}/LogCmp.cap"

	test -x "${servicectl}" ||
	    atf_skip "source-built servicectl is required"
	mkdir -p "${bundle}/bin" "${bundle}/etc"
	cp "${objdir}/logcmp" "${bundle}/bin/logcmp"
	cp "${srcdir}/capbundle/logcmp.ucl" "${bundle}/etc/logcmp.ucl"
	chmod 0555 "${bundle}" "${bundle}/bin" "${bundle}/etc" \
	    "${bundle}/bin/logcmp"
	chmod 0444 "${bundle}/etc/logcmp.ucl"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/LogCmp.cap" 2>/dev/null || true
	rm -rf "${PWD}/LogCmp.cap"
}

atf_test_case security_contract
security_contract_head()
{
	atf_set "descr" "LogCmp is sandboxed, audited, traced, and sink-limited"
}
security_contract_body()
{
	source="@SRCTOP@/usr.sbin/logcmp/logcmp.c"

	for token in SERVICE_PROTECT_NOFORK SERVICE_PROTECT_NOSOCK \
	    CAP_XFER_NONE CAP_CLOFORK_ONCE CAP_CLOEXEC_LOCKED cap_enter \
	    system.syslog AUE_LOGCMP_POLICY
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	atf_check -s exit:0 -o match:'probe record__drop' \
	    grep 'probe record__drop' \
	    "@SRCTOP@/usr.sbin/logcmp/logcmp_provider.d"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case security_contract
}
