#!/usr/libexec/atf-sh

atf_test_case manifest cleanup
manifest_head()
{
	atf_set "descr" "[CRYPTO] is a verified system capability bundle"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/localcrypto"
	objdir="@OBJTOP@/usr.sbin/localcrypto"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	manifest="${srcdir}/capbundle/crypto.ucl"
	bundle="${PWD}/Crypto.cap"

	test -x "${servicectl}" || atf_skip "source-built servicectl is required"
	test ! -e "${bundle}" || atf_fail "stale test bundle: ${bundle}"
	atf_check -s exit:0 mkdir -p "${bundle}/bin" "${bundle}/etc"
	atf_check -s exit:0 cp "${objdir}/localcrypto" "${bundle}/bin/localcrypto"
	atf_check -s exit:0 cp "${manifest}" "${bundle}/etc/crypto.ucl"
	atf_check -s exit:0 chmod 0555 "${bundle}" "${bundle}/bin" "${bundle}/etc" \
	    "${bundle}/bin/localcrypto"
	atf_check -s exit:0 chmod 0444 "${bundle}/etc/crypto.ucl"

	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"

	chmod 0644 "${bundle}/etc/crypto.ucl"
	printf '%s\n' 'ambient_authority = true;' >> "${bundle}/etc/crypto.ucl"
	atf_check -s not-exit:0 -e match:'unknown key' \
	    "${servicectl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/Crypto.cap" 2>/dev/null || true
	rm -rf "${PWD}/Crypto.cap"
}

atf_test_case provider_security_contract
provider_security_contract_head()
{
	atf_set "descr" "[CRYPTO] workers retain no ambient authority or key material"
}
provider_security_contract_body()
{
	source="@SRCTOP@/usr.sbin/localcrypto/localcrypto.c"

	for token in SERVICE_PROTECT_NOFORK SERVICE_PROTECT_NOIPC \
	    SERVICE_PROTECT_NOFDRECV SERVICE_PROTECT_NOEXEC SERVICE_PROTECT_NOSOCK \
	    service_worker_drop_inherited_authority cap_enter explicit_bzero \
	    service_component_client_label cryptocmp_named_create_policy_validate \
	    cryptodesc_named_create cryptodesc_named_lease cryptodesc_named_rotate \
	    cryptodesc_named_delete
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case provider_security_contract
}
