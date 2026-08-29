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
	atf_set "descr" "[CRYPTO] is a verified system capability bundle"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/Crypto"
	objdir="@OBJTOP@/usr.sbin/Crypto"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	manifest="${srcdir}/capbundle/crypto.ucl"
	bundle="${PWD}/Crypto.cap"
	unit="${bundle}/Units/localcrypto.unit"

	test -x "${servicectl}" || atf_skip "source-built servicectl is required"
	test ! -e "${bundle}" || atf_fail "stale test bundle: ${bundle}"
	atf_check -s exit:0 mkdir -p "${unit}/bin"
	atf_check -s exit:0 cp "${srcdir}/capbundle/Bundle.ucl" "${bundle}/Bundle.ucl"
	atf_check -s exit:0 cp "${objdir}/localcrypto" "${unit}/bin/Crypto"
	atf_check -s exit:0 cp "${manifest}" "${unit}/Unit.ucl"
	atf_check -s exit:0 chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" \
	    "${unit}/bin" "${unit}/bin/Crypto"
	atf_check -s exit:0 chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl"

	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"

	chmod 0644 "${unit}/Unit.ucl"
	printf '%s\n' 'ambient_authority = true;' >> "${unit}/Unit.ucl"
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
	require_srctree
	source="@SRCTOP@/usr.sbin/Crypto/localcrypto.c"
	srcdir="@SRCTOP@/usr.sbin/Crypto"

	for token in SERVICE_PROTECT_NOFORK SERVICE_PROTECT_NOIPC \
	    SERVICE_PROTECT_NOFDRECV SERVICE_PROTECT_NOEXEC SERVICE_PROTECT_NOSOCK \
	    service_worker_drop_inherited_authority cap_enter explicit_bzero \
	    harden_control_descriptor CAP_XFER_NONE CAP_CLOFORK_LOCKED \
	    CAP_CLOEXEC_LOCKED cap_ioctls_limit cap_rights_limit CAP_IOCTL \
	    service_component_client_label cryptocmp_named_create_policy_validate \
	    cryptodesc_named_create cryptodesc_named_lease cryptodesc_named_rotate \
	    cryptodesc_named_delete auditcmp_client_prepare auditcmp_client_adopt \
	    auditcmp_submit named-create named-lease named-rotate named-delete
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	atf_check -s exit:0 -o match:'LIBADD=.*auditcmp' \
	    grep 'LIBADD=.*auditcmp' "${srcdir}/Makefile"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case provider_security_contract
}
