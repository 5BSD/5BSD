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
	atf_set "descr" "[CRYPTO] is a verified system capability bundle"
}
manifest_body()
{
	installed="/Capabilities/System/Crypto.cap"
	installed_unit="${installed}/Units/bsdcrypto.unit"
	switchboardctl="${SWITCHBOARDCTL:-$(atf_get_srcdir)/../switchboardctl/switchboardctl_test_bin}"
	manifest="${installed_unit}/Unit.ucl"
	bundle="${PWD}/Crypto.cap"
	unit="${bundle}/Units/bsdcrypto.unit"

	test -x "${switchboardctl}" || atf_skip "source-built switchboardctl is required"
	test -x "${installed_unit}/bin/BSDCrypto" ||
	    atf_skip "installed Crypto.cap bundle is required"
	test ! -e "${bundle}" || atf_fail "stale test bundle: ${bundle}"
	atf_check -s exit:0 mkdir -p "${unit}/bin"
	atf_check -s exit:0 cp "${installed}/Bundle.ucl" "${bundle}/Bundle.ucl"
	atf_check -s exit:0 cp "${installed_unit}/bin/BSDCrypto" "${unit}/bin/BSDCrypto"
	atf_check -s exit:0 cp "${manifest}" "${unit}/Unit.ucl"
	atf_check -s exit:0 chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" \
	    "${unit}/bin" "${unit}/bin/BSDCrypto"
	atf_check -s exit:0 chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl"

	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${switchboardctl}" verify "${bundle}"

	chmod 0644 "${unit}/Unit.ucl"
	printf '%s\n' 'ambient_authority = true;' >> "${unit}/Unit.ucl"
	atf_check -s not-exit:0 -e match:'unknown key' \
	    "${switchboardctl}" verify "${bundle}"
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
	source="${SRCTREE}/usr.sbin/BSDCrypto/bsdcrypto.c"
	srcdir="${SRCTREE}/usr.sbin/BSDCrypto"

	for token in SERVICE_PROTECT_NOFORK SERVICE_PROTECT_NOIPC \
	    SERVICE_PROTECT_NOFDRECV SERVICE_PROTECT_NOEXEC SERVICE_PROTECT_NOSOCK \
	    service_worker_enter_capability_mode \
	    service_provider_enter_capability_mode explicit_bzero \
	    harden_control_descriptor CAP_XFER_NONE CAP_CLOFORK_LOCKED \
	    CAP_CLOEXEC_LOCKED cap_ioctls_limit cap_rights_limit CAP_IOCTL \
	    service_identity id.client_label cryptocmp_named_create_policy_validate \
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
