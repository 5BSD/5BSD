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
	atf_set "descr" "LocalFilesystem is a verified system .cap bundle"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/localfilesystem"
	objdir="@OBJTOP@/usr.sbin/localfilesystem"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	manifest="${srcdir}/capbundle/localfilesystem.ucl"
	bundle="${PWD}/LocalFilesystem.cap"
	unit="${bundle}/Units/localfilesystem.unit"

	test -x "${servicectl}" ||
	    atf_skip "source-built servicectl is required"
	mkdir -p "${unit}/bin"
	cp "${srcdir}/capbundle/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "${objdir}/localfilesystem" "${unit}/bin/localfilesystem"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S \
		    "${objdir}/localfilesystem"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' readelf -S \
		    "${objdir}/localfilesystem"
	fi
	cp "${manifest}" "${unit}/Unit.ucl"
	chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" "${unit}/bin" \
	    "${unit}/bin/localfilesystem"
	chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl"

	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"

	chmod 0644 "${unit}/Unit.ucl"
	printf '%s\n' 'ambient_authority = true;' >> \
	    "${unit}/Unit.ucl"
	atf_check -s not-exit:0 -e match:'unknown key' \
	    "${servicectl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/LocalFilesystem.cap" 2>/dev/null || true
	rm -rf "${PWD}/LocalFilesystem.cap"
}

atf_test_case provider_security_contract
provider_security_contract_head()
{
	atf_set "descr" \
	    "LocalFilesystem workers are audited and propagation-hardened"
}

atf_test_case observability_contract
observability_contract_head()
{
	atf_set "descr" \
	    "LocalFilesystem exposes component, session, request, and audit observability"
}
observability_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/localfilesystem/filesystemcmp.c"
	provider="@SRCTOP@/usr.sbin/localfilesystem/localfilesystem_provider.d"

	for probe in LOCALFILESYSTEM_PROBE_SESSION \
	    LOCALFILESYSTEM_PROBE_SESSION_END LOCALFILESYSTEM_PROBE_REQUEST
	do
		atf_check -s exit:0 -o match:"${probe}" grep "${probe}" \
		    "${source}"
	done
	for probe in session__start session__end request__done
	do
		atf_check -s exit:0 -o match:"${probe}" grep "${probe}" \
		    "${provider}"
	done
	atf_check -s exit:0 -o match:'auditcmp_submit' grep auditcmp_submit \
	    "${source}"
}
provider_security_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/localfilesystem/filesystemcmp.c"

	atf_check -s exit:0 -o match:'SERVICE_PROTECT_NOFORK' \
	    grep SERVICE_PROTECT_NOFORK "${source}"
	atf_check -s exit:0 -o match:'SERVICE_PROTECT_NOSOCK' \
	    grep SERVICE_PROTECT_NOSOCK "${source}"
	atf_check -s exit:0 -o match:'CAP_XFER_NONE' \
	    grep CAP_XFER_NONE "${source}"
	atf_check -s exit:0 -o match:'CAP_CLOFORK_ONCE' \
	    grep CAP_CLOFORK_ONCE "${source}"
	atf_check -s exit:0 -o match:'CAP_CLOFORK_LOCKED' \
	    grep CAP_CLOFORK_LOCKED "${source}"
	atf_check -s exit:0 -o match:'CAP_CLOEXEC_LOCKED' \
	    grep CAP_CLOEXEC_LOCKED "${source}"
	atf_check -s exit:0 -o match:'harden_resource_fd' \
	    grep harden_resource_fd "${source}"
	atf_check -s exit:0 -o match:'CAP_RENAMEAT_SOURCE' \
	    grep CAP_RENAMEAT_SOURCE "${source}"
	atf_check -s exit:0 -o match:'cap_fcntls_limit' \
	    grep cap_fcntls_limit "${source}"
	atf_check -s exit:0 -o match:'cap_enter' \
	    grep cap_enter "${source}"
	for token in auditcmp_client_prepare auditcmp_client_adopt auditcmp_submit
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	atf_check -s exit:1 -o empty -e empty grep 'audit_submit(' "${source}"
	atf_check -s exit:0 -o match:'LOCALFILESYSTEM_PROBE_SESSION' \
	    grep LOCALFILESYSTEM_PROBE_SESSION "${source}"
	atf_check -s exit:0 -o match:'LOCALFILESYSTEM_PROBE_REQUEST' \
	    grep LOCALFILESYSTEM_PROBE_REQUEST "${source}"
	atf_check -s exit:0 -o match:'request__done' \
	    grep request__done \
	    "@SRCTOP@/usr.sbin/localfilesystem/localfilesystem_provider.d"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case provider_security_contract
	atf_add_test_case observability_contract
}
