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
	atf_set "descr" "Kernel LocalNetwork is a verified system .cap bundle"
}
manifest_body()
{
	require_srctree
	srcdir="@SRCTOP@/usr.sbin/localnetwork"
	objdir="@OBJTOP@/usr.sbin/localnetwork"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	manifest="${srcdir}/capbundle/localnetwork.ucl"
	bundle="${PWD}/Network.cap"
	unit="${bundle}/Units/localnetwork.unit"

	test -x "${servicectl}" ||
	    atf_skip "source-built servicectl is required"
	mkdir -p "${unit}/bin"
	cp "${srcdir}/capbundle/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "${objdir}/localnetwork" "${unit}/bin/Network"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S \
		    "${objdir}/localnetwork"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' readelf -S \
		    "${objdir}/localnetwork"
	fi
	cp "${manifest}" "${unit}/Unit.ucl"
	chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" "${unit}/bin" \
	    "${unit}/bin/Network"
	chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl"

	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
	atf_check -s exit:0 -o match:'system.Network' \
	    grep 'activation' "${manifest}"
	atf_check -s exit:1 -o empty -e empty \
	    grep 'interface' "${manifest}"
	atf_check -s exit:0 -o match:'version = "1.0.0"' \
	    grep 'version = "1.0.0"' "${srcdir}/capbundle/Bundle.ucl"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/Network.cap" 2>/dev/null || true
	rm -rf "${PWD}/Network.cap"
}

atf_test_case kernel_security_contract
kernel_security_contract_head()
{
	atf_set "descr" \
	    "Kernel worker uses an attenuated network broker in capability mode"
}

atf_test_case observability_contract
observability_contract_head()
{
	atf_set "descr" \
	    "LocalNetwork exposes session, request, resolver, rejection, and audit observability"
}
observability_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/localnetwork/networkcmp.c"
	provider="@SRCTOP@/usr.sbin/localnetwork/localnetwork_provider.d"

	for probe in SESSION_START SESSION_END REQUEST_DONE RESOLVE_START \
	    RESOLVE_DONE REJECT
	do
		atf_check -s exit:0 -o match:"LOCALNETWORK_${probe}" \
		    grep "LOCALNETWORK_${probe}" "${source}"
	done
	for probe in session__start session__end request__done resolve__start \
	    resolve__done reject
	do
		atf_check -s exit:0 -o match:"${probe}" grep "${probe}" \
		    "${provider}"
	done
	atf_check -s exit:0 -o match:'auditcmp_submit' grep auditcmp_submit \
	    "${source}"
}
kernel_security_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/localnetwork/networkcmp.c"

	atf_check -s exit:0 -o match:'NETWORKCMP_FEATURE_DNS' \
	    grep NETWORKCMP_FEATURE_DNS "${source}"
	atf_check -s exit:0 -o match:'cap_getaddrinfo' \
	    grep cap_getaddrinfo "${source}"
	atf_check -s exit:0 -o match:'CAPNET_NAME2ADDR' \
	    grep CAPNET_NAME2ADDR "${source}"
	atf_check -s exit:0 -o match:'CAPNET_CONNECT' \
	    grep CAPNET_CONNECT "${source}"
	atf_check -s exit:0 -o match:'CAPNET_BIND' \
	    grep CAPNET_BIND "${source}"
	atf_check -s exit:0 -o match:'cap_connect' \
	    grep cap_connect "${source}"
	atf_check -s exit:0 -o match:'cap_bind' \
	    grep cap_bind "${source}"
	atf_check -s exit:0 -o match:'socket' \
	    grep -F 'socket(' "${source}"
	atf_check -s exit:0 -o match:'CAP_XFER_NONE' \
	    grep CAP_XFER_NONE "${source}"
	atf_check -s exit:0 -o match:'CAP_CLOFORK_ONCE' \
	    grep CAP_CLOFORK_ONCE "${source}"
	atf_check -s exit:0 -o match:'CAP_CLOFORK_LOCKED' \
	    grep CAP_CLOFORK_LOCKED "${source}"
	atf_check -s exit:0 -o match:'CAP_CLOEXEC_LOCKED' \
	    grep CAP_CLOEXEC_LOCKED "${source}"
	atf_check -s exit:0 -o match:'cap_enter' \
	    grep cap_enter "${source}"
	for token in auditcmp_client_prepare auditcmp_client_adopt auditcmp_submit
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	atf_check -s exit:1 -o empty -e empty grep 'audit_submit(' "${source}"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case kernel_security_contract
	atf_add_test_case observability_contract
}
