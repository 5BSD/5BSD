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
	atf_set "descr" "Kernel LocalNetwork is a verified system .cap bundle"
}
manifest_body()
{
	installed="/Capabilities/System/Network.cap"
	installed_unit="${installed}/Units/bsdnetwork.unit"
	switchboardctl="${SWITCHBOARDCTL:-$(atf_get_srcdir)/../switchboardctl/switchboardctl_test_bin}"
	manifest="${installed_unit}/Unit.ucl"
	bundle="${PWD}/Network.cap"
	unit="${bundle}/Units/bsdnetwork.unit"

	test -x "${switchboardctl}" ||
	    atf_skip "source-built switchboardctl is required"
	test -x "${installed_unit}/bin/BSDNetwork" ||
	    atf_skip "installed Network.cap bundle is required"
	mkdir -p "${unit}/bin"
	cp "${installed}/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "${installed_unit}/bin/BSDNetwork" "${unit}/bin/BSDNetwork"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S \
		    "${installed_unit}/bin/BSDNetwork"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' readelf -S \
		    "${installed_unit}/bin/BSDNetwork"
	fi
	pfunit="${bundle}/Units/pf.unit"
	mkdir -p "${pfunit}/bin"
	cp "${installed}/Units/pf.unit/Unit.ucl" "${pfunit}/Unit.ucl"
	cp "${installed}/Units/pf.unit/bin/BSDPF" "${pfunit}/bin/BSDPF"
	chmod 0555 "${pfunit}" "${pfunit}/bin" "${pfunit}/bin/BSDPF"
	chmod 0444 "${pfunit}/Unit.ucl"
	cp "${manifest}" "${unit}/Unit.ucl"
	chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" "${unit}/bin" \
	    "${unit}/bin/BSDNetwork"
	chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl"

	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${switchboardctl}" verify "${bundle}"
	atf_check -s exit:0 -o match:'system.Network' \
	    grep 'activation' "${manifest}"
	atf_check -s exit:1 -o empty -e empty \
	    grep 'interface' "${manifest}"
	atf_check -s exit:0 -o match:'version = "1.0.0"' \
	    grep 'version = "1.0.0"' "${installed}/Bundle.ucl"
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
	    "Capability-mode worker uses in-process DNS and attenuated sockets"
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
	source="${SRCTREE}/usr.sbin/BSDNetwork/networkcmp.c"
	provider="${SRCTREE}/usr.sbin/BSDNetwork/bsdnetwork_provider.d"

	for probe in SESSION_START SESSION_END REQUEST_DONE RESOLVE_START \
	    RESOLVE_DONE REJECT
	do
		atf_check -s exit:0 -o match:"BSDNETWORK_${probe}" \
		    grep "BSDNETWORK_${probe}" "${source}"
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
	source="${SRCTREE}/usr.sbin/BSDNetwork/networkcmp.c"
	resolver="${SRCTREE}/usr.sbin/BSDNetwork/resolver.c"
	tzfs_policy="${SRCTREE}/usr.sbin/BSDFilesystem/bsdfilesystem.ucl"

	for token in NETWORKCMP_FEATURE_DNS endpoint_is_internal broker_connect \
	    broker_perform_connect harden_delivered_socket CAP_XFER_ONCE \
	    CAP_CLOFORK_ONCE CAP_CLOEXEC_LOCKED service_harden_fd \
	    service_worker_enter_capability_mode \
	    service_provider_enter_capability_mode auditcmp_client_prepare \
	    auditcmp_client_adopt auditcmp_submit
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	atf_check -s exit:0 -o match:'socket' grep -F 'socket(' "${source}"
	atf_check -s exit:0 -o match:'netresolve' grep -F 'netresolve(' "${source}"
	for token in service_open_isolated hosts_lookup dns_query \
	    RSLV_INSTALLER_CONFIG_PATH 'error != ELOOP && error != EMLINK'
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${resolver}"
	done
	atf_check -s exit:0 -o match:'/tmp/bsdinstall_etc/resolv.conf' \
	    grep '/tmp/bsdinstall_etc/resolv.conf' "${tzfs_policy}"
	atf_check -s exit:1 -o empty -e empty \
	    grep -E 'cap_getaddrinfo|cap_connect[(]|cap_bind[(]' "${source}"
	atf_check -s exit:1 -o empty -e empty grep 'audit_submit(' "${source}"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case kernel_security_contract
	atf_add_test_case observability_contract
}
