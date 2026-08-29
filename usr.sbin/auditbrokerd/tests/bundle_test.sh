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

atf_test_case manifest
manifest_body()
{
	src="@SRCTOP@/usr.sbin/auditbrokerd"
	obj="@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin"
	bundle="${PWD}/Audit.cap"
	unit="${bundle}/Units/auditbrokerd.unit"

	test -x "${obj}" || atf_skip "servicectl test binary is required"
	mkdir -p "${unit}/bin"
	cp "${src}/capbundle/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "@OBJTOP@/usr.sbin/auditbrokerd/auditbrokerd" "${unit}/bin/Audit"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S \
		    "@OBJTOP@/usr.sbin/auditbrokerd/auditbrokerd"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' readelf -S \
		    "@OBJTOP@/usr.sbin/auditbrokerd/auditbrokerd"
	fi
	cp "${src}/capbundle/auditbrokerd.ucl" "${unit}/Unit.ucl"
	atf_check -s exit:0 -o ignore "${obj}" verify "${bundle}"
}

atf_test_case security_contract
security_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/auditbrokerd/auditcmp.c"
	manifest="@SRCTOP@/usr.sbin/auditbrokerd/capbundle/auditbrokerd.ucl"
	syscalls="@SRCTOP@/sys/kern/syscalls.master"
	wrappers="@SRCTOP@/contrib/openbsm/libbsm/bsm_wrappers.c"
	for token in auditcmp_policy_event SERVICE_PROTECT_NOFORK \
	    SERVICE_PROTECT_NOFDRECV SERVICE_PROTECT_NOSOCK cap_enter \
	    AUDITCMP_RATE_PER_SECOND
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	atf_check -s exit:0 -o match:'user = "root"' grep user "${manifest}"
	atf_check -s exit:1 -o empty grep SERVICE_PROTECT_NOPRIVS "${source}"
	atf_check -s exit:0 -o match:'STD|CAPENABLED' \
	    grep '^445.*AUE_AUDIT.*STD|CAPENABLED' "${syscalls}"
	atf_check -s exit:0 -o match:'AUE_AUDITON.*STD' \
	    grep '^446' "${syscalls}"
	atf_check -s exit:1 -o empty \
	    grep '^446.*CAPENABLED' "${syscalls}"
	atf_check -s exit:0 -o match:'errno == ECAPMODE' \
	    grep 'errno == ECAPMODE' "${wrappers}"
	atf_check -s exit:0 -o match:'error == ENOTSUP' \
	    grep 'error == ENOTSUP' "${wrappers}"
	atf_check -s exit:0 -o match:'PRIV_AUDIT_SUBMIT' \
	    grep PRIV_AUDIT_SUBMIT \
	    "@SRCTOP@/sys/security/audit/audit_syscalls.c"
	atf_check -s exit:0 -o match:'jailed' \
	    grep 'jailed(td->td_ucred)' \
	    "@SRCTOP@/sys/security/audit/audit_syscalls.c"
}

atf_test_case observability_contract
observability_contract_body()
{
	require_srctree
	provider="@SRCTOP@/usr.sbin/auditbrokerd/auditbrokerd_provider.d"
	source="@SRCTOP@/usr.sbin/auditbrokerd/auditcmp.c"
	for probe in session submit reject; do
		atf_check -s exit:0 -o ignore grep "probe ${probe}" "$provider"
	done
	for macro in AUDITBROKERD_PROBE_SESSION AUDITBROKERD_PROBE_SUBMIT \
	    AUDITBROKERD_PROBE_REJECT; do
		atf_check -s exit:0 -o ignore grep "$macro" "$source"
	done
}

atf_test_case bounded_worker_lifecycle
bounded_worker_lifecycle_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/auditbrokerd/auditcmp.c"
	for token in AUDITCMP_MAX_WORKERS EVFILT_PROCDESC NOTE_EXIT \
	    service_provider_quiescing service_provider_quiesce_complete \
	    pdkill pdwait; do
		atf_check -s exit:0 -o ignore grep "${token}" "${source}"
	done
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case security_contract
	atf_add_test_case observability_contract
	atf_add_test_case bounded_worker_lifecycle
}
