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
	obj="@OBJTOP@/usr.sbin/switchboardctl/tests/switchboardctl_test_bin"
	bundle="${PWD}/Audit.cap"
	unit="${bundle}/Units/auditbrokerd.unit"

	test -x "${obj}" || atf_skip "switchboardctl test binary is required"
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
	    SERVICE_PROTECT_NOFDRECV SERVICE_PROTECT_NOSOCK \
	    service_worker_enter_capability_mode \
	    service_provider_enter_capability_mode \
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

# The auth agent's per-operation event classes: backend_submit() refines the
# session's admission event by the record's operation prefix, so an
# "elevate/..." record commits as AUE_AUTHAGENT_ELEVATE (43335) and a
# "mint/..." record as AUE_AUTHAGENT_MINT (43336).  The C policy_test drives
# the mapping; this pins the wiring and the registered numbers.
atf_test_case auth_agent_event_contract
auth_agent_event_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/auditbrokerd/auditcmp.c"
	policy="@SRCTOP@/usr.sbin/auditbrokerd/auditcmp_policy.c"
	header="@SRCTOP@/usr.sbin/auditbrokerd/auditcmp_policy.h"
	kevents="@SRCTOP@/sys/bsm/audit_kevents.h"
	events="@SRCTOP@/contrib/openbsm/etc/audit_event"

	atf_check -s exit:0 -o ignore grep -F \
	    'int	auditcmp_policy_operation_event(const char *, const char *, int);' \
	    "${header}"
	atf_check -s exit:0 -o ignore grep -F \
	    'event = auditcmp_policy_operation_event(provider, operation, event);' \
	    "${source}"
	# ...applied inside backend_submit(), before audit_submit().
	atf_check -s exit:0 -o ignore sh -c \
	    "awk '/^backend_submit\(/,/^}/' '${source}' |
	     awk '/auditcmp_policy_operation_event/ { p = NR }
	          /audit_submit\(/ { s = NR }
	          END { exit !(p && s && p < s) }'"
	atf_check -s exit:0 -o ignore grep -F \
	    '{ "system.AuthAgent", "elevate", AUE_AUTHAGENT_ELEVATE }' "${policy}"
	atf_check -s exit:0 -o ignore grep -F \
	    '{ "system.AuthAgent", "mint", AUE_AUTHAGENT_MINT }' "${policy}"
	# The historical providers keep a NULL operation (every operation).
	for provider in system.Log system.Network system.Notify system.Crypto; do
		atf_check -s exit:0 -o ignore grep -F \
		    "{ \"${provider}\", NULL, " "${policy}"
	done
	atf_check -s exit:0 -o ignore grep -E \
	    '^#define[[:space:]]+AUE_AUTHAGENT_ELEVATE[[:space:]]+43335([[:space:]]|$)' \
	    "${kevents}"
	atf_check -s exit:0 -o ignore grep -E \
	    '^#define[[:space:]]+AUE_AUTHAGENT_MINT[[:space:]]+43336([[:space:]]|$)' \
	    "${kevents}"
	atf_check -s exit:0 -o ignore grep '^43335:AUE_AUTHAGENT_ELEVATE:' \
	    "${events}"
	atf_check -s exit:0 -o ignore grep '^43336:AUE_AUTHAGENT_MINT:' \
	    "${events}"
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
	atf_add_test_case auth_agent_event_contract
	atf_add_test_case bounded_worker_lifecycle
}
