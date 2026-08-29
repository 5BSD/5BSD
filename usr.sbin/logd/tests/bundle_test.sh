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
	atf_set "descr" "Ledger is a verified system .cap bundle"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/logd"
	objdir="@OBJTOP@/usr.sbin/logd"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	bundle="${PWD}/Log.cap"
	unit="${bundle}/Units/logd.unit"

	test -x "${servicectl}" ||
	    atf_skip "source-built servicectl is required"
	mkdir -p "${unit}/bin" "${unit}/Config"
	cp "${srcdir}/capbundle/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "${objdir}/logd" "${unit}/bin/Log"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S "${objdir}/logd"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' readelf -S "${objdir}/logd"
	fi
	cp "${srcdir}/capbundle/logd.ucl" "${unit}/Unit.ucl"
	cp "${srcdir}/capbundle/logd.conf" "${unit}/Config/logd.conf"
	chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" "${unit}/bin" \
	    "${unit}/bin/Log" "${unit}/Config"
	chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl" \
	    "${unit}/Config/logd.conf"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/Log.cap" 2>/dev/null || true
	rm -rf "${PWD}/Log.cap"
}

atf_test_case security_contract
security_contract_head()
{
	atf_set "descr" "Ledger is sandboxed, audited, traced, and sink-limited"
}

atf_test_case observability_contract
observability_contract_head()
{
	atf_set "descr" "Ledger exposes lifecycle, batching, wake, flush, and loss probes"
}

atf_test_case bounded_pool_contract
bounded_pool_contract_head()
{
	atf_set "descr" \
	    "Ledger uses fixed configurable shards and no per-client worker fork"
}
bounded_pool_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/logd/logcmp.c"
	config="@SRCTOP@/usr.sbin/logd/capbundle/logd.conf"
	for token in pool_worker dispatch_to_pool logcmp_storage_attach_pool \
	    logcmp_session_drain_budget CAP_XFER_ONCE; do
		atf_check -s exit:0 -o ignore grep "${token}" "${source}"
	done
	atf_check -s exit:1 -o empty -e empty grep '^start_session(' "${source}"
	for key in ingress_shards max_sessions drain_batch; do
		atf_check -s exit:0 -o ignore grep "${key}" "${config}"
	done
}
observability_contract_body()
{
	require_srctree
	provider="@SRCTOP@/usr.sbin/logd/logd_provider.d"
	client="@SRCTOP@/lib/liblogcmp/logcmp_provider.d"
	for probe in pool__start pool__admit pool__shutdown session__start session__end record__write record__drop wakeup__receive \
	    batch__drain flush__complete storage__persist storage__rotate \
	    storage__corruption query__complete; do
		atf_check -s exit:0 -o ignore grep "probe ${probe}" "$provider"
	done
	for probe in component__open message__send message__receive \
	    message__reject record__enqueue wakeup__send flush__complete \
	    reconnect; do
		atf_check -s exit:0 -o ignore grep "probe ${probe}" "$client"
	done
	atf_check -s exit:0 -o ignore grep LOGD_PROBE_BATCH \
	    "@SRCTOP@/usr.sbin/logd/logcmp.c"
	atf_check -s exit:0 -o ignore grep LOGD_PROBE_SESSION_END \
	    "@SRCTOP@/usr.sbin/logd/logcmp.c"
	atf_check -s exit:0 -o ignore grep LOGD_PROBE_QUERY \
	    "@SRCTOP@/usr.sbin/logd/logcmp.c"
	atf_check -s exit:0 -o ignore grep LOGCMP_PROBE_ENQUEUE \
	    "@SRCTOP@/lib/liblogcmp/logcmp.c"
}
security_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/logd/logcmp.c"

	for token in SERVICE_PROTECT_NOFORK SERVICE_PROTECT_NOSOCK \
	    CAP_XFER_NONE CAP_CLOFORK_ONCE CAP_CLOEXEC_LOCKED cap_enter \
	    system.syslog auditcmp_client_prepare auditcmp_client_adopt \
	    auditcmp_submit
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	atf_check -s exit:1 -o empty -e empty grep 'audit_submit(' "${source}"
	atf_check -s exit:0 -o match:'probe record__drop' \
	    grep 'probe record__drop' \
	    "@SRCTOP@/usr.sbin/logd/logd_provider.d"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case security_contract
	atf_add_test_case observability_contract
	atf_add_test_case bounded_pool_contract
}
