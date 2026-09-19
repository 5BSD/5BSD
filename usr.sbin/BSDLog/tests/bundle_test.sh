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
	atf_set "descr" "bsdlog is a verified system .cap bundle"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/bsdlog"
	objdir="@OBJTOP@/usr.sbin/bsdlog"
	switchboardctl="${SWITCHBOARDCTL:-@OBJTOP@/usr.sbin/switchboardctl/tests/switchboardctl_test_bin}"
	bundle="${PWD}/Log.cap"
	unit="${bundle}/Units/bsdlog.unit"

	test -x "${switchboardctl}" ||
	    atf_skip "source-built switchboardctl is required"
	mkdir -p "${unit}/bin" "${unit}/Config"
	cp "${srcdir}/capbundle/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "${objdir}/bsdlog" "${unit}/bin/Log"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S "${objdir}/bsdlog"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' readelf -S "${objdir}/bsdlog"
	fi
	cp "${srcdir}/capbundle/bsdlog.ucl" "${unit}/Unit.ucl"
	cp "${srcdir}/capbundle/bsdlog.conf" "${unit}/Config/bsdlog.conf"
	chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" "${unit}/bin" \
	    "${unit}/bin/Log" "${unit}/Config"
	chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl" \
	    "${unit}/Config/bsdlog.conf"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${switchboardctl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/Log.cap" 2>/dev/null || true
	rm -rf "${PWD}/Log.cap"
}

atf_test_case security_contract
security_contract_head()
{
	atf_set "descr" "bsdlog is sandboxed, audited, traced, and sink-limited"
}

atf_test_case observability_contract
observability_contract_head()
{
	atf_set "descr" "bsdlog exposes lifecycle, batching, wake, flush, and loss probes"
}

atf_test_case bounded_pool_contract
bounded_pool_contract_head()
{
	atf_set "descr" \
	    "bsdlog uses fixed configurable shards and no per-client worker fork"
}

atf_test_case live_media_storage_fallback_contract
live_media_storage_fallback_contract_head()
{
	atf_set "descr" "bsdlog falls back to its private runtime store when persistent ZFS is unavailable"
}
live_media_storage_fallback_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/BSDLog/logcmp.c"
	manual="@SRCTOP@/usr.sbin/BSDLog/bsdlog.8"

	atf_check -s exit:0 -o ignore grep \
	    'service_storage_open(context, "state"' "$source"
	atf_check -s exit:0 -o ignore grep \
	    'service_capability_open(context, "container", "directory"' "$source"
	atf_check -s exit:0 -o ignore grep 'ephemeral runtime store' "$source"
	atf_check -s exit:0 -o ignore grep 'switchboard runtime container' "$manual"
}
bounded_pool_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/BSDLog/logcmp.c"
	config="@SRCTOP@/usr.sbin/BSDLog/capbundle/bsdlog.conf"
	for token in pool_worker dispatch_to_pool logcmp_storage_attach_pool \
	    logcmp_session_drain_budget SERVICE_HARDEN_XFER_ONCE; do
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
	provider="@SRCTOP@/usr.sbin/BSDLog/bsdlog_provider.d"
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
	atf_check -s exit:0 -o ignore grep BSDLOG_PROBE_BATCH \
	    "@SRCTOP@/usr.sbin/BSDLog/logcmp.c"
	atf_check -s exit:0 -o ignore grep BSDLOG_PROBE_SESSION_END \
	    "@SRCTOP@/usr.sbin/BSDLog/logcmp.c"
	atf_check -s exit:0 -o ignore grep BSDLOG_PROBE_QUERY \
	    "@SRCTOP@/usr.sbin/BSDLog/logcmp.c"
	atf_check -s exit:0 -o ignore grep LOGCMP_PROBE_ENQUEUE \
	    "@SRCTOP@/lib/liblogcmp/logcmp.c"
}
security_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/BSDLog/logcmp.c"

	for token in SERVICE_PROTECT_NOFORK SERVICE_PROTECT_NOSOCK \
	    CAP_XFER_NONE CAP_CLOFORK_ONCE CAP_CLOEXEC_LOCKED \
	    service_worker_enter_capability_mode \
	    service_provider_enter_capability_mode auditcmp_client_prepare \
	    auditcmp_client_adopt auditcmp_submit
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	atf_check -s exit:1 -o empty -e empty grep 'system.syslog' "${source}"
	atf_check -s exit:1 -o empty -e empty grep 'audit_submit(' "${source}"
	atf_check -s exit:0 -o match:'probe record__drop' \
	    grep 'probe record__drop' \
	    "@SRCTOP@/usr.sbin/BSDLog/bsdlog_provider.d"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case security_contract
	atf_add_test_case observability_contract
	atf_add_test_case bounded_pool_contract
	atf_add_test_case live_media_storage_fallback_contract
}
