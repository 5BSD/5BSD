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
	atf_set "descr" "Beacon installs as a verified .cap provider"
}
manifest_body()
{
	require_srctree
	srcdir="@SRCTOP@/usr.sbin/bsdnotify"
	objdir="@OBJTOP@/usr.sbin/bsdnotify"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	bundle="${PWD}/BsdNotify.cap"
	unit="${bundle}/Units/bsdnotify.unit"

	test -x "${servicectl}" || atf_skip "test servicectl is required"
	mkdir -p "${unit}/bin"
	cp "${srcdir}/capbundle/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "${objdir}/bsdnotify" "${unit}/bin/bsdnotify"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S "${objdir}/bsdnotify"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' readelf -S "${objdir}/bsdnotify"
	fi
	cp "${srcdir}/capbundle/bsdnotify.ucl" "${unit}/Unit.ucl"
	chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" "${unit}/bin" \
	    "${unit}/bin/bsdnotify"
	chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl"
	atf_check -s exit:0 -o match:'bsdnotify.conf' \
	    grep bsdnotify.conf "${srcdir}/Makefile"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/BsdNotify.cap" 2>/dev/null || true
	rm -rf "${PWD}/BsdNotify.cap"
}

atf_test_case security_contract
security_contract_head()
{
	atf_set "descr" "Beacon confines its bounded event-driven router"
}
security_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/bsdnotify/bsdnotify.c"
	for token in cap_enter SERVICE_PROTECT_NOFDRECV CAP_XFER_ONCE \
	    auditcmp_client_prepare auditcmp_client_adopt auditcmp_submit \
	    service_listener_accept EVFILT_TIMER
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	atf_check -s exit:1 -o empty -e empty grep 'audit_submit(' "${source}"
}

atf_test_case router_lifecycle_contract
router_lifecycle_contract_head()
{
	atf_set "descr" \
	    "Beacon becomes ready only after its router and exits if that router dies"
}

atf_test_case router_async_contract
router_async_contract_head()
{
	atf_set "descr" \
	    "Beacon multiplexes independent channel sessions without per-client forks"
}

atf_test_case observability_contract
observability_contract_head()
{
	atf_set "descr" "Beacon client and daemon probes are declared and fired"
}
observability_contract_body()
{
	require_srctree
	provider="@SRCTOP@/lib/libnotify/notify_provider.d"
	source="@SRCTOP@/lib/libnotify/notify.c"
	daemon_provider="@SRCTOP@/usr.sbin/bsdnotify/bsdnotify_provider.d"
	daemon_source="@SRCTOP@/usr.sbin/bsdnotify/bsdnotify.c"
	for probe in rpc publish next reject reconnect; do
		atf_check -s exit:0 -o ignore grep "probe ${probe}" "$provider"
	done
	for macro in NOTIFY_PROBE_RPC NOTIFY_PROBE_REJECT \
	    NOTIFY_PROBE_RECONNECT; do
		atf_check -s exit:0 -o ignore grep "$macro" "$source"
	done
	for probe in session__start session__end subscribe publish deliver timer \
	    reject; do
		atf_check -s exit:0 -o ignore grep "probe ${probe}" \
		    "$daemon_provider"
	done
	for macro in BSDNOTIFY_PROBE_SESSION_START \
	    BSDNOTIFY_PROBE_SESSION_END BSDNOTIFY_PROBE_SUBSCRIBE \
	    BSDNOTIFY_PROBE_PUBLISH BSDNOTIFY_PROBE_DELIVER \
	    BSDNOTIFY_PROBE_TIMER BSDNOTIFY_PROBE_REJECT; do
		atf_check -s exit:0 -o ignore grep "$macro" "$daemon_source"
	done
	atf_check -s exit:0 -o ignore grep auditcmp_submit "$daemon_source"
}
router_async_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/bsdnotify/bsdnotify.c"
	atf_check -s exit:0 -o match:'ROUTER_MAX_SESSIONS' \
	    grep 'ROUTER_MAX_SESSIONS' "${source}"
	atf_check -s exit:0 -o match:'channel_set_request_handler' \
	    grep 'channel_set_request_handler' "${source}"
	atf_check -s exit:0 -o match:'channel_dispatch' \
	    grep 'channel_dispatch' "${source}"
	atf_check -s exit:0 -o match:'EVFILT_WRITE' \
	    grep 'EVFILT_WRITE' "${source}"
	atf_check -s exit:0 -o match:'router->nsessions' \
	    grep 'router->nsessions' "${source}"
}
router_lifecycle_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/bsdnotify/bsdnotify.c"
	atf_check -s exit:0 -o match:'channel_send_event' \
	    grep channel_send_event "${source}"
	atf_check -s exit:0 -o match:'service_session_receive_event' \
	    grep service_session_receive_event "${source}"
	atf_check -s exit:0 -o match:'pdwait' grep pdwait "${source}"
	atf_check -s exit:0 -o match:'restart = "on-failure"' \
	    grep restart \
	    "@SRCTOP@/usr.sbin/bsdnotify/capbundle/bsdnotify.ucl"
}

atf_test_case worker_channel_contract
worker_channel_contract_head()
{
	atf_set "descr" \
	    "Beacon uses an unnamed capability channel and a two-hop linear session budget without SCM_RIGHTS"
}
worker_channel_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/bsdnotify/bsdnotify.c"
	atf_check -s exit:0 -o match:'service_provider_worker_channel' \
	    grep service_provider_worker_channel "${source}"
	atf_check -s exit:0 -o match:'CAP_XFER_TWICE' \
	    grep CAP_XFER_TWICE "@SRCTOP@/usr.sbin/serviced/naming.c"
	atf_check -s exit:0 -o match:'SERVICE_PROTECT_NOFDRECV' \
	    grep SERVICE_PROTECT_NOFDRECV "${source}"
	atf_check -s exit:0 -o match:'router_admission_classify' \
	    grep router_admission_classify "${source}"
	atf_check -s exit:0 -o match:'SERVICED_PROBE_WORKER_CHANNEL' \
	    grep SERVICED_PROBE_WORKER_CHANNEL \
	    "@SRCTOP@/usr.sbin/serviced/svc_proto.c"
	atf_check -s exit:0 -o match:'AUE_SERVICED_COMPONENT' \
	    grep AUE_SERVICED_COMPONENT \
	    "@SRCTOP@/usr.sbin/serviced/svc_proto.c"
	atf_check -s exit:1 -o empty -e empty \
	    grep -E 'socketpair|SCM_RIGHTS|internal_(send|receive)_fd' "${source}"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case security_contract
	atf_add_test_case router_lifecycle_contract
	atf_add_test_case router_async_contract
	atf_add_test_case worker_channel_contract
	atf_add_test_case observability_contract
}
