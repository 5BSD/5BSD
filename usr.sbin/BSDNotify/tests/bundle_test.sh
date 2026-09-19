#!/usr/libexec/atf-sh

# These cases assert source- and object-tree contracts (grep the daemon
# sources, syscall tables and DTrace providers; inspect the built binary).
# Those trees are absent on an installed system, so skip cleanly there rather
# than failing on missing files.
require_srctree()
{
	test -r "@SRCTOP@/usr.sbin/BSDNotify/bsdnotify.c" ||
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
	switchboardctl="${SWITCHBOARDCTL:-@OBJTOP@/usr.sbin/switchboardctl/tests/switchboardctl_test_bin}"
	bundle="${PWD}/Notify.cap"
	unit="${bundle}/Units/bsdnotify.unit"

	test -x "${switchboardctl}" || atf_skip "test switchboardctl is required"
	mkdir -p "${unit}/bin"
	cp "${srcdir}/capbundle/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "${objdir}/bsdnotify" "${unit}/bin/Notify"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S "${objdir}/bsdnotify"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' readelf -S "${objdir}/bsdnotify"
	fi
	cp "${srcdir}/capbundle/bsdnotify.ucl" "${unit}/Unit.ucl"
	chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" "${unit}/bin" \
	    "${unit}/bin/Notify"
	chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl"
	atf_check -s exit:0 -o match:'bsdnotify.conf' \
	    grep bsdnotify.conf "${srcdir}/Makefile"
	# ipc-anointments v1: both tiers are declared, the gated one with its
	# requires set, and the open one stays resolvable by user sessions.
	unitucl="${srcdir}/capbundle/bsdnotify.ucl"
	atf_check -s exit:0 -o match:'"system.Notify",' grep -F '"system.Notify",' "${unitucl}"
	atf_check -s exit:0 -o match:'name = "system.Notify.System"' \
	    grep -F 'name = "system.Notify.System"' "${unitucl}"
	atf_check -s exit:0 -o match:'requires = \["system.notify.system"\]' \
	    grep -F 'requires = ["system.notify.system"]' "${unitucl}"
	atf_check -s exit:0 -o match:'resolvable_by = \["user"\]' \
	    grep -F 'resolvable_by = ["user"]' "${unitucl}"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${switchboardctl}" verify "${bundle}"
}

atf_test_case shipped_policy
shipped_policy_head()
{
	atf_set "descr" "The shipped bsdnotify.conf states both tier defaults and parses"
}
shipped_policy_body()
{
	require_srctree
	conf="@SRCTOP@/usr.sbin/BSDNotify/capbundle/bsdnotify.conf"
	notifyctl="@OBJTOP@/usr.sbin/notifyctl/tests/notifyctl_test_bin"
	atf_check -s exit:0 -o ignore grep -E '^default \{' "${conf}"
	atf_check -s exit:0 -o ignore grep -E '^system_default \{' "${conf}"
	atf_check -s exit:0 -o ignore grep -E '^clients \{' "${conf}"
	atf_check -s exit:0 -o ignore grep -F 'publish = [ "user.*" ]' "${conf}"
	atf_check -s exit:0 -o ignore grep -F 'timers = true' "${conf}"
	test -x "${notifyctl}" || atf_skip "test notifyctl is required"
	cp "${conf}" bsdnotify.conf
	chmod 0644 bsdnotify.conf
	atf_check -s exit:0 \
	    -o match:'valid \(0 clients, default explicit, system_default explicit\)' \
	    "${notifyctl}" configtest bsdnotify.conf
}

atf_test_case tier_contract
tier_contract_head()
{
	atf_set "descr" "Beacon exposes both tiers and admits by listener, not by client"
}
tier_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/BSDNotify/bsdnotify.c"
	header="@SRCTOP@/lib/libnotify/notify_protocol.h"
	atf_check -s exit:0 -o ignore grep -F '"system.Notify.System"' "${header}"
	atf_check -s exit:0 -o ignore grep -F 'NOTIFY_SYSTEM_INTERFACE' "${source}"
	atf_check -s exit:0 -o ignore grep -F 'notify_policy_db_select' "${source}"
	atf_check -s exit:0 -o ignore grep -F 'accept_kqueue_arm' "${source}"
	atf_check -s exit:0 -o ignore grep -F 'identity.service_name' "${source}"
	# two exposes: one per tier
	atf_check -s exit:0 -o inline:'2\n' \
	    sh -c "grep -c 'service_provider_expose(provider,' '${source}'"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/Notify.cap" 2>/dev/null || true
	rm -rf "${PWD}/Notify.cap"
}

atf_test_case security_contract
security_contract_head()
{
	atf_set "descr" "Beacon confines its bounded event-driven router"
}
security_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/BSDNotify/bsdnotify.c"
	for token in service_worker_enter_capability_mode \
	    service_provider_enter_capability_mode SERVICE_PROTECT_NOFDRECV \
	    SERVICE_HARDEN_XFER_ONCE \
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
	daemon_provider="@SRCTOP@/usr.sbin/BSDNotify/bsdnotify_provider.d"
	daemon_source="@SRCTOP@/usr.sbin/BSDNotify/bsdnotify.c"
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

	# The anointment sweep: session-admit(label, tier, rights, client_abi)
	# from the accept loop and tier-policy(label, tier, source) from the
	# router, declared, stubbed for the no-DTrace build, fired, profiled.
	header="@SRCTOP@/usr.sbin/BSDNotify/bsdnotify_probes.h"
	profile="@SRCTOP@/cddl/usr.sbin/bsdinstruments/profiles/capability-services.d"
	atf_check -s exit:0 -o ignore grep -F \
	    'probe session__admit(const char *, uint32_t, uint64_t, uint8_t);' \
	    "$daemon_provider"
	atf_check -s exit:0 -o ignore grep -F \
	    'probe tier__policy(const char *, uint32_t, const char *);' \
	    "$daemon_provider"
	# Both arms of the macro header (DTrace on and off).
	atf_check -o inline:'2\n' sh -c \
	    "grep -c 'BSDNOTIFY_PROBE_SESSION_ADMIT(a, b, c, d)' '$header'"
	atf_check -o inline:'2\n' sh -c \
	    "grep -c 'BSDNOTIFY_PROBE_TIER_POLICY(a, b, c)' '$header'"
	atf_check -s exit:0 -o ignore grep -F 'BSDNOTIFY_PROBE_SESSION_ADMIT(' \
	    "$daemon_source"
	atf_check -s exit:0 -o ignore grep -F 'BSDNOTIFY_PROBE_TIER_POLICY(' \
	    "$daemon_source"
	# tier-policy reads its source from the policy engine's new entry
	# point, and the plain select() is a wrapper over it.
	atf_check -s exit:0 -o ignore grep -F 'notify_policy_db_select_source(' \
	    "@SRCTOP@/usr.sbin/BSDNotify/policy.h"
	atf_check -o inline:'2\n' sh -c \
	    "grep -c '^notify_policy_db_select\(_source\)\?(' \
	    '@SRCTOP@/usr.sbin/BSDNotify/policy.c'"
	atf_check -s exit:0 -o ignore grep -F \
	    'session->policy = notify_policy_db_select_source(' "$daemon_source"
	for clause in 'bsdnotify*:::session-admit' 'bsdnotify*:::tier-policy' \
	    notify_admit notify_tier; do
		atf_check -s exit:0 -o ignore grep -F "$clause" "$profile"
	done
	# The profile keys admit on (label, tier, abi) = (arg0, arg1, arg3)
	# and tier-policy on (tier, source) = (arg1, arg2).
	atf_check -s exit:0 -o ignore grep -F \
	    '@notify_admit[copyinstr(arg0), arg1, arg3]' "$profile"
	atf_check -s exit:0 -o ignore grep -F \
	    '@notify_tier[arg1, copyinstr(arg2)]' "$profile"
}

# The tier-mismatch refusal (a connection resolved for one listener but
# accepted on the other) is audited as AUE_BSDNOTIFY_POLICY with operation
# admit-tier-mismatch-{open,system}, result EPROTO, through an accept-side
# system.Audit session.  It lives in main()'s two-listener accept loop, which
# no unit test reaches (the loop and router_add_session() are compiled out of
# the NOTIFY_ROUTER_TEST build), and the mismatch itself needs switchboard to
# stamp a resolved name that disagrees with the listener -- so the live path
# is VM-ONLY.  Its shape and its ordering are pinned here instead.
atf_test_case tier_mismatch_audit_contract
tier_mismatch_audit_contract_head()
{
	atf_set "descr" \
	    "The accept loop audits a tier mismatch once, as EPROTO, before closing (live path VM-only)"
}
tier_mismatch_audit_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/BSDNotify/bsdnotify.c"

	atf_check -s exit:0 -o ignore grep -F '"admit-tier-mismatch-system"' \
	    "$source"
	atf_check -s exit:0 -o ignore grep -F '"admit-tier-mismatch-open"' \
	    "$source"
	atf_check -s exit:0 -o ignore grep -F \
	    'audit_policy(accept_audit, identity.client_label,' "$source"
	# The operation is chosen by the tier the connection ARRIVED on.
	atf_check -s exit:0 -o ignore grep -F \
	    'tier == NOTIFY_TIER_SYSTEM ?' "$source"
	# Within the accept loop: the refusal is logged, audited EPROTO, then
	# the descriptor is closed and the loop continues; the session-admit
	# probe fires only past that point.  One refusal, one record.
	atf_check -s exit:0 -o ignore sh -c \
	    "awk '/^main\(void\)/,/^}/' '$source' |
	     awk '/but accepted on %s listener/ { l = NR }
	          /audit_policy\(accept_audit, identity.client_label,/ { a = NR }
	          /admit-tier-mismatch-open\", EPROTO\);/ { e = NR }
	          a && !c && /close\(fd\);/ { c = NR }
	          c && !k && /continue;/ { k = NR }
	          /BSDNOTIFY_PROBE_SESSION_ADMIT\(/ { p = NR }
	          END { exit !(l && a && e && c && k && p &&
	              l < a && a < e && e < c && c < k && k < p) }'"
	# Fail soft: the accept-side session is optional (NULL is a no-op),
	# and it is opened AFTER the router fork so the router never inherits
	# it.
	atf_check -s exit:0 -o ignore grep -F 'if (audit == NULL)' "$source"
	atf_check -s exit:0 -o ignore grep -F \
	    'auditcmp_client_adopt(accept_audit_fd, &accept_audit)' "$source"
	atf_check -s exit:0 -o ignore sh -c \
	    "awk '/^main\(void\)/,/^}/' '$source' |
	     awk '/close\(router_pair\[1\]\);/ { f = NR }
	          /auditcmp_client_prepare\(&accept_audit_fd\)/ { o = NR }
	          END { exit !(f && o && f < o) }'"
	# The event class the broker files it under.
	atf_check -s exit:0 -o ignore grep -F \
	    '{ "system.Notify", NULL, AUE_BSDNOTIFY_POLICY }' \
	    "@SRCTOP@/usr.sbin/BSDAudit/auditcmp_policy.c"
}
router_async_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/BSDNotify/bsdnotify.c"
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
	source="@SRCTOP@/usr.sbin/BSDNotify/bsdnotify.c"
	atf_check -s exit:0 -o match:'channel_send_event' \
	    grep channel_send_event "${source}"
	atf_check -s exit:0 -o match:'service_session_receive_event' \
	    grep service_session_receive_event "${source}"
	atf_check -s exit:0 -o match:'pdwait' grep pdwait "${source}"
	atf_check -s exit:0 -o match:'restart = "on-failure"' \
	    grep restart \
	    "@SRCTOP@/usr.sbin/BSDNotify/capbundle/bsdnotify.ucl"
}

atf_test_case worker_channel_contract
worker_channel_contract_head()
{
	atf_set "descr" \
	    "Beacon uses an unnamed capability channel and per-hop session attenuation (SERVICE_HARDEN_XFER_ONCE before the worker forward) without raw SCM_RIGHTS"
}
worker_channel_contract_body()
{
	require_srctree
	source="@SRCTOP@/usr.sbin/BSDNotify/bsdnotify.c"
	atf_check -s exit:0 -o match:'service_provider_worker_channel' \
	    grep service_provider_worker_channel "${source}"
	# The router forward is attenuated per hop: bsdnotify tightens the
	# session with SERVICE_HARDEN_XFER_ONCE before handing it on, so the
	# router lands at CAP_XFER_NONE without a kernel-baked multi-hop budget.
	atf_check -s exit:0 -o match:'SERVICE_HARDEN_XFER_ONCE' \
	    grep SERVICE_HARDEN_XFER_ONCE "${source}"
	atf_check -s exit:0 -o match:'SERVICE_PROTECT_NOFDRECV' \
	    grep SERVICE_PROTECT_NOFDRECV "${source}"
	atf_check -s exit:0 -o match:'router_admission_classify' \
	    grep router_admission_classify "${source}"
	atf_check -s exit:0 -o match:'SWITCHBOARD_PROBE_WORKER_CHANNEL' \
	    grep SWITCHBOARD_PROBE_WORKER_CHANNEL \
	    "@SRCTOP@/usr.sbin/switchboard/svc_proto.c"
	atf_check -s exit:0 -o match:'AUE_SWITCHBOARD_COMPONENT' \
	    grep AUE_SWITCHBOARD_COMPONENT \
	    "@SRCTOP@/usr.sbin/switchboard/svc_proto.c"
	atf_check -s exit:1 -o empty -e empty \
	    grep -E 'socketpair|SCM_RIGHTS|internal_(send|receive)_fd' "${source}"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case shipped_policy
	atf_add_test_case tier_contract
	atf_add_test_case security_contract
	atf_add_test_case router_lifecycle_contract
	atf_add_test_case router_async_contract
	atf_add_test_case worker_channel_contract
	atf_add_test_case observability_contract
	atf_add_test_case tier_mismatch_audit_contract
}
