#!/usr/libexec/atf-sh

require_srctree()
{
	test -r "@SRCTOP@/usr.sbin/BSDAuth/authagentd.c" ||
	    atf_skip "source tree (@SRCTOP@) required for contract checks"
}

atf_test_case dtrace_contract
dtrace_contract_head()
{
	atf_set "descr" \
	    "AuthAgent exposes request and elevate outcome/latency probes to bsdinstruments"
}
dtrace_contract_body()
{
	local binary profile provider source

	require_srctree
	provider="@SRCTOP@/usr.sbin/BSDAuth/authagentd_provider.d"
	source="@SRCTOP@/usr.sbin/BSDAuth/authagentd.c"
	profile="@SRCTOP@/cddl/usr.sbin/bsdinstruments/profiles/capability-services.d"
	for probe in request__start request__done elevate__start \
	    elevate__done; do
		atf_check -s exit:0 -o ignore grep -F "probe ${probe}" "${provider}"
	done
	for macro in AUTHAGENT_PROBE_REQUEST_START \
	    AUTHAGENT_PROBE_REQUEST_DONE AUTHAGENT_PROBE_ELEVATE_START \
	    AUTHAGENT_PROBE_ELEVATE_DONE; do
		atf_check -s exit:0 -o ignore grep -F "${macro}" "${source}"
	done
	for clause in 'authagent*:::request-start' \
	    'authagent*:::request-done' authagent_latency_ns; do
		atf_check -s exit:0 -o ignore grep -F "${clause}" "${profile}"
	done
	if [ "@MK_DTRACE@" = "yes" ]; then
		binary="@OBJTOP@/usr.sbin/BSDAuth/authagentd"
		test -x "${binary}" ||
		    atf_fail "missing AuthAgent binary: ${binary}"
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S "${binary}"
	fi
}

# The declaration of one probe in a provider .d, joined onto a single line
# (declarations wrap), so its arity can be pinned by counting commas.
probe_decl()
{
	# $1 = provider file, $2 = probe name (with the double underscore)
	awk -v probe="probe $2(" '
		index($0, probe) { collecting = 1 }
		collecting { printf "%s ", $0 }
		collecting && /;/ { exit }
	' "$1"
}

atf_test_case anoint_probe_contract
anoint_probe_contract_head()
{
	atf_set "descr" \
	    "The anointment sweep probes (elevate-done stage arg, ratelimit-block, policy-resolve) are declared, wired and profiled"
}
anoint_probe_contract_body()
{
	local decl header nargs profile provider source

	require_srctree
	provider="@SRCTOP@/usr.sbin/BSDAuth/authagentd_provider.d"
	header="@SRCTOP@/usr.sbin/BSDAuth/authagentd_probes.h"
	source="@SRCTOP@/usr.sbin/BSDAuth/authagentd.c"
	profile="@SRCTOP@/cddl/usr.sbin/bsdinstruments/profiles/capability-services.d"

	# Declared in the provider.
	for probe in elevate__done ratelimit__block policy__resolve; do
		atf_check -s exit:0 -o ignore grep -F "probe ${probe}(" \
		    "${provider}"
	done

	# elevate-done carries SIX arguments: client, uid, name, status,
	# transport_error, stage.  Five commas in the declaration.
	decl=$(probe_decl "${provider}" elevate__done)
	test -n "${decl}" || atf_fail "elevate__done declaration not found"
	nargs=$(( $(printf '%s' "${decl}" | tr -cd ',' | wc -c) + 1 ))
	test "${nargs}" -eq 6 ||
	    atf_fail "elevate__done declares ${nargs} args, expected 6: ${decl}"
	atf_check -s exit:0 -o ignore \
	    grep -E 'const char \*stage\)' "${provider}"
	# ratelimit-block(uid, failures); policy-resolve(uid, count, all,
	# admin_rights, from_default_rule).
	decl=$(probe_decl "${provider}" ratelimit__block)
	nargs=$(( $(printf '%s' "${decl}" | tr -cd ',' | wc -c) + 1 ))
	test "${nargs}" -eq 2 ||
	    atf_fail "ratelimit__block declares ${nargs} args, expected 2"
	decl=$(probe_decl "${provider}" policy__resolve)
	nargs=$(( $(printf '%s' "${decl}" | tr -cd ',' | wc -c) + 1 ))
	test "${nargs}" -eq 5 ||
	    atf_fail "policy__resolve declares ${nargs} args, expected 5"

	# The macro header: both the DTrace and the no-op arm take the same
	# argument list, and the elevate-done list ends in `stage`.
	atf_check -s exit:0 -o ignore grep -F \
	    'AUTHAGENT_PROBE_ELEVATE_DONE(client, uid, name, status, error, stage)' \
	    "${header}"
	atf_check -o inline:'2\n' sh -c \
	    "grep -c 'AUTHAGENT_PROBE_ELEVATE_DONE(client, uid, name, status, error, stage)' '${header}'"
	atf_check -o inline:'2\n' sh -c \
	    "grep -c 'AUTHAGENT_PROBE_RATELIMIT_BLOCK(uid, failures)' '${header}'"
	atf_check -o inline:'2\n' sh -c \
	    "grep -c 'AUTHAGENT_PROBE_POLICY_RESOLVE(uid, count, all, admin_rights,' '${header}'"
	# ...and the no-op arm consumes every argument (an unused-variable
	# build break with DTrace off is what this guards).
	atf_check -s exit:0 -o ignore grep -F '(void)(stage);' "${header}"
	atf_check -s exit:0 -o ignore grep -F '(void)(failures);' "${header}"
	atf_check -s exit:0 -o ignore grep -F '(void)(from_default_rule);' \
	    "${header}"

	# Fired from the daemon, at the documented sites.
	atf_check -s exit:0 -o ignore grep -F \
	    'AUTHAGENT_PROBE_ELEVATE_DONE(c->client_label, t.uid, t.name,' \
	    "${source}"
	atf_check -s exit:0 -o ignore grep -F \
	    'reply.status, send_error, t.stage);' "${source}"
	atf_check -s exit:0 -o ignore grep -F \
	    'AUTHAGENT_PROBE_RATELIMIT_BLOCK(uid,' "${source}"
	atf_check -s exit:0 -o ignore grep -F \
	    'AUTHAGENT_PROBE_POLICY_RESOLVE(uid, grant->nanointments,' \
	    "${source}"
	# Every documented stage string exists in the source.
	for stage in caller shape policy ratelimit password mint ok; do
		atf_check -s exit:0 -o ignore grep -F \
		    "stage = \"${stage}\";" "${source}"
	done

	# The bsdinstruments profile consumes them, and reads the stage from
	# the sixth argument (arg5) of elevate-done.
	for clause in 'authagent*:::elevate-start' \
	    'authagent*:::elevate-done' 'authagent*:::ratelimit-block' \
	    'authagent*:::policy-resolve' elevate_latency_ns \
	    elevate_outcomes elevate_ratelimited policy_grants; do
		atf_check -s exit:0 -o ignore grep -F "${clause}" "${profile}"
	done
	atf_check -s exit:0 -o ignore grep -F 'copyinstr(arg5)' "${profile}"
	# The profile's elevate-done clauses must not read past arg5.
	atf_check -s exit:1 -o empty grep -E 'arg[6-9]' "${profile}"
}

atf_test_case audit_event_contract
audit_event_contract_head()
{
	atf_set "descr" \
	    "AUE_AUTHAGENT_ELEVATE (43335) and AUE_AUTHAGENT_MINT (43336) are registered, mapped by the broker and emitted by the agent"
}
audit_event_contract_body()
{
	local broker events kevents makefile source testh

	require_srctree
	kevents="@SRCTOP@/sys/bsm/audit_kevents.h"
	events="@SRCTOP@/contrib/openbsm/etc/audit_event"
	broker="@SRCTOP@/usr.sbin/BSDAudit/auditcmp_policy.c"
	source="@SRCTOP@/usr.sbin/BSDAuth/authagentd.c"
	testh="@SRCTOP@/usr.sbin/BSDAuth/authagentd_test.h"
	makefile="@SRCTOP@/usr.sbin/BSDAuth/Makefile"

	# Kernel event numbers, exactly once each, with the documented names.
	atf_check -s exit:0 -o ignore grep -E \
	    '^#define[[:space:]]+AUE_AUTHAGENT_ELEVATE[[:space:]]+43335([[:space:]]|$)' \
	    "${kevents}"
	atf_check -s exit:0 -o ignore grep -E \
	    '^#define[[:space:]]+AUE_AUTHAGENT_MINT[[:space:]]+43336([[:space:]]|$)' \
	    "${kevents}"
	atf_check -o inline:'1\n' sh -c \
	    "grep -cE '[[:space:]]43335([[:space:]]|$)' '${kevents}'"
	atf_check -o inline:'1\n' sh -c \
	    "grep -cE '[[:space:]]43336([[:space:]]|$)' '${kevents}'"

	# The event database names them the same and once each.
	atf_check -s exit:0 -o ignore grep -E \
	    '^43335:AUE_AUTHAGENT_ELEVATE:[^:]+:[a-z,]+$' "${events}"
	atf_check -s exit:0 -o ignore grep -E \
	    '^43336:AUE_AUTHAGENT_MINT:[^:]+:[a-z,]+$' "${events}"
	atf_check -o inline:'1\n' sh -c "grep -c '^43335:' '${events}'"
	atf_check -o inline:'1\n' sh -c "grep -c '^43336:' '${events}'"

	# The broker maps the agent's operation prefixes onto them.
	atf_check -s exit:0 -o ignore grep -F \
	    '{ "system.Auth", "elevate", AUE_AUTHAGENT_ELEVATE }' \
	    "${broker}"
	atf_check -s exit:0 -o ignore grep -F \
	    '{ "system.Auth", "mint", AUE_AUTHAGENT_MINT }' "${broker}"
	atf_check -s exit:0 -o ignore grep -F auditcmp_policy_operation_event \
	    "@SRCTOP@/usr.sbin/BSDAudit/auditcmp.c"

	# The agent submits through system.Audit with the documented operation
	# shapes, after the reply, and links the client library.
	atf_check -s exit:0 -o ignore grep -F 'auditcmp_submit(g_audit,' \
	    "${source}"
	atf_check -s exit:0 -o ignore grep -F '"elevate/%s/%s"' "${source}"
	atf_check -s exit:0 -o ignore grep -F '"elevate/%s"' "${source}"
	atf_check -s exit:0 -o ignore grep -F '"mint/%s/n%u%s%s%s"' "${source}"
	atf_check -s exit:0 -o ignore grep -F '"mint/%s"' "${source}"
	atf_check -s exit:0 -o ignore grep -F '"%.*s/uid%u"' "${source}"
	atf_check -s exit:0 -o ignore grep -E \
	    '^LIBADD=.*[[:space:]]auditcmp([[:space:]]|$)' "${makefile}"
	# Submission FOLLOWS the reply: the agent is on every login's critical
	# path, so a slow broker may delay the next request but never the
	# channel of the one it describes.  Both audit calls appear in the
	# source after channel_send_reply() within handle_request().
	atf_check -s exit:0 -o ignore sh -c \
	    "awk '/^handle_request\(/,/^}/' '${source}' |
	     awk '/agent_audit_elevate\(c, &t, reply.status\)/ { a = NR }
	          /agent_audit_mint\(c, &t, reply.status\)/ { m = NR }
	          /channel_send_reply\(request/ { r = NR }
	          END { exit !(a && m && r && a > r && m > r) }'"
	# And the session is opened lazily from the request path, never at
	# start-up: no pre-capability-mode prepare/adopt, so checking in never
	# waits for system.Audit to come up.
	atf_check -s exit:1 -o inline:'0\n' sh -c \
	    "grep -c 'auditcmp_client_prepare\|auditcmp_client_adopt' '${source}'"
	atf_check -s exit:0 -o ignore grep -F 'auditcmp_client_open(&g_audit)' \
	    "${source}"
	# The check-in is logged so a boot race is diagnosable from syslog.
	atf_check -s exit:0 -o ignore grep -F '"ready (elevation %s)"' "${source}"
	# The test seam that lets the C tests capture the records.
	atf_check -s exit:0 -o ignore grep -F \
	    'void	authagentd_test_set_audit_hook(authagentd_test_audit_fn fn);' \
	    "${testh}"
}

atf_init_test_cases()
{
	atf_add_test_case dtrace_contract
	atf_add_test_case anoint_probe_contract
	atf_add_test_case audit_event_contract
}
