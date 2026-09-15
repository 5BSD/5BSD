#!/usr/libexec/atf-sh
#
# Observability contract for IPC anointments (docs/ipc-anointments-design.md):
# the switchboard anoint-* / mint-anoint probes, the shipped
# share/dtrace/switchboard-anoint script, and the bsdinstruments profile
# clauses that consume them.  Source-tree greps, so these skip on an
# installed system without the tree.

require_srctree()
{
	test -r "@SRCTOP@/usr.sbin/switchboard/anoint.c" ||
	    atf_skip "source tree (@SRCTOP@) required for contract checks"
}

# The declaration of one probe in a provider .d joined onto one line
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

check_arity()
{
	# $1 = provider file, $2 = probe, $3 = expected argument count
	local decl nargs

	decl=$(probe_decl "$1" "$2")
	test -n "${decl}" || atf_fail "$2 is not declared in $1"
	nargs=$(( $(printf '%s' "${decl}" | tr -cd ',' | wc -c) + 1 ))
	test "${nargs}" -eq "$3" ||
	    atf_fail "$2 declares ${nargs} args, expected $3: ${decl}"
}

atf_test_case probe_contract
probe_contract_head()
{
	atf_set "descr" \
	    "anoint-allow/-set/-visibility and mint-anoint are declared, stubbed, fired at their documented sites, and profiled"
}
probe_contract_body()
{
	local header profile provider src

	require_srctree
	src="@SRCTOP@/usr.sbin/switchboard"
	provider="${src}/switchboard_provider.d"
	header="${src}/switchboard_probes.h"
	profile="@SRCTOP@/cddl/usr.sbin/bsdinstruments/profiles/capability-services.d"

	# Declared, with the documented arity.
	check_arity "${provider}" anoint__deny 3
	check_arity "${provider}" anoint__allow 3
	check_arity "${provider}" anoint__set 4
	check_arity "${provider}" mint__anoint 5
	check_arity "${provider}" anoint__visibility 2
	atf_check -s exit:0 -o ignore grep -F \
	    'probe anoint__allow(const char *name, const char *requester,' \
	    "${provider}"
	atf_check -s exit:0 -o ignore grep -F \
	    'probe anoint__set(const char *label, unsigned int count, int all,' \
	    "${provider}"
	atf_check -s exit:0 -o ignore grep -F \
	    'probe mint__anoint(uid_t uid, unsigned int count, int all,' \
	    "${provider}"
	atf_check -s exit:0 -o ignore grep -F \
	    'probe anoint__visibility(const char *name, uid_t uid);' \
	    "${provider}"

	# The macro header maps each onto DTRACE_PROBEn, and the no-DTrace
	# arm defines every arity used (5 for mint-anoint).
	for macro in 'SWITCHBOARD_PROBE_ANOINT_DENY(name, label, missing)' \
	    'SWITCHBOARD_PROBE_ANOINT_ALLOW(name, requester, nrequires)' \
	    'SWITCHBOARD_PROBE_ANOINT_SET(label, count, all, admin_rights)' \
	    'SWITCHBOARD_PROBE_MINT_ANOINT(uid, count, all, admin_rights, status)' \
	    'SWITCHBOARD_PROBE_ANOINT_VISIBILITY(name, uid)'; do
		atf_check -s exit:0 -o ignore grep -F "#define	${macro}" \
		    "${header}"
	done
	atf_check -s exit:0 -o ignore grep -F \
	    'DTRACE_PROBE3(switchboard, anoint__allow, name, requester, nrequires)' \
	    "${header}"
	atf_check -s exit:0 -o ignore grep -F \
	    'DTRACE_PROBE4(switchboard, anoint__set, label, count, all, admin_rights)' \
	    "${header}"
	atf_check -s exit:0 -o ignore grep -F \
	    'DTRACE_PROBE5(switchboard, mint__anoint, uid, count, all, admin_rights,' \
	    "${header}"
	atf_check -s exit:0 -o ignore grep -F \
	    'DTRACE_PROBE2(switchboard, anoint__visibility, name, uid)' \
	    "${header}"
	atf_check -s exit:0 -o ignore grep -E \
	    '^#define[[:space:]]+DTRACE_PROBE5\(provider, name, arg1, arg2, arg3, arg4, arg5\)' \
	    "${header}"

	# Fired at the documented sites, and only there.
	#  deny: the single refusal function in anoint.c.
	atf_check -o inline:'1\n' sh -c \
	    "grep -c 'SWITCHBOARD_PROBE_ANOINT_DENY(' '${src}/anoint.c'"
	#  allow: the resolve (naming_lookup, gated names only) and the
	#  self-served control names; never the on-demand pre-check.
	atf_check -o inline:'2\n' sh -c \
	    "grep -c 'SWITCHBOARD_PROBE_ANOINT_ALLOW(' '${src}/naming.c'"
	atf_check -s exit:0 -o ignore grep -B1 -F \
	    'SWITCHBOARD_PROBE_ANOINT_ALLOW(name, (requester != NULL ?' \
	    "${src}/naming.c"
	atf_check -s exit:0 -o ignore grep -F 'if (nrequires > 0)' \
	    "${src}/naming.c"
	atf_check -s exit:0 -o ignore grep -F \
	    'SWITCHBOARD_PROBE_ANOINT_ALLOW(name, NAMING_SESSION_LABEL, 1U);' \
	    "${src}/naming.c"
	atf_check -s exit:1 -o empty grep -F 'SWITCHBOARD_PROBE_ANOINT_ALLOW' \
	    "${src}/anoint.c"
	atf_check -s exit:1 -o empty grep -F 'SWITCHBOARD_PROBE_ANOINT_ALLOW' \
	    "${src}/on_demand.c"
	#  set: a unit at exec (execute.c) and a session channel at mint
	#  (domain.c, under the session label).
	atf_check -s exit:0 -o ignore grep -F \
	    'SWITCHBOARD_PROBE_ANOINT_SET(m->label, svc->domain.anoint.n,' \
	    "${src}/execute.c"
	atf_check -s exit:0 -o ignore grep -F \
	    'SWITCHBOARD_PROBE_ANOINT_SET(SVC_SESSION_LABEL,' "${src}/domain.c"
	#  mint-anoint: next to mint-domain in the SVC_OP_MINT_DOMAIN handler.
	atf_check -s exit:0 -o ignore sh -c \
	    "awk '/^handle_mint_domain\(/,/^}/' '${src}/svc_proto.c' |
	     awk '/SWITCHBOARD_PROBE_MINT_DOMAIN\(/ { d = NR }
	          /SWITCHBOARD_PROBE_MINT_ANOINT\(/ { a = NR }
	          END { exit !(d && a && d < a) }'"
	#  visibility: the USER-kind gated-name rule in svc_domain_resolves.
	atf_check -s exit:0 -o ignore sh -c \
	    "awk '/^svc_domain_resolves\(/,/^}/' '${src}/domain.c' |
	     grep -F 'SWITCHBOARD_PROBE_ANOINT_VISIBILITY(name, domain->uid);'"

	# The session label is one constant, shared by every site that
	# names a login session as the requester.
	atf_check -s exit:0 -o ignore grep -F \
	    '#define	SVC_SESSION_LABEL		"org.5bsd.user-session"' \
	    "${src}/switchboard.h"
	atf_check -s exit:0 -o ignore grep -F \
	    '#define	NAMING_SESSION_LABEL	SVC_SESSION_LABEL' "${src}/naming.c"
	atf_check -s exit:0 -o ignore grep -F \
	    'requester->manifest.label : SVC_SESSION_LABEL,' \
	    "${src}/on_demand.c"

	# The bsdinstruments profile consumes allow, deny and mint-anoint.
	for clause in 'switchboard*:::anoint-allow' \
	    'switchboard*:::anoint-deny' 'switchboard*:::mint-anoint' \
	    anoint_allow anoint_deny anoint_mint; do
		atf_check -s exit:0 -o ignore grep -F "${clause}" "${profile}"
	done
	atf_check -s exit:0 -o ignore grep -F \
	    '@anoint_mint[arg0, arg1, arg2, arg3, arg4]' "${profile}"
	atf_check -s exit:0 -o ignore grep -F \
	    '@anoint_deny[copyinstr(arg0), copyinstr(arg1), copyinstr(arg2)]' \
	    "${profile}"

	# One refusal, one AUE_SWITCHBOARD_ANOINT record: the invariant is
	# stated at the refusal function, and the C anoint_test drives it.
	atf_check -s exit:0 -o ignore grep -F 'One refusal, one record.' \
	    "${src}/anoint.c"
	atf_check -s exit:0 -o ignore grep -F \
	    'switchboard_audit(AUE_SWITCHBOARD_ANOINT, uid, EACCES,' \
	    "${src}/anoint.c"
}

atf_test_case anoint_script_shipped
anoint_script_shipped_head()
{
	atf_set "descr" \
	    "share/dtrace/switchboard-anoint is installed and traces every anoint probe"
}
anoint_script_shipped_body()
{
	local makefile script

	require_srctree
	script="@SRCTOP@/share/dtrace/switchboard-anoint"
	makefile="@SRCTOP@/share/dtrace/Makefile"

	test -r "${script}" || atf_fail "missing ${script}"
	atf_check -s exit:0 -o ignore grep -E \
	    '^[[:space:]]+switchboard-anoint[[:space:]]+\\$' "${makefile}"
	atf_check -s exit:0 -o inline:'#!/usr/sbin/dtrace -s\n' head -n 1 \
	    "${script}"
	for probe in anoint-allow anoint-deny anoint-set mint-anoint \
	    anoint-visibility; do
		atf_check -s exit:0 -o ignore grep -F \
		    "switchboard*:::${probe}" "${script}"
	done
	atf_check -s exit:0 -o ignore grep -F 'dtrace:::BEGIN' "${script}"
	atf_check -s exit:0 -o ignore grep -F 'dtrace:::END' "${script}"
	# The deny clause prints the missing names and the mint clause the
	# status (arg4), matching the provider's argument order.
	atf_check -s exit:0 -o ignore grep -F 'missing=%s' "${script}"
	atf_check -s exit:0 -o ignore grep -F '@mints[arg0, arg4]' "${script}"
	# Every other shipped switchboard script is still listed too (the
	# SCRIPTS list is alphabetical; a drop would be a packaging change).
	for other in switchboard-capabilities switchboard-connections \
	    switchboard-exec-latency; do
		atf_check -s exit:0 -o ignore grep -E \
		    "^[[:space:]]+${other}[[:space:]]+\\\\$" "${makefile}"
	done
}

atf_test_case anoint_script_parses
anoint_script_parses_head()
{
	atf_set "descr" \
	    "dtrace -C -e -s share/dtrace/switchboard-anoint compiles (skips without dtrace)"
	atf_set "timeout" "60"
}
anoint_script_parses_body()
{
	local script

	require_srctree
	script="@SRCTOP@/share/dtrace/switchboard-anoint"
	test -r "${script}" || atf_fail "missing ${script}"
	[ "@MK_DTRACE@" = "yes" ] || atf_skip "built without DTrace"
	command -v dtrace >/dev/null 2>&1 || atf_skip "dtrace(1) not available"
	# -e: compile and exit before enabling anything; -Z is deliberately
	# NOT given, so a clause naming a probe the provider does not define
	# is a compile error here (the switchboard* pattern matches no live
	# process, which -e tolerates).
	if ! dtrace -C -e -s "${script}" >dtrace.out 2>dtrace.err; then
		if grep -qi 'privileges\|permission denied\|/dev/dtrace' \
		    dtrace.err; then
			atf_skip "dtrace needs privileges: $(head -n 1 dtrace.err)"
		fi
		cat dtrace.err >&2
		atf_fail "switchboard-anoint does not compile"
	fi
	# A broken script (a nonexistent action) is rejected the same way,
	# proving the parse above is a real check and not a no-op.
	sed 's/printf(/no_such_action(/' "${script}" >broken.d
	atf_check -s not-exit:0 -o ignore -e ignore \
	    dtrace -C -e -s broken.d
}

atf_init_test_cases()
{
	atf_add_test_case probe_contract
	atf_add_test_case anoint_script_shipped
	atf_add_test_case anoint_script_parses
}
