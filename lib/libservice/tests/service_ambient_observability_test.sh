#!/usr/libexec/atf-sh
#
# Observability contract for the service_ambient DTrace provider
# (lib/libservice/service_ambient_provider.d): the elevate-start/-done
# probes around service_elevate(3).  Source-tree greps, so these skip on an
# installed system without the tree.

require_srctree()
{
	test -r "@SRCTOP@/lib/libservice/service_client.c" ||
	    atf_skip "source tree (@SRCTOP@) required for contract checks"
}

atf_test_case elevate_probe_contract
elevate_probe_contract_head()
{
	atf_set "descr" \
	    "service_elevate(3) fires elevate-start once and elevate-done on every exit, never with the password"
}
elevate_probe_contract_body()
{
	local header profile provider source

	require_srctree
	provider="@SRCTOP@/lib/libservice/service_ambient_provider.d"
	header="@SRCTOP@/lib/libservice/service_ambient_probes.h"
	source="@SRCTOP@/lib/libservice/service_client.c"
	profile="@SRCTOP@/cddl/usr.sbin/bsdinstruments/profiles/capability-services.d"

	# Declared: start(name), done(name, error).
	atf_check -s exit:0 -o ignore grep -F \
	    'probe elevate__start(const char *name);' "${provider}"
	atf_check -s exit:0 -o ignore grep -F \
	    'probe elevate__done(const char *name, int error);' "${provider}"
	# The existing registration probes are untouched.
	for probe in reg__create reg__result; do
		atf_check -s exit:0 -o ignore grep -F "probe ${probe}(" \
		    "${provider}"
	done

	# The macro header: both probes, and a DTRACE_PROBE2 stub for the
	# no-DTrace build (the header previously stubbed only 1 and 4).
	atf_check -s exit:0 -o ignore grep -F \
	    '#define	SERVICE_AMBIENT_PROBE_ELEVATE_START(name)' "${header}"
	atf_check -s exit:0 -o ignore grep -F \
	    '#define	SERVICE_AMBIENT_PROBE_ELEVATE_DONE(name, error)' "${header}"
	atf_check -s exit:0 -o ignore grep -F \
	    'DTRACE_PROBE1(service_ambient, elevate__start, name)' "${header}"
	atf_check -s exit:0 -o ignore grep -F \
	    'DTRACE_PROBE2(service_ambient, elevate__done, name, error)' \
	    "${header}"
	atf_check -s exit:0 -o ignore grep -E \
	    '^#define[[:space:]]+DTRACE_PROBE2\(provider, name, arg1, arg2\)' \
	    "${header}"

	# Wired into service_elevate(): the header is included, the start
	# probe fires exactly once, and every return after it is preceded by
	# a done probe (one done per exit, including success).
	atf_check -s exit:0 -o ignore grep -F \
	    '#include "service_ambient_probes.h"' "${source}"
	atf_check -s exit:0 -o ignore sh -c \
	    "awk '/^service_elevate\(/,/^}/' '${source}' |
	     awk '/SERVICE_AMBIENT_PROBE_ELEVATE_START\(name\);/ { s++; next }
	          s && /return \(/ { r++ }
	          /SERVICE_AMBIENT_PROBE_ELEVATE_DONE\(name, / { d++ }
	          END { printf \"start=%d returns-after-start=%d done=%d\\n\", s, r, d;
	              exit !(s == 1 && r > 0 && r == d) }'"
	# The start probe fires only after argument validation (a NULL name
	# would otherwise be dereferenced by the probe itself): the EINVAL
	# returns come first.
	atf_check -s exit:0 -o ignore sh -c \
	    "awk '/^service_elevate\(/,/^}/' '${source}' |
	     awk '/SERVICE_AMBIENT_PROBE_ELEVATE_START\(name\);/ { s = NR }
	          !s && /errno = EINVAL;/ { v++ }
	          END { exit !(s && v > 0) }'"
	# The success exit reports 0 and the reply status is passed through.
	atf_check -s exit:0 -o ignore grep -F \
	    'SERVICE_AMBIENT_PROBE_ELEVATE_DONE(name, 0);' "${source}"
	atf_check -s exit:0 -o ignore grep -F \
	    'SERVICE_AMBIENT_PROBE_ELEVATE_DONE(name, reply_data.status);' \
	    "${source}"
	# Never the password.
	atf_check -s exit:1 -o empty grep -E \
	    'SERVICE_AMBIENT_PROBE_ELEVATE_(START|DONE)\(.*password' "${source}"
	atf_check -s exit:1 -o empty grep -E 'probe .*password' "${provider}"
	atf_check -s exit:0 -o ignore grep -F 'Never' "${header}"

	# The bsdinstruments profile consumes elevate-done by (execname, errno).
	atf_check -s exit:0 -o ignore grep -F \
	    'service_ambient*:::elevate-done' "${profile}"
	atf_check -s exit:0 -o ignore grep -F \
	    '@elevate_client[execname, arg1]' "${profile}"
}

atf_init_test_cases()
{
	atf_add_test_case elevate_probe_contract
}
