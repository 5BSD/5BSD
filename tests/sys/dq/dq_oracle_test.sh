#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# The pass-everything oracle (stage 1c-i): a program attached to a queue
# whose controller answers every RESOLVE with PASS must behave as it does
# unattached.  dqpass (installed beside this test) is that controller.
#
# commands: a fixed list of commands, run unattached and under dqpass;
# their output and exit status must agree, and dqpass must report no
# dropped, failed-closed or unmarked consultation (it exits 125 if so).
#
# suites: the kyua suites named in DQ_ORACLE_SUITES (default sys/file,
# sys/kern/execve and sys/dq_regress) run under dqpass and unattached;
# the per-case results must agree, except the cases dqpass.expected lists (I5, jail, setcred,
# fplookup, core dumps).
#
# oracle_standing: both again under dqpass -r /:all, a standing rule that
# passes every lookup a rule can cover without posting it
# (dq-standing-decisions, stage 1): the results must agree just the same,
# and every run must have counted standing passes.
#

. "$(atf_get_srcdir)/dq_suites.subr"

# DQPASS_RULES: the standing rules dqpass installs (oracle_standing).
DQPASS_RULES=
dqpass()
{
	"$(atf_get_srcdir)/dqpass" ${DQPASS_RULES} "$@"
}

# With standing rules, a report must show that they decided something.
require_standing()
{
	[ -z "${DQPASS_RULES}" ] && return 0
	grep -Eq '^dqpass: standing pass [1-9]' "$1" || {
		cat "$1" >&2
		atf_fail "$2: no standing pass under ${DQPASS_RULES}"
	}
}

require_dq()
{
	[ -c /dev/dq ] || atf_fail "/dev/dq is absent"
	[ -x "$(atf_get_srcdir)/dqpass" ] || atf_fail "dqpass is not installed"
}

# Run "$@" both ways; compare output and status.
same_both_ways()
{
	local plain_out pass_out plain_rc pass_rc

	plain_out=$("$@" 2>&1); plain_rc=$?
	pass_out=$(dqpass -o dqpass.report "$@" 2>&1); pass_rc=$?
	if [ "${pass_rc}" -eq 125 ]; then
		cat dqpass.report >&2
		atf_fail "dqpass saw a dropped, failed-closed or unmarked consultation: $*"
	fi
	if [ "${plain_rc}" -ne "${pass_rc}" ]; then
		cat dqpass.report >&2
		atf_fail "exit status differs for '$*': unattached ${plain_rc}, attached ${pass_rc}"
	fi
	if [ "${plain_out}" != "${pass_out}" ]; then
		printf '%s\n' "${plain_out}" > plain.out
		printf '%s\n' "${pass_out}" > pass.out
		diff -u plain.out pass.out >&2
		atf_fail "output differs for '$*'"
	fi
	grep -q 'RESOLVE events' dqpass.report ||
	    atf_fail "dqpass wrote no report for '$*'"
	require_standing dqpass.report "$*"
}

atf_test_case commands
commands_head()
{
	atf_set "descr" "fixed commands give the same output and status " \
	    "attached under dqpass as unattached"
	atf_set "require.user" "root"
}
commands_body()
{
	run_commands
}

run_commands()
{
	require_dq
	mkdir work
	echo hello > work/a
	same_both_ways /bin/ls -l /usr/share/examples
	same_both_ways /bin/cat work/a
	same_both_ways /bin/sh -c 'cd work && mkdir d && ln a d/b && mv d/b d/c && cat d/c && rm -r d'
	same_both_ways /usr/bin/find /usr/share/man/man4 -name 'dq*'
	# link(2): plain, and following a symlink (ln -L, AT_SYMLINK_FOLLOW).
	same_both_ways /bin/sh -c 'cd work && ln a hard && cat hard && rm hard'
	same_both_ways /bin/sh -c 'cd work && ln -s a sl && ln -L sl hl && cat hl && ls -l hl | cut -c1-10 && rm sl hl'
	same_both_ways /bin/sh -c 'test -e /nonexistent; echo $?'
	same_both_ways /bin/sh -c 'exec /usr/bin/true'
	same_both_ways /bin/sh -c 'exit 3'
	same_both_ways /usr/bin/env -i /bin/sh -c 'cd /usr/share && pwd -P'
	# A #! script: the interpreter lookup is consulted as EXEC_INTERP,
	# under -r too: a subtree rule never covers it (dq(4)).
	printf '#!/bin/sh\necho script $1\n' > work/s.sh
	chmod 755 work/s.sh
	same_both_ways ./work/s.sh arg
	dqpass -o r ./work/s.sh x >/dev/null
	atf_check -o match:'exec_interp' cat r
	# socket(2) and socketpair(2) (1c-ii): a program, and nc(1) over an
	# AF_UNIX stream socket (bind, connect, socket).
	same_both_ways "$(atf_get_srcdir)/dq_sockprog"
	dqpass -o r "$(atf_get_srcdir)/dq_sockprog" >/dev/null
	atf_check -o match:'socket ' -o match:'socketpair ' cat r
	same_both_ways /bin/sh -c 'cd work && rm -f ns && { nc -lU ns > got & } && i=0 && while [ ! -S ns ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done && echo hi | nc -NU ns && wait && cat got && rm -f ns got'
}

atf_test_case suites
suites_head()
{
	atf_set "descr" "kyua suites give the same per-case results attached " \
	    "under dqpass as unattached, apart from dqpass.expected"
	atf_set "require.user" "root"
	atf_set "require.progs" "kyua"
}
suites_body()
{
	run_suites
}

run_suites()
{
	local suite kf expected nsuites rc defaults

	require_dq
	# The fixture without its comments and blank lines (an empty pattern
	# would match every line).
	expected=patterns
	# Every entry names one program and case and its owner, "# ux-N:
	# cause" or "# by-design D###: reason": an untagged entry would hide
	# a difference no sub-series removes, a bare word every case whose
	# name contains it.
	dq_check_expected "$(atf_get_srcdir)/dqpass.expected"
	dq_patterns "${expected}" "$(atf_get_srcdir)/dqpass.expected"
	# Only the default set can prove an entry stale: an entry for a
	# suite left out matches nothing.
	defaults=
	[ -n "${DQ_ORACLE_SUITES}" ] || defaults=yes
	: ${DQ_ORACLE_SUITES:="sys/file sys/kern/execve sys/dq_regress"}
	: > used
	nsuites=0
	for suite in ${DQ_ORACLE_SUITES}; do
		kf="/usr/tests/${suite}/Kyuafile"
		# A suite that is not there compared nothing: not a pass.
		[ -f "${kf}" ] || atf_fail "suite ${suite} is not installed"
		dq_kyua_test plain.db "${kf}" || true
		rc=0
		dq_kyua_test pass.db "${kf}" dqpass -o pass.report || rc=$?
		if [ "${rc}" -eq 125 ]; then
			cat pass.report >&2
			atf_fail "${suite}: dqpass saw a dropped, failed-closed" \
			    "or unmarked consultation"
		fi
		[ -s pass.report ] || atf_fail "${suite}: dqpass wrote no report"
		require_standing pass.report "${suite}"
		dq_results plain.db plain.all
		dq_results pass.db pass.all
		echo "=== ${suite}: cases dqpass.expected excludes" >&2
		dq_excluded "${expected}" plain.all pass.all
		dq_pattern_use "${expected}" plain.all pass.all used
		grep -v -E -f "${expected}" plain.all > plain.res
		grep -v -E -f "${expected}" pass.all > pass.res
		[ -s plain.res ] || atf_fail "${suite}: every case is excluded"
		dq_require_passed "${suite}" plain.res pass.res
		if ! diff -u plain.res pass.res >&2; then
			cat pass.report >&2
			# The attached run's output of each case that differs.
			diff plain.res pass.res | sed -n 's/^> \([^ ]*\) .*/\1/p' |
			    xargs -r kyua report --results-file=pass.db --verbose \
			    --results-filter=passed,skipped,xfail,broken,failed \
			    >&2 2>/dev/null
			atf_fail "${suite}: results differ under dqpass"
		fi
		if ! dq_report_zero pass.report unmarked >&2; then
			cat pass.report >&2
			atf_fail "${suite}: unmarked user-space lookups (ledger failure)"
		fi
		rm -f plain.db pass.db plain.res pass.res pass.report plain.all* \
		    pass.all*
		nsuites=$((nsuites + 1))
	done
	[ "${nsuites}" -gt 0 ] || atf_fail "no suite was compared"
	[ -z "${defaults}" ] ||
	    dq_pattern_verdict "$(atf_get_srcdir)/dqpass.expected" used
}

atf_test_case rules_option
rules_option_head()
{
	atf_set "descr" "dqpass -r splits off only a final :read or :all; " \
	    "any other ':' belongs to the path"
	atf_set "require.user" "root"
}
rules_option_body()
{
	local d rule

	require_dq
	d=$(realpath .)
	mkdir "a:b"
	echo x > "a:b/f"
	for rule in "$d/a:b" "$d/a:b:read" "$d/a:b:all"; do
		atf_check -o inline:'x\n' -e save:ev \
		    "$(atf_get_srcdir)/dqpass" -v -o r -r "${rule}" \
		    /bin/cat "$d/a:b/f"
		atf_check -o match:'^dqpass: standing pass [1-9]' cat r
		posted open "$d/a:b/f" && atf_fail "-r ${rule}: the open posted"
	done
	# Neither suffix: the whole argument is the rule's path, which
	# covers nothing here.
	atf_check -o inline:'x\n' -e save:ev "$(atf_get_srcdir)/dqpass" -v \
	    -o r -r "$d/a:b:x" /bin/cat "$d/a:b/f"
	atf_check -o match:'^dqpass: standing pass 0 ' cat r
	posted open "$d/a:b/f" || atf_fail "-r $d/a:b:x: the open did not post"
	# :all covers a write-class open, :read does not.
	atf_check -e save:ev "$(atf_get_srcdir)/dqpass" -v -o r \
	    -r "$d/a:b:read" /usr/bin/truncate -s 0 "$d/a:b/f"
	posted open "$d/a:b/f" || atf_fail ":read: the write open did not post"
	atf_check -e save:ev "$(atf_get_srcdir)/dqpass" -v -o r \
	    -r "$d/a:b:all" /usr/bin/truncate -s 0 "$d/a:b/f"
	posted open "$d/a:b/f" && atf_fail ":all: the write open posted"
	return 0
}

# posted OP PATH: dqpass -v (in ev) printed an OP event for exactly PATH.
posted()
{
	grep '^dqpass: pid ' ev | grep -F " $1 class " | grep -qF "\"$2\""
}

atf_test_case oracle_standing
oracle_standing_head()
{
	atf_set "descr" "the commands and suites give the same results " \
	    "under dqpass -r /:all, whose standing rule passes every " \
	    "lookup a rule covers without posting it, as unattached"
	atf_set "require.user" "root"
	atf_set "require.progs" "kyua"
}
oracle_standing_body()
{
	DQPASS_RULES="-r /:all"
	run_commands
	run_suites
}

atf_init_test_cases()
{
	atf_add_test_case commands
	atf_add_test_case suites
	atf_add_test_case rules_option
	atf_add_test_case oracle_standing
}
