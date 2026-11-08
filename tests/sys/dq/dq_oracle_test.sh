#
# SPDX-License-Identifier: BSD-2-Clause
#
# The pass-everything oracle (stage 1c-i): a program attached to a queue
# whose controller answers every RESOLVE with PASS must behave as it does
# unattached.  dqpass (installed beside this test) is that controller.
#
# commands: a fixed list of commands, run unattached and under dqpass;
# their output and exit status must agree, and dqpass must report no
# dropped, failed-closed or unmarked consultation (it exits 125 if so).
#
# suites: the kyua suites named in DQ_ORACLE_SUITES (default sys/file and
# sys/kern/execve) run under dqpass and unattached; the per-case results
# must agree, except the cases dqpass.expected lists (I5, jail, setcred,
# fplookup, core dumps).
#

dqpass()
{
	"$(atf_get_srcdir)/dqpass" "$@"
}

require_dq()
{
	[ -c /dev/dq ] || atf_skip "/dev/dq is absent"
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
	# A #! script: the interpreter lookup is consulted as EXEC_INTERP.
	printf '#!/bin/sh\necho script $1\n' > work/s.sh
	chmod 755 work/s.sh
	same_both_ways ./work/s.sh arg
	dqpass -o r ./work/s.sh x >/dev/null
	atf_check -o match:'exec_interp' cat r
}

# kyua's per-case results, normalized: "program:case result", sorted.
results()
{
	kyua report --results-file="$1" \
	    --results-filter=passed,skipped,xfail,broken,failed 2>/dev/null |
	    sed -n -e 's/^\([^ ]*:[^ ]*\)  *->  *\([a-z_]*\).*/\1 \2/p' | sort
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
	local suite kf expected

	require_dq
	# The fixture without its comments and blank lines (an empty pattern
	# would match every line).
	expected=patterns
	sed -e '/^#/d' -e '/^[[:space:]]*$/d' \
	    "$(atf_get_srcdir)/dqpass.expected" > "${expected}"
	: ${DQ_ORACLE_SUITES:="sys/file sys/kern/execve"}
	for suite in ${DQ_ORACLE_SUITES}; do
		kf="/usr/tests/${suite}/Kyuafile"
		if [ ! -f "${kf}" ]; then
			echo "suite ${suite} not installed: skipped" >&2
			continue
		fi
		kyua test --results-file="plain.db" -k "${kf}" >/dev/null 2>&1
		dqpass -o "pass.report" kyua test --results-file="pass.db" \
		    -k "${kf}" >/dev/null 2>&1
		results plain.db | grep -v -E -f "${expected}" > plain.res
		results pass.db | grep -v -E -f "${expected}" > pass.res
		if ! diff -u plain.res pass.res >&2; then
			cat pass.report >&2
			atf_fail "${suite}: results differ under dqpass"
		fi
		if grep -q 'unmarked [1-9]' pass.report; then
			cat pass.report >&2
			atf_fail "${suite}: unmarked user-space lookups (ledger failure)"
		fi
		rm -f plain.db pass.db plain.res pass.res pass.report
	done
}

atf_init_test_cases()
{
	atf_add_test_case commands
	atf_add_test_case suites
}
