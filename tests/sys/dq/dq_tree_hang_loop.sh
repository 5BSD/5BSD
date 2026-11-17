#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
#
# The served-root hang reproducer (transparency rows T-R11, T-R12): one
# test case, usr.bin/find's find_test:find_printf by default, run again
# and again under dqtree with two CPU burners beside it, as the
# dq_tree_suites_test runs that hung for 300 s ran it, with the hang
# capture (dq_hang.subr) watching.  It is not part of the default run:
# kyua runs it only with the dq_hang_loop configuration variable set, in
# a guest with two vCPUs (vm-provider.sh CPUS=2):
#
#	kyua -v test_suites.FreeBSD.dq_hang_loop=yes test \
#	    sys/dq/dq_tree_hang_loop
#
# DQ_HANG_CASE (program:case under /usr/tests), DQ_HANG_ROUNDS (200) and
# DQ_HANG_MAX (3: stop after that many hung rounds) change what is run and
# how often.  Every round must pass: a round that
# times out or fails is a hang, reported with the capture.
#

. "$(atf_get_srcdir)/dq_suites.subr"
. "$(atf_get_srcdir)/dq_hang.subr"

atf_test_case loop cleanup
loop_head()
{
	atf_set "descr" "a served-root test case run repeatedly beside CPU " \
	    "burners completes every time (the find_printf hang)"
	atf_set "require.user" "root"
	atf_set "require.config" "dq_hang_loop"
	atf_set "require.progs" "kyua mount_nullfs dtrace"
	atf_set "timeout" "21600"
}
loop_body()
{
	local root kase prog name rounds maxhangs i hangs sampler rc res start
	local secs

	[ -c /dev/dq ] || atf_fail "/dev/dq is absent"
	[ -x "$(atf_get_srcdir)/dqtree" ] || atf_fail "dqtree is not installed"
	kase="${DQ_HANG_CASE:-usr.bin/find/find_test:find_printf}"
	prog="${kase%%:*}"
	name="${kase#*:}"
	rounds="${DQ_HANG_ROUNDS:-200}"
	maxhangs="${DQ_HANG_MAX:-3}"
	root="/usr/obj/dqtree-hang.$$"
	dq_assemble_root "${root}" || atf_fail "cannot assemble ${root}"
	[ -x "${root}/usr/tests/${prog}" ] ||
	    atf_fail "${prog} is not in ${root}"
	# Two burners: the hung runs shared their CPUs.
	for i in 1 2; do
		sh -c 'while :; do :; done' &
		echo $! >> burners
	done
	hangs=0
	i=0
	while [ "${i}" -lt "${rounds}" ]; do
		i=$((i + 1))
		rm -rf hang "${root}/tmp/hang.db"
		hang_sampler hang "${root}" "dqtree -o hang.report ${root}" &
		sampler=$!
		start=$(date +%s)
		rc=0
		env -i HOME=/tmp PATH=/bin:/sbin:/usr/bin:/usr/sbin TMPDIR=/tmp \
		    "$(atf_get_srcdir)/dqtree" -o hang.report "${root}" \
		    kyua test --results-file=/tmp/hang.db \
		    -k "/usr/tests/$(dirname "${prog}")/Kyuafile" \
		    "$(basename "${prog}"):${name}" > round.out 2>&1 || rc=$?
		secs=$(($(date +%s) - start))
		kill "${sampler}" 2>/dev/null
		wait "${sampler}" 2>/dev/null
		res=$(kyua report --results-file="${root}/tmp/hang.db" \
		    --results-filter=passed,skipped,xfail,broken,failed 2>&1 |
		    grep -E -- " -> " | head -n 1)
		case "${res}" in
		*"->  passed"*|*"-> passed"*)
			echo "round ${i}: passed in ${secs} s" >&2 ;;
		*)
			hangs=$((hangs + 1))
			echo "=== round ${i}: not passed (dqtree ${rc}," \
			    "${secs} s): ${res}" >&2
			tail -n 50 round.out >&2
			kyua report --results-file="${root}/tmp/hang.db" \
			    --verbose >&2 2>/dev/null
			hang_report hang
			[ "${hangs}" -lt "${maxhangs}" ] || break
			;;
		esac
	done
	echo "${hangs} of ${i} rounds did not pass" >&2
	[ "${hangs}" -eq 0 ] || atf_fail "${hangs} of ${rounds} rounds hung" \
	    "or failed"
}
loop_cleanup()
{

	if [ -f burners ]; then
		xargs kill < burners 2>/dev/null
	fi
	dq_teardown_root
}

atf_init_test_cases()
{
	atf_add_test_case loop
}
