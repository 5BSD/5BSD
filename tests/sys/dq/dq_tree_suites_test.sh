#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# The served-root suites oracle (stage 1c-iii-c, D173): kyua suites run in
# a served root made by dq_serve_tree() over a copy of the system's tree
# (dqtree, installed beside this test) must give the per-case results
# chroot(8) of the same directory gives, apart from dqtree.expected.
#
# The directory is DQ_TREE_ROOT when set (a prepared system tree under
# /usr/obj, never /home); otherwise it is assembled under /usr/obj from
# read-only nullfs views of /bin, /sbin, /lib, /libexec, /usr and /etc,
# a tmpfs /tmp and a devfs /dev, and torn down afterwards.  The suites are
# DQ_TREE_SUITES (default sys/file lib/libc/gen bin/ls usr.bin/find; add
# sys/vfs lib/libc/sys for the informational run).  The unattached run's
# results are printed beside them for reference.
#

. "$(atf_get_srcdir)/dq_suites.subr"

dqtree()
{
	"$(atf_get_srcdir)/dqtree" "$@"
}

# The fixtures' patterns, one per line, with each line's owner tag: the
# word after an inline "#" ("ux-1", "by-design", "unowned"), "-" for a
# pattern without one.  Output: "pattern<TAB>tag".
tagged_patterns()
{
	awk '
	/^[[:space:]]*(#|$)/ { next }
	{
		p = $0; tag = "-"
		i = index(p, "#")
		if (i > 0) {
			c = substr(p, i + 1); p = substr(p, 1, i - 1)
			sub(/^[[:space:]]+/, "", c)
			split(c, w, /[:[:space:]]/)
			tag = w[1]
		}
		sub(/[[:space:]]+$/, "", p)
		printf("%s\t%s\n", p, tag)
	}' "$@"
}

# Per tag, how many cases of $2 differ from the reference $1 and are
# matched (first match) by a pattern of that tag in $3 (tagged_patterns).
count_by_tag()
{
	awk -v ref="$1" -v got="$2" '
	BEGIN {
		n = 0
		while ((getline l < ref) > 0) {
			split(l, f, " ")
			want[f[1]] = f[2]
		}
	}
	FILENAME != got {
		split($0, f, "\t")
		pat[n] = f[1]
		tag[n] = f[2]
		n++
		next
	}
	{
		split($0, f, " ")
		if ((f[1] in want) && want[f[1]] == f[2])
			next
		for (i = 0; i < n; i++) {
			if ($0 ~ pat[i]) {
				cnt[tag[i]]++
				break
			}
		}
	}
	END {
		for (t in cnt)
			printf("  %s: %d\n", t, cnt[t])
	}' "$3" "$2" | sort
}

# While a served-root run lasts, every 10 seconds, the kernel stacks of
# the threads waiting in dq(4), with the time: a stall (a requester that
# waits until kern.dq.default_deadline_ms) shows which wait it is and what
# it holds.  Written to $1 until killed.
stall_sampler()
{

	while :; do
		sleep 10
		{
			date -u +%T
			procstat -kka 2>/dev/null | grep -E 'dq_|dqres_'
		} >> "$1"
	done
}

# A failure recorded for the end of the case (suites_body's "failed").
fail_later()
{

	failed="${failed}${failed:+; }$*"
}

assemble()
{
	local r d

	r="$1"
	mkdir -p "${r}" || return 1
	echo "${r}" > root.made
	for d in bin sbin lib libexec usr etc; do
		mkdir -p "${r}/${d}"
		mount_nullfs -o ro "/${d}" "${r}/${d}" || return 1
		echo "${r}/${d}" >> mounts
	done
	mkdir -p "${r}/tmp" "${r}/dev" "${r}/var/run" "${r}/var/tmp"
	mount -t tmpfs tmpfs "${r}/tmp" || return 1
	echo "${r}/tmp" >> mounts
	mount -t devfs devfs "${r}/dev" || return 1
	echo "${r}/dev" >> mounts
	chmod 1777 "${r}/tmp" "${r}/var/tmp"
}

atf_test_case suites cleanup
suites_head()
{
	atf_set "descr" "kyua suites give the same per-case results in a " \
	    "served root as in chroot(8) of the same directory"
	atf_set "require.user" "root"
	atf_set "require.progs" "kyua mount_nullfs"
}
suites_body()
{
	local root suite kf expected env failed sampler stalled nsuites rc
	local defaults

	[ -c /dev/dq ] || atf_fail "/dev/dq is absent"
	[ -x "$(atf_get_srcdir)/dqtree" ] || atf_fail "dqtree is not installed"
	if [ -n "${DQ_TREE_ROOT}" ]; then
		root="${DQ_TREE_ROOT}"
	else
		root="/usr/obj/dqtree-root.$$"
		assemble "${root}" || atf_fail "cannot assemble ${root}"
	fi
	expected=patterns
	tagged_patterns "$(atf_get_srcdir)/dqtree.expected" \
	    "$(atf_get_srcdir)/dqpass.expected" > tags
	# Every expected difference names one program and case and has an
	# owner (a sub-series or a design reference).
	dq_check_expected "$(atf_get_srcdir)/dqtree.expected" \
	    "$(atf_get_srcdir)/dqpass.expected"
	cut -f 1 tags > "${expected}"
	# Every suite runs and reports before the case fails.
	failed=
	env="env -i HOME=/tmp PATH=/bin:/sbin:/usr/bin:/usr/sbin TMPDIR=/tmp"
	# Only the default set can prove an entry of dqtree.expected stale
	# (dqpass.expected's are dq_oracle_test's to judge).
	defaults=
	[ -n "${DQ_TREE_SUITES}" ] || defaults=yes
	: ${DQ_TREE_SUITES:="sys/file lib/libc/gen bin/ls usr.bin/find"}
	: > used
	nsuites=0
	for suite in ${DQ_TREE_SUITES}; do
		kf="/usr/tests/${suite}/Kyuafile"
		# A suite that is not there compared nothing: not a pass.
		[ -f "${root}${kf}" ] ||
		    atf_fail "suite ${suite} is not in ${root}"
		rm -f "${root}/tmp/chroot.db" "${root}/tmp/tree.db"
		dq_kyua_test /tmp/chroot.db "${kf}" ${env} chroot "${root}" ||
		    true
		: > stalls
		stalled=
		stall_sampler stalls &
		sampler=$!
		rc=0
		dq_kyua_test /tmp/tree.db "${kf}" ${env} \
		    "$(atf_get_srcdir)/dqtree" -o tree.report "${root}" || rc=$?
		if [ "${rc}" -eq 125 ]; then
			fail_later "${suite}: dqtree saw a dropped, failed-closed" \
			    "or unmarked consultation or a malformed reply"
		fi
		kill "${sampler}" 2>/dev/null
		wait "${sampler}" 2>/dev/null
		[ -s tree.report ] || atf_fail "${suite}: dqtree wrote no report"
		dq_kyua_test plain.db "${kf}" || true
		dq_results "${root}/tmp/chroot.db" chroot.all
		dq_results "${root}/tmp/tree.db" tree.all
		echo "=== ${suite}: cases the expected differences exclude" >&2
		dq_excluded "${expected}" chroot.all tree.all
		dq_pattern_use "${expected}" chroot.all tree.all used
		grep -v -E -f "${expected}" chroot.all > chroot.res
		grep -v -E -f "${expected}" tree.all > tree.res
		[ -s chroot.res ] || atf_fail "${suite}: every case is excluded"
		dq_require_passed "${suite}" chroot.res tree.res
		echo "=== ${suite}: expected differences by owner" >&2
		count_by_tag chroot.all tree.all tags >&2
		dq_results plain.db plain.all
		grep -v -E -f "${expected}" plain.all > plain.res
		echo "=== ${suite}: unattached vs chroot (reference)" >&2
		diff -u plain.res chroot.res >&2 || true
		cat tree.report >&2
		if ! diff -u chroot.res tree.res >&2; then
			# The served-root run's output of each case that differs.
			diff chroot.res tree.res | sed -n 's/^> \([^ ]*\) .*/\1/p' |
			    xargs -r kyua report \
			    --results-file="${root}/tmp/tree.db" --verbose \
			    --results-filter=passed,skipped,xfail,broken,failed \
			    >&2 2>/dev/null
			fail_later "${suite}: results differ in the served root"
			stalled=yes
		fi
		# A requester that waited out its deadline: the reference
		# controller held or lost an event for kern.dq.default_deadline_ms.
		if ! dq_report_zero tree.report deadline_misses >&2; then
			fail_later "${suite}: a requester waited until its deadline"
			stalled=yes
		fi
		if [ -n "${stalled}" ]; then
			echo "=== ${suite}: dq(4) waits sampled every 10 s" >&2
			tail -n 400 stalls >&2
		fi
		dq_report_zero tree.report unmarked failclosed dropped \
		    bad_replies >&2 ||
		    fail_later "${suite}: unmarked, failed-closed or dropped" \
		    "consultations, or malformed replies"
		dq_report_zero tree.report objects >&2 ||
		    fail_later "${suite}: served objects left live"
		rm -f plain.db chroot.res tree.res plain.res tree.report \
		    chroot.all* tree.all* plain.all* stalls
		nsuites=$((nsuites + 1))
	done
	[ "${nsuites}" -gt 0 ] || atf_fail "no suite was compared"
	[ -z "${failed}" ] || atf_fail "${failed}"
	# dqtree.expected's patterns come first in ${expected} (tags).
	[ -z "${defaults}" ] ||
	    dq_pattern_verdict "$(atf_get_srcdir)/dqtree.expected" used
}
suites_cleanup()
{
	local m r

	if [ -f mounts ]; then
		sort -r mounts | while read -r m; do
			umount -f "${m}" 2>/dev/null
		done
	fi
	if [ -f root.made ]; then
		r="$(cat root.made)"
		# Never remove through a mount that is still there: the
		# read-only views are of the system's own /bin, /usr and /etc.
		if mount -p | awk -v r="${r}" '
		    $2 == r || index($2, r "/") == 1 { found = 1 }
		    END { exit !found }'; then
			echo "${r}: still mounted, left in place" >&2
		else
			rm -rf "${r}" 2>/dev/null
		fi
	fi
	return 0
}

atf_init_test_cases()
{
	atf_add_test_case suites
}
