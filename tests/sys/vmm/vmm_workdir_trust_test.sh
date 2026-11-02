#
# Copyright (c) 2026 5BSD
#
# SPDX-License-Identifier: BSD-2-Clause
#
# The privileged nested-virtualization runners accept a WORKDIR below a
# root-owned world-writable directory only when that ancestor carries the
# sticky bit (notably /tmp).  stat(1) "%Lp" prints only the permission bits
# (0777) and drops S_ISVTX, so a helper that tests 01000 against "%Lp" never
# sees the sticky bit and refuses /tmp.  Exercise the WORKDIR helper of every
# runner that implements the exemption: a sticky world-writable ancestor is
# accepted and a non-sticky world-writable ancestor is refused.
#
# Ownership is not under test here (an unprivileged Kyua run cannot create
# root-owned directories), so stat(1) is wrapped to report uid 0 while the
# mode bits stay the real ones from the file system.

RUNNERS="run-svm-nested-atf.sh:trusted_workdir \
run-svm-nested-live.sh:trusted_workdir_hierarchy \
run-vmx-nested-live.sh:trusted_workdir_hierarchy"

# Print the named shell function from a runner script.
extract_helper()
{
	awk -v fn="$2()" '
	    $0 == fn { on = 1 }
	    on { print }
	    on && $0 == "}" { exit }
	' "$1"
}

# Run one runner's helper on $3 in a subshell; exit status 0 = accepted.
check_workdir()
{
	runner=$(atf_get_srcdir)/$1
	[ -r "$runner" ] || atf_fail "missing runner $runner"
	helper=$(extract_helper "$runner" "$2")
	[ -n "$helper" ] || atf_fail "$1 no longer defines $2()"
	(
		set -eu
		fail() { echo "refused: $*" >&2; exit 1; }
		stat()
		{
			out=$(command stat "$@") || return
			echo "0 ${out#* }"
		}
		eval "$helper"
		"$2" "$3" "WORKDIR"
	)
}

make_tree()
{
	base=$(mktemp -d /tmp/vmm-workdir-trust.XXXXXX) ||
	    atf_fail "cannot create a scratch directory below /tmp"
	echo "$base" >scratch
	chmod "$1" "$base"
	mkdir -m 0700 "$base/work"
	echo "$base/work"
}

cleanup_tree()
{
	[ -f scratch ] || return 0
	base=$(cat scratch)
	case "$base" in
	/tmp/vmm-workdir-trust.*) rm -rf "$base" ;;
	esac
}

atf_test_case sticky_ancestor_accepted cleanup
sticky_ancestor_accepted_head()
{
	atf_set "descr" "A root-owned sticky world-writable WORKDIR ancestor" \
	    "(the /tmp layout) is accepted by every runner"
}
sticky_ancestor_accepted_body()
{
	[ -k /tmp ] || atf_skip "/tmp is not sticky on this host"
	work=$(make_tree 1777)
	for entry in $RUNNERS; do
		check_workdir "${entry%%:*}" "${entry#*:}" "$work" ||
		    atf_fail "${entry%%:*} refused a sticky world-writable ancestor"
	done
}
sticky_ancestor_accepted_cleanup()
{
	cleanup_tree
}

atf_test_case nonsticky_ancestor_refused cleanup
nonsticky_ancestor_refused_head()
{
	atf_set "descr" "A world-writable WORKDIR ancestor without the" \
	    "sticky bit is refused by every runner"
}
nonsticky_ancestor_refused_body()
{
	[ -k /tmp ] || atf_skip "/tmp is not sticky on this host"
	work=$(make_tree 0777)
	for entry in $RUNNERS; do
		if check_workdir "${entry%%:*}" "${entry#*:}" "$work" \
		    2>stderr; then
			atf_fail "${entry%%:*} accepted a non-sticky" \
			    "world-writable ancestor"
		fi
		grep -q "writable" stderr ||
		    atf_fail "${entry%%:*} refused for an unexpected reason:" \
		    "$(cat stderr)"
	done
}
nonsticky_ancestor_refused_cleanup()
{
	cleanup_tree
}

atf_init_test_cases()
{
	atf_add_test_case sticky_ancestor_accepted
	atf_add_test_case nonsticky_ancestor_refused
}
