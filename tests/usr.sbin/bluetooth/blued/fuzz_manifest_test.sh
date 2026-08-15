#!/bin/sh

# SPDX-License-Identifier: BSD-2-Clause

atf_test_case installed_harness_sources
installed_harness_sources_head()
{
	atf_set descr 'Installed fuzz build recipe has all referenced harness sources'
}
installed_harness_sources_body()
{
	fuzzdir="$(atf_get_srcdir)/fuzz"
	makefile="$fuzzdir/Makefile"
	missing=''

	[ -f "$makefile" ] || atf_fail "missing installed fuzz/Makefile"

	# Each fuzz target names its harness as ${H}/fuzz_*.c.  Check the
	# installed tree, rather than the source tree, so FILESGROUP omissions
	# cannot leave a package with a build rule but no source file.
	for src in $(awk '
	{
		while (match($0, /\$\{H\}\/fuzz_[[:alnum:]_]+\.c/)) {
			print substr($0, RSTART + 5, RLENGTH - 5)
			$0 = substr($0, RSTART + RLENGTH)
		}
	}' "$makefile" | sort -u); do
		[ -f "$fuzzdir/$src" ] || missing="$missing $src"
	done

	[ -z "$missing" ] ||
		atf_fail "fuzz build recipe references uninstalled source(s):$missing"
}

atf_init_test_cases()
{
	atf_add_test_case installed_harness_sources
}
