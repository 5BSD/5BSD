#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause

# Reproducible LLVM coverage runner for the locally executable Bluetooth
# stack.  Hardware-only ATF cases remain part of the Kyua run and report an
# explicit skip when their controller or privileges are unavailable.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
srctop=$(CDPATH= cd -- "$here/../../../.." && pwd)
out=${1:-/tmp/bluetooth-coverage}
objprefix=${MAKEOBJDIRPREFIX:-$out/obj}
profiles=$out/profiles
report=$out/report
results=$out/results.db
kyua_report=$report/kyua.txt
component_baseline=$here/coverage-baseline.txt
min_line=${MIN_LINE_COVERAGE:-95.0}
min_branch=${MIN_BRANCH_COVERAGE:-79.8}

mkdir -p "$profiles" "$report"
rm -f "$profiles"/*.profraw "$out/merged.profdata" "$results"

env MAKEOBJDIRPREFIX="$objprefix" make -C "$here" \
    BLUETOOTH_COVERAGE=yes -j"$(sysctl -n hw.ncpu)"

objdir=$(env MAKEOBJDIRPREFIX="$objprefix" make -C "$here" -V .OBJDIR)

run_status=0
(
    cd "$here"
    LLVM_PROFILE_FILE="$profiles/%m-%p.profraw" \
        kyua test -k "$objdir/Kyuafile" --build-root="$objdir" \
        --results-file="$results"
) || run_status=$?

set -- "$profiles"/*.profraw
if [ ! -e "$1" ]; then
    echo "coverage: no profiles were produced" >&2
    exit 1
fi
llvm-profdata merge -sparse "$profiles"/*.profraw -o "$out/merged.profdata"

objects=
for name in $(awk '/^ATF_TESTS_C\+=/{print $2}' "$here/Makefile"); do
    if [ -x "$objdir/$name" ]; then
        objects="$objects -object $objdir/$name"
    fi
done
if [ -z "$objects" ]; then
    echo "coverage: no instrumented test programs found" >&2
    exit 1
fi

# Deliberate word splitting: objects is a generated sequence of
# "-object path" pairs and source/object paths in this tree contain no spaces.
# shellcheck disable=SC2086
llvm-cov report $objects -instr-profile="$out/merged.profdata" \
    -ignore-filename-regex='(^|/)(tests|contrib)/|(^|/)sys/sys/' \
    >"$report/summary.txt"
# shellcheck disable=SC2086
llvm-cov show $objects -instr-profile="$out/merged.profdata" \
    -ignore-filename-regex='(^|/)(tests|contrib)/|(^|/)sys/sys/' \
    -format=html -output-dir="$report/html" >/dev/null

cat "$report/summary.txt"
echo "Coverage report: $report/html/index.html"
echo "Kyua results: $results"
if [ "$run_status" -ne 0 ]; then
	echo "coverage: Kyua reported failures (status $run_status)" >&2
	exit "$run_status"
fi

# Hardware exercise is intentionally opportunistic, but a software test must
# never disappear from coverage behind an unnoticed skip.
kyua report --results-file="$results" >"$kyua_report"
unexpected_skips=$out/unexpected-skips
awk '/ -> skipped:/ && $1 !~ /^hci_hw_test:/ { print }' "$kyua_report" \
    >"$unexpected_skips"
if [ -s "$unexpected_skips" ]; then
	echo "coverage: unexpected non-hardware skips:" >&2
	cat "$unexpected_skips" >&2
	exit 1
fi

# Keep the floors just below the measured software baseline.  Raising these
# environment-overridable values is an explicit part of landing new coverage;
# a patch may not silently reduce either line or branch coverage.
set -- $(awk '$1 == "TOTAL" { gsub(/%/, "", $10); gsub(/%/, "", $13); print $10, $13 }' \
    "$report/summary.txt")
line=$1
branch=$2
if ! awk -v actual="$line" -v minimum="$min_line" \
    'BEGIN { exit !(actual + 0 >= minimum + 0) }'; then
	echo "coverage: line coverage ${line}% is below ${min_line}%" >&2
	exit 1
fi
if ! awk -v actual="$branch" -v minimum="$min_branch" \
    'BEGIN { exit !(actual + 0 >= minimum + 0) }'; then
	echo "coverage: branch coverage ${branch}% is below ${min_branch}%" >&2
	exit 1
fi
echo "Coverage gates: line ${line}% >= ${min_line}%, branch ${branch}% >= ${min_branch}%"

component_failures=$out/component-failures
rm -f "$component_failures"
while read -r source source_line source_branch; do
	case "$source" in
	""|'#'*) continue ;;
	esac
	set -- $(awk -v source="$source" '$1 == source {
	    gsub(/%/, "", $10); gsub(/%/, "", $13); print $10, $13
	}' "$report/summary.txt")
	if [ "$#" -ne 2 ]; then
		echo "coverage: tracked component missing from report: $source" \
		    >>"$component_failures"
		continue
	fi
	if ! awk -v actual="$1" -v minimum="$source_line" \
	    'BEGIN { exit !(actual + 0 >= minimum + 0) }'; then
		echo "coverage: $source line coverage $1% is below $source_line%" \
		    >>"$component_failures"
	fi
	if ! awk -v actual="$2" -v minimum="$source_branch" \
	    'BEGIN { exit !(actual + 0 >= minimum + 0) }'; then
		echo "coverage: $source branch coverage $2% is below $source_branch%" \
		    >>"$component_failures"
	fi
done <"$component_baseline"
if [ -s "$component_failures" ]; then
	cat "$component_failures" >&2
	exit 1
fi
echo "Coverage gates: all tracked component floors passed"
