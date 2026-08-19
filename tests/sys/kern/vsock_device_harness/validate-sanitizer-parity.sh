#!/bin/sh
# Ensure every non-VirtIO host model claimed by the coverage ledger is also
# compiled and executed by the ASan/UBSan harness, not only by Kyua.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ledger=${WASPNEST_NONVIRTIO_LEDGER:-$here/../../../waspnest/waspnest-nonvirtio-coverage.tsv}
run=$here/run.sh
makefile=$here/Makefile

fail()
{
	echo "sanitizer parity: $*" >&2
	exit 1
}

[ -f "$ledger" ] || fail "missing non-VirtIO coverage ledger: $ledger"

tests=$(awk -F '\t' 'NR > 1 && $3 != "-" {
    n = split($3, names, ",")
    for (i = 1; i <= n; i++) if (!seen[names[i]]++) print names[i]
}' "$ledger")
tests="$tests
mevent_lifecycle_test"

for test_program in $tests; do
	grep -Eq "ATF_TESTS_C\\+=[[:space:]]*$test_program([[:space:]]|$)" \
	    "$makefile" || fail "$test_program is not built by Kyua"
	grep -Fq '"$here/'"$test_program"'.c"' "$run" ||
	    fail "$test_program source is absent from sanitizer staging"
	grep -Fq '"$work/'"$test_program"'.c"' "$run" ||
	    fail "$test_program is not compiled by the sanitizer harness"
done

echo "PASS sanitizer model parity"
