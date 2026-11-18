#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-provider.sh refuses a stage whose test programs come from more than one
# checkout (STALE_TESTS) unless TESTS_SRC_ROOTS names them all
# (5bsd-issues 2026-11-18-guest-stage-stale-tests-sys-file-binaries.md).
# Runs check-stage-tests.py on fake programs; no guest.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }
chk() { python3.12 -I "$root/check-stage-tests.py" "$@" > "$work/out" 2>&1; }
# prog PATH SOURCE...: an ELF-headed file recording the source names.
prog() {
	p=$work/stage/usr/tests/$1; shift
	mkdir -p "${p%/*}"
	{ printf '\177ELF\002\001\001\000'; for s; do printf '\000%s\000' "$s"; done; } > "$p"
}
A=/usr/obj/5BSD-a B=/usr/obj/5BSD-b
grep -q 'check-stage-tests.py" "\$stage" "\$@" ||' "$root/vm-provider.sh" ||
    fail 'vm-provider does not run check-stage-tests.py'
prog sys/file/flock_test $A/tests/sys/file/flock_test.c
prog sys/kern/k_test $A/tests/sys/kern/k_test.c $A/contrib/netbsd-tests/lib/x.c
# A generated source in the object directory is the same checkout.
prog sys/kern/gen_test /usr/obj$A/amd64.amd64/tests/sys/kern/gen.c
printf '#!/bin/sh\necho %s/tests/x.c\n' "$B" > "$work/stage/usr/tests/script_test"
echo "$B/tests/sys/file/data.c" > "$work/stage/usr/tests/sys/file/data"
chk "$work/stage" || fail "one checkout refused: $(cat "$work/out")"
grep -qx "TESTS_SRC_ROOT=$A programs=3" "$work/out" || fail "count: $(cat "$work/out")"
# The issue's case: one directory reinstalled from another checkout.
prog sys/file/flock_test $B/tests/sys/file/flock_test.c
rc=0; chk "$work/stage" || rc=$?
[ $rc = 3 ] || fail "mixed stage exit $rc: $(cat "$work/out")"
grep -qx "STALE_TESTS: usr/tests/sys/file/flock_test names $B" "$work/out" ||
    fail "no STALE_TESTS line: $(cat "$work/out")"
chk "$work/stage" --allow "$A" --allow "$B" ||
    fail "a declared overlay refused: $(cat "$work/out")"
rc=0; chk "$work/stage" --allow "$A" || rc=$?
[ $rc = 3 ] || fail "an undeclared checkout accepted (exit $rc)"
rc=0; chk "$work/none" || rc=$?
[ $rc = 2 ] || fail "a stage without usr/tests: exit $rc"
echo 'PASS a stage with test programs from two checkouts is STALE_TESTS unless declared'
