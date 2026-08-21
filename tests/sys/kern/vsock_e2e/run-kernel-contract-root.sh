#!/bin/sh
# Run kernel-only VirtIO contract tests against explicitly selected modules.

set -eu

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 077

OBJTOP=${OBJTOP:-/usr/obj/usr/src/amd64.amd64}
KERNEL=${KERNEL:-$OBJTOP/sys/VBSD/kernel}
KTEST_MODULE=${KTEST_MODULE:-$OBJTOP/sys/VBSD/modules/usr/src/sys/modules/ktest/ktest/ktest.ko}
SGLIST_MODULE=${SGLIST_MODULE:-$OBJTOP/sys/VBSD/modules/usr/src/sys/modules/ktest/ktest_sglist_boundary/ktest_sglist_boundary.ko}
KYUAFILE=${KERNEL_CONTRACT_KYUAFILE:-$OBJTOP/tests/sys/kern/Kyuafile}
if [ -n "${WORKDIR:-}" ]; then
	RESULT=${RESULT:-$WORKDIR/kyua-kernel-contract-root.db}
else
	RESULT=${RESULT:-/tmp/kyua-kernel-contract-root-$(date -u +%Y%m%dT%H%M%SZ).db}
fi

fail()
{
	echo "kernel contract root gate: $*" >&2
	exit 1
}

cleanup()
{
	kldunload ktest_sglist_boundary 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

[ "$(id -u)" -eq 0 ] || fail "must run as root"
for file in "$KERNEL" "$KTEST_MODULE" "$SGLIST_MODULE" "$KYUAFILE"; do
	[ -f "$file" ] && [ ! -L "$file" ] ||
	    fail "reviewed build artifact is not a regular file: $file"
done
nm "$KERNEL" | grep -Eq '[[:space:]]sglist_append_boundary$' ||
    fail "reviewed kernel lacks sglist boundary support"
BOOT_KERNEL=$(sysctl -n kern.bootfile)
[ -f "$BOOT_KERNEL" ] && [ ! -L "$BOOT_KERNEL" ] ||
    fail "booted kernel is not a regular file: $BOOT_KERNEL"
[ "$(sha256 -q "$BOOT_KERNEL")" = "$(sha256 -q "$KERNEL")" ] ||
    fail "booted kernel does not match reviewed kernel: $KERNEL"
nm "$BOOT_KERNEL" | grep -Eq '[[:space:]]sglist_append_boundary$' ||
    fail "booted kernel lacks sglist boundary support; install and reboot it"
kldstat -q -m ktest_ktest_sglist_boundary &&
    fail "ktest_sglist_boundary is already loaded from an unverified path"

if ! kldstat -q -m ktestmod; then
	kldload "$KTEST_MODULE"
fi
kldload "$SGLIST_MODULE"
kldstat -v | grep -F "ktest_sglist_boundary.ko ($SGLIST_MODULE)" >/dev/null ||
    fail "loaded module path does not match $SGLIST_MODULE"

inventory=$(kyua list -k "$KYUAFILE")
for test_case in virtual_adjacent_boundary physical_boundary_and_zero_length \
    boundary_failure_is_atomic vmpages_boundary_straddle \
    vmpages_partial_failure_is_atomic bio_boundary_direction_split \
    unmapped_bio_boundary_and_ordinary_compatibility \
    zero_capacity_is_rejected; do
	printf '%s\n' "$inventory" |
	    grep -qx "sglist_boundary_test:$test_case" ||
	    fail "built suite lacks kernel boundary case: $test_case"
done

test_status=0
kyua test -k "$KYUAFILE" -r "$RESULT" sglist_boundary_test ||
    test_status=$?
report_status=0
report=$(kyua report -r "$RESULT") || report_status=$?
printf '%s\n' "$report"
echo "KERNEL-CONTRACT kernel=$KERNEL sha256=$(sha256 -q "$KERNEL")"
echo "KERNEL-CONTRACT module=$SGLIST_MODULE sha256=$(sha256 -q "$SGLIST_MODULE")"
echo "KERNEL-CONTRACT result=$RESULT"
[ "$report_status" -eq 0 ] || exit "$report_status"
[ "$test_status" -eq 0 ] || exit "$test_status"
printf '%s\n' "$report" | grep -Eq \
    'Test cases: 8 total, 0 skipped, 0 expected failures, 0 broken, 0 failed' ||
    fail "gate requires all eight kernel boundary tests to pass"
