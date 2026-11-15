#!/bin/sh
# build-capability-fixtures.sh -- build the test-only mac_capability fixture
# modules for a guest kernel and collect them for vm-provider.sh
# (CAPABILITY_FIXTURES_DIR).
#
# usage: build-capability-fixtures.sh KERNBUILDDIR OUTDIR
#    or: KERNBUILDDIR=... FIXTURES_OUT=... build-capability-fixtures.sh
#        (the second form serves as BUILDENV_SHELL)
#
# Run it inside `make buildenv` of the source tree whose GENERIC the stage
# carries, with KERNBUILDDIR that kernel's object directory: the modules must
# match it.  It builds tests/sys/mac_capability/fixtures (keystore,
# kernelstore; see its README) and tools/test/daemon-runtime/cleanup-fixture
# and copies the three .ko files into OUTDIR.  None of them is installed by
# a world, a kernel or a package; they are for disposable test images only.
set -eu

kern=${1:-${KERNBUILDDIR:-}}
out=${2:-${FIXTURES_OUT:-}}
[ -n "$kern" ] && [ -n "$out" ] || {
	sed -n '2,/^set -eu/p' "$0" | sed -e '/^set -eu/d' -e 's/^# \{0,1\}//' >&2
	exit 64
}
[ -f "$kern/opt_global.h" ] || { echo "not a kernel build directory: $kern" >&2; exit 2; }
srctop=$(cd "$(dirname "$0")/../../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
jobs=$(sysctl -n hw.ncpu)
make -j"$jobs" -C "$srctop/tests/sys/mac_capability" fixtures KERNBUILDDIR="$kern"
make -j"$jobs" -C "$srctop/tools/test/daemon-runtime/cleanup-fixture" KERNBUILDDIR="$kern"
for d in tests/sys/mac_capability/fixtures/keystore \
    tests/sys/mac_capability/fixtures/kernelstore \
    tools/test/daemon-runtime/cleanup-fixture; do
	obj=$(make -C "$srctop/$d" -V .OBJDIR KERNBUILDDIR="$kern")
	for ko in "$obj"/*.ko; do
		[ -f "$ko" ] || { echo "no module built in $obj" >&2; exit 1; }
		cp -f "$ko" "$out/"
	done
done
for k in mac_capability_test_keystore mac_capability_test_kernelstore \
    mac_capability_test_cleanup; do
	[ -f "$out/$k.ko" ] || { echo "missing $k.ko in $out" >&2; exit 1; }
done
echo "capability fixtures in $out"
