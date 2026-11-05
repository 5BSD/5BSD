#!/bin/sh
# Compile the production aggregation implementation with simulated kernel I/O.
# No /dev/dtrace, privileges, guest, or network is used.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${1:-$(cd "$here/../../.." && pwd)}
out=${2:-/usr/obj/libdtrace-aggregate-test}
mkdir -p "$out"
# Reuse the maintained library's platform/header flags; do not copy its logic.
cflags=$(make -C "$src/cddl/lib/libdtrace" -V CFLAGS)
# CFLAGS intentionally undergoes shell field splitting, as in a Make recipe.
${CC:-cc} $cflags -UNDEBUG -ffunction-sections -fdata-sections \
    "$here/aggregate_vm_test.c" -Wl,--gc-sections -ldtrace -lproc -lxo \
    -o "$out/aggregate_vm_test"
"$out/aggregate_vm_test"
