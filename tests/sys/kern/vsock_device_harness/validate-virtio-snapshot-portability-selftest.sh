#!/bin/sh
# Prove that the portability guard rejects a native state field outside the
# three historical legacy VirtIO snapshot codecs.  This test deliberately
# changes only a temporary copy of the production source; it never relies on
# a bhyve header or a host ABI to obtain the expected result.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${SRCTOP:-/usr/src}
guard=$here/validate-virtio-snapshot-portability.sh
source=$src/usr.sbin/bhyve/virtio.c
bhyverun=$src/usr.sbin/bhyve/bhyverun.c
work=$(mktemp -d "${TMPDIR:-/tmp}/virtio-snapshot-portability.XXXXXX")

cleanup()
{
	status=${1:-$?}
	trap - EXIT HUP INT TERM
	rm -rf -- "$work"
	exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

[ -x "$guard" ] || {
	echo "snapshot portability selftest: missing guard" >&2
	exit 1
}
[ -r "$source" ] || {
	echo "snapshot portability selftest: missing virtio source" >&2
	exit 1
}
[ -r "$bhyverun" ] || {
	echo "snapshot portability selftest: missing bhyverun source" >&2
	exit 1
}

fixture=$work/virtio.c
diagnostic=$work/guard.out
# Add a syntactically isolated, deliberately invalid native field.  sed(1)
# creates the fixture in a private temporary directory; the guard must fail
# before any compiled artifact is involved.
sed '$a\
static int\
vi_pci_snapshot_unportable_probe(struct virtio_softc *vs, struct vm_snapshot_meta *meta)\
{\
\tint ret;\
\
\tSNAPSHOT_VAR_OR_LEAVE(vs->vs_flags, meta, ret, done);\
done:\
\treturn (ret);\
}' "$source" > "$fixture"

if SRCTOP="$src" VIRTIO_SNAPSHOT_SOURCE="$fixture" "$guard" \
    >"$diagnostic" 2>&1; then
	echo "snapshot portability selftest: escaped native field was accepted" >&2
	exit 1
fi
if ! grep -q 'native-width bhyve snapshot field remains' "$diagnostic"; then
	echo "snapshot portability selftest: guard failed for the wrong reason" >&2
	cat "$diagnostic" >&2
	exit 1
fi

# Destination CPU capture is the architecture-owned restore admission step.
# Mutate only a private copy: the guard must reject a refactor that replaces
# it with a similarly named but non-existent helper before any binary is run.
bhyverun_fixture=$work/bhyverun.c
sed 's/checkpoint_cpu_contract_capture(bsp,/checkpoint_cpu_contract_capture_removed(bsp,/' \
    "$bhyverun" > "$bhyverun_fixture"
if SRCTOP="$src" BHYVERUN_SOURCE="$bhyverun_fixture" "$guard" \
    >"$diagnostic" 2>&1; then
	echo "snapshot portability selftest: restore without destination CPU capture was accepted" >&2
	exit 1
fi
if ! grep -q 'restore must decode, capture, then compare CPU contract' "$diagnostic"; then
	echo "snapshot portability selftest: restore-order guard failed for the wrong reason" >&2
	cat "$diagnostic" >&2
	exit 1
fi

# The common VirtIO core must not gain an Intel-only include.  Substitute only
# a private copy of that one source while retaining the validator's complete
# production device-file inventory.
common_fixture=$work/virtio-common.c
sed '1i\
#include <amd64/include/vmm.h>' "$source" > "$common_fixture"
if SRCTOP="$src" VIRTIO_COMMON_CORE_SOURCE="$common_fixture" "$guard" \
    >"$diagnostic" 2>&1; then
	echo "snapshot portability selftest: CPU-specific common VirtIO source was accepted" >&2
	exit 1
fi
if ! grep -q 'shared VirtIO source has a CPU-specific dependency' "$diagnostic"; then
	echo "snapshot portability selftest: CPU-specific source guard failed for the wrong reason" >&2
	cat "$diagnostic" >&2
	exit 1
fi

# Exercise the same policy through a device-model fixture.  The extra source
# is additive, so the guard still scans every real production device before
# it reaches this hostile copy.
device_fixture=$work/pci_virtio_balloon.c
sed '1i\
#include <x86/include/specialreg.h>' "$src/usr.sbin/bhyve/pci_virtio_balloon.c" \
    > "$device_fixture"
if SRCTOP="$src" VIRTIO_EXTRA_DEVICE_SOURCE="$device_fixture" "$guard" \
    >"$diagnostic" 2>&1; then
	echo "snapshot portability selftest: CPU-specific device source was accepted" >&2
	exit 1
fi
if ! grep -q 'shared VirtIO source has a CPU-specific dependency' "$diagnostic"; then
	echo "snapshot portability selftest: device source guard failed for the wrong reason" >&2
	cat "$diagnostic" >&2
	exit 1
fi

echo "PASS snapshot portability guard rejects escaped native field"
