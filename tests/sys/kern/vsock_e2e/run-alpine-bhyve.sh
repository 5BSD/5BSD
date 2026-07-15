#!/bin/sh
# Launch Alpine with bhyve's virtio-vsock device.  This deliberately does not
# modify the image, ISO, or host networking.
#
# Set exactly one of IMAGE=/path/to/alpine.raw or ISO=/path/to/alpine-virt.iso.
# Optional: TRANSPORT, CID, DIR, TAP, UEFI, BHYVE, VMNAME, CONSOLE.
set -eu

IMAGE=${IMAGE:-}
ISO=${ISO:-}
TRANSPORT=${TRANSPORT:-modern}
CID=${CID:-4}
DIR=${DIR:-$HOME/vm/vsock-sockdir-alpine}
TAP=${TAP:-tap0}
VMNAME=${VMNAME:-alpine-vsock}
BHYVE=${BHYVE:-/usr/obj/usr/src/$(uname -p).$(uname -p)/usr.sbin/bhyve/bhyve}
UEFI=${UEFI:-/usr/local/share/uefi-firmware/BHYVE_UEFI.fd}
CONSOLE=${CONSOLE:-stdio}

case "$TRANSPORT" in
modern|legacy) ;;
*) echo "TRANSPORT must be modern or legacy" >&2; exit 2 ;;
esac
if [ -n "$IMAGE" ] && [ -n "$ISO" ]; then
	echo "set only one of IMAGE or ISO" >&2
	exit 2
elif [ -n "$IMAGE" ]; then
	test -f "$IMAGE" || { echo "IMAGE not found: $IMAGE" >&2; exit 2; }
	storage="-s 3,virtio-blk,$IMAGE"
elif [ -n "$ISO" ]; then
	test -f "$ISO" || { echo "ISO not found: $ISO" >&2; exit 2; }
	storage="-s 3,ahci-cd,$ISO"
else
	echo "set IMAGE to a raw disk or ISO to an Alpine virt ISO" >&2
	exit 2
fi
test -x "$BHYVE" || { echo "bhyve not found: $BHYVE" >&2; exit 2; }
test -f "$UEFI" || { echo "UEFI firmware not found: $UEFI" >&2; exit 2; }
mkdir -p "$DIR"

netargs=
if [ -n "$TAP" ]; then
	netargs="-s 4,virtio-net,$TAP"
fi

echo "Launching Alpine with virtio-$TRANSPORT PCI transport"
echo "vsock CID=$CID path=$DIR"
# shellcheck disable=SC2086
exec "$BHYVE" -c 2 -m 2G -H -w \
    -s 0,hostbridge \
    $storage \
    $netargs \
    -s "5,virtio-vsock,cid=$CID,path=$DIR,transport=$TRANSPORT" \
    -s 31,lpc -l "com1,$CONSOLE" -l "bootrom,$UEFI" "$VMNAME"
