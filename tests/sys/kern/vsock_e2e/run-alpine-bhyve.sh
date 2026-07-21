#!/bin/sh
# Launch Alpine with bhyve's virtio-vsock device.  This deliberately does not
# modify the image, ISO, or host networking.
#
# Set exactly one of IMAGE=/path/to/alpine.raw or ISO=/path/to/alpine-virt.iso.
# Optional: TRANSPORT, CID, WORKDIR, DIR, TAP, UEFI, BHYVE, VMNAME, CONSOLE,
# VIRTIO_MSIX, MONITOR, RNG, and BLOCK_IMAGE.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
IMAGE=${IMAGE:-}
ISO=${ISO:-}
TRANSPORT=${TRANSPORT:-modern}
CID=${CID:-4}
WORKDIR=${WORKDIR:-${TMPDIR:-/tmp}/bhyve-virtio-alpine-manual}
DIR=${DIR:-$WORKDIR/vsock}
TAP=${TAP:-tap0}
VMNAME=${VMNAME:-alpine-vsock}
BHYVE=${BHYVE:-}
UEFI=${UEFI:-}
CONSOLE=${CONSOLE:-stdio}
VIRTIO_MSIX=${VIRTIO_MSIX:-yes}
MONITOR=${MONITOR:-no}
RNG=${RNG:-no}
BLOCK_IMAGE=${BLOCK_IMAGE:-}
SRCTOP=${SRCTOP:-$(cd "$here/../../../.." && pwd)}
OBJROOT=${OBJROOT:-/usr/obj}

if [ -z "$BHYVE" ]; then
	object_bhyve="$OBJROOT$SRCTOP/$(uname -p).$(uname -p)/usr.sbin/bhyve/bhyve"
	if [ -x "$object_bhyve" ]; then
		BHYVE=$object_bhyve
	else
		BHYVE=$(command -v bhyve 2>/dev/null || true)
	fi
fi
if [ -z "$UEFI" ]; then
	for candidate in /usr/local/share/uefi-firmware/BHYVE_UEFI.fd \
	    /usr/local/share/edk2-bhyve/BHYVE_UEFI.fd; do
		[ ! -f "$candidate" ] || { UEFI=$candidate; break; }
	done
fi

case "$TRANSPORT" in
modern|legacy) ;;
*) echo "TRANSPORT must be modern or legacy" >&2; exit 2 ;;
esac
for setting in "VIRTIO_MSIX:$VIRTIO_MSIX" "MONITOR:$MONITOR" "RNG:$RNG"; do
	name=${setting%%:*}
	value=${setting#*:}
	case "$value" in yes|no) ;; *) echo "$name must be yes or no" >&2; exit 2;; esac
done
if [ -n "$IMAGE" ] && [ -n "$ISO" ]; then
	echo "set only one of IMAGE or ISO" >&2
	exit 2
elif [ -n "$IMAGE" ]; then
	test -f "$IMAGE" || { echo "IMAGE not found: $IMAGE" >&2; exit 2; }
elif [ -n "$ISO" ]; then
	test -f "$ISO" || { echo "ISO not found: $ISO" >&2; exit 2; }
else
	echo "set IMAGE to a raw disk or ISO to an Alpine virt ISO" >&2
	exit 2
fi
test -x "$BHYVE" || { echo "bhyve not found: $BHYVE" >&2; exit 2; }
test -f "$UEFI" || { echo "UEFI firmware not found: $UEFI" >&2; exit 2; }
if [ -n "$BLOCK_IMAGE" ]; then
	test -f "$BLOCK_IMAGE" || { echo "BLOCK_IMAGE not found: $BLOCK_IMAGE" >&2; exit 2; }
fi
mkdir -p "$DIR"

echo "Launching Alpine with virtio-$TRANSPORT PCI transport"
echo "vsock CID=$CID path=$DIR"
set -- "$BHYVE" -c 2 -m 2G -H -w -s 0,hostbridge
[ "$VIRTIO_MSIX" = yes ] || set -- "$@" -W
[ "$MONITOR" = no ] || set -- "$@" -M
if [ -n "$IMAGE" ]; then
	set -- "$@" -s "3,virtio-blk,$IMAGE"
else
	set -- "$@" -s "3,ahci-cd,$ISO"
fi
[ -z "$TAP" ] || set -- "$@" -s "4,virtio-net,$TAP,transport=$TRANSPORT"
set -- "$@" -s "5,virtio-vsock,cid=$CID,path=$DIR,transport=$TRANSPORT"
[ -z "$BLOCK_IMAGE" ] || set -- "$@" -s "6,virtio-blk,$BLOCK_IMAGE,transport=$TRANSPORT"
[ "$RNG" = no ] || set -- "$@" -s "7,virtio-rnd,transport=$TRANSPORT"
set -- "$@" -s 31,lpc -l "com1,$CONSOLE" -l "bootrom,$UEFI" "$VMNAME"
exec "$@"
