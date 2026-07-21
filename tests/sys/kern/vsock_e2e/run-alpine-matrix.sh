#!/bin/sh
# Full topology/transport matrix.  Keep the single-topology runner small and
# make isolation an explicit part of the acceptance test.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
ISO=${ISO:?set ISO to an Alpine virt ISO}
WORKDIR=${WORKDIR:-/tmp/bhyve-virtio-alpine-matrix}
TRANSPORTS=${TRANSPORTS:-"modern legacy"}
TOPOLOGIES=${TOPOLOGIES:-"vsock rng block input combined"}
VM_FREE_GATES=${VM_FREE_GATES:-yes}

[ "$(id -u)" -eq 0 ] || {
	echo "run-alpine-matrix.sh must run as root" >&2
	exit 1
}
[ ! -L "$WORKDIR" ] || {
	echo "WORKDIR must not be a symbolic link: $WORKDIR" >&2
	exit 1
}
mkdir -p -m 0700 "$WORKDIR"
[ -d "$WORKDIR" ] || { echo "WORKDIR is not a directory: $WORKDIR" >&2; exit 1; }
owner=$(stat -f %u "$WORKDIR")
[ "$owner" -eq 0 ] || {
	echo "WORKDIR must be owned by root: $WORKDIR (uid $owner)" >&2
	exit 1
}
mode=$(stat -f %Lp "$WORKDIR")
[ "$mode" = 700 ] || {
	echo "WORKDIR must have mode 0700: $WORKDIR (mode $mode)" >&2
	exit 1
}

case "$VM_FREE_GATES" in
yes)
	echo "==== VM-free adversarial device harnesses ===="
	srctop=${SRCTOP:-/usr/src}
	device_harness="$srctop/tests/sys/kern/vsock_device_harness/run.sh"
	[ -f "$device_harness" ] || {
		echo "device harness source not found: $device_harness" >&2
		echo "set SRCTOP or use VM_FREE_GATES=no for a VM-only rerun" >&2
		exit 1
	}
	SRCTOP="$srctop" sh "$device_harness"
	echo "==== VM-free host pipeline controls ===="
	if [ -f "$here/Makefile" ]; then
		make -C "$here"
		tools=${TOOLS:-$(make -C "$here" -V .OBJDIR)}
	else
		tools=${TOOLS:-$here}
	fi
	TOOLS="$tools" sh "$here/host-tools-selftest.sh"
	;;
no) ;;
*) echo "VM_FREE_GATES must be yes or no" >&2; exit 2 ;;
esac

for topology in $TOPOLOGIES; do
	case "$topology" in
	vsock|rng|block|input|combined) ;;
	*) echo "invalid topology: $topology" >&2; exit 2 ;;
	esac
	for transport in $TRANSPORTS; do
		case "$transport" in modern|legacy) ;;
		*) echo "invalid transport: $transport" >&2; exit 2 ;;
		esac
		case "$topology:$transport" in
		vsock:*) devices=vsock ;;
		rng:*) devices=rng ;;
		block:*) devices=block ;;
		input:modern) devices=input ;;
		input:legacy)
			echo "==== topology=input transport=legacy: SKIP (historical bhyve interface has no upstream Alpine driver) ===="
			continue
			;;
		combined:modern) devices="vsock rng block input" ;;
		combined:legacy)
			devices="vsock rng block"
			echo "==== topology=combined transport=legacy: historical input omitted (no upstream Alpine driver) ===="
			;;
		esac
		echo "==== topology=$topology transport=$transport devices=$devices ===="
		env ISO="$ISO" TRANSPORTS="$transport" DEVICES="$devices" \
		    WORKDIR="$WORKDIR/$topology" \
		    sh "$here/run-alpine-auto.sh"
	done
done

echo "Alpine topology/transport matrix completed successfully"
