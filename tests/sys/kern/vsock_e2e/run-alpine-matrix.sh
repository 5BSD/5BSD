#!/bin/sh
# Full topology/transport matrix.  Keep the single-topology runner small and
# make isolation an explicit part of the acceptance test.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
ISO=${ISO:?set ISO to an Alpine virt ISO}
WORKDIR=${WORKDIR:-/tmp/bhyve-virtio-alpine-matrix}
TRANSPORTS=${TRANSPORTS:-"modern legacy"}
TOPOLOGIES=${TOPOLOGIES:-"net vsock-userspace vsock-kernel rng balloon rtc block scsi console 9p fs input gpu mem pmem sound iommu combined"}
VM_FREE_GATES=${VM_FREE_GATES:-yes}
NET_PACKED=${NET_PACKED:-no}
RNG_PACKED=${RNG_PACKED:-no}
BALLOON_PACKED=${BALLOON_PACKED:-no}
BALLOON_DEFLATE_ON_OOM=${BALLOON_DEFLATE_ON_OOM:-no}
BALLOON_FREE_PAGE_REPORTING=${BALLOON_FREE_PAGE_REPORTING:-no}
BALLOON_PAGE_POISON=${BALLOON_PAGE_POISON:-no}
RTC_PACKED=${RTC_PACKED:-no}
RTC_ALARM=${RTC_ALARM:-no}
BLOCK_PACKED=${BLOCK_PACKED:-no}
SCSI_PACKED=${SCSI_PACKED:-no}
CONSOLE_PACKED=${CONSOLE_PACKED:-no}
INPUT_PACKED=${INPUT_PACKED:-no}
NINEP_PACKED=${NINEP_PACKED:-no}
FS_PACKED=${FS_PACKED:-no}
FS_QUEUES=${FS_QUEUES:-2}
VSOCK_PACKED=${VSOCK_PACKED:-no}
GPU_PACKED=${GPU_PACKED:-no}
GPU_BLOB=${GPU_BLOB:-no}
GPU_WIDTH=${GPU_WIDTH:-1024}
GPU_HEIGHT=${GPU_HEIGHT:-768}
MEM_PACKED=${MEM_PACKED:-no}
PMEM_PACKED=${PMEM_PACKED:-no}
SOUND_PACKED=${SOUND_PACKED:-no}
IOMMU_PACKED=${IOMMU_PACKED:-no}
reset_test_default=${RESET_TEST:-no}
reboot_test_default=${REBOOT_TEST:-no}
reset_soak_iterations=${VIRTIO_RESET_SOAK_ITERATIONS:-0}

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

for transport in $TRANSPORTS; do
	case "$transport" in
	modern|legacy) ;;
	*) echo "invalid transport: $transport" >&2; exit 2 ;;
	esac
done
for topology in $TOPOLOGIES; do
	case "$topology" in
	net|vsock-userspace|vsock-kernel|rng|balloon|rtc|block|scsi|console|9p|fs|input|gpu|mem|pmem|sound|iommu|combined) ;;
	*) echo "invalid topology: $topology" >&2; exit 2 ;;
	esac
done
case "$reset_soak_iterations" in
''|*[!0-9]*)
	echo "VIRTIO_RESET_SOAK_ITERATIONS must be a non-negative integer" >&2
	exit 2
	;;
esac
case "$reset_test_default:$reboot_test_default" in
yes:yes|yes:no|no:yes|no:no) ;;
*) echo "RESET_TEST and REBOOT_TEST must be yes or no" >&2; exit 2 ;;
esac
case "$RNG_PACKED" in
yes|no) ;;
*) echo "RNG_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$NET_PACKED" in
yes|no) ;;
*) echo "NET_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$BALLOON_PACKED" in
yes|no) ;;
*) echo "BALLOON_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$BALLOON_DEFLATE_ON_OOM" in
yes|no) ;;
*) echo "BALLOON_DEFLATE_ON_OOM must be yes or no" >&2; exit 2 ;;
esac
case "$BALLOON_FREE_PAGE_REPORTING" in
yes|no) ;;
*) echo "BALLOON_FREE_PAGE_REPORTING must be yes or no" >&2; exit 2 ;;
esac
case "$BALLOON_PAGE_POISON" in
yes|no) ;;
*) echo "BALLOON_PAGE_POISON must be yes or no" >&2; exit 2 ;;
esac
case "$RTC_PACKED" in
yes|no) ;;
*) echo "RTC_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$RTC_ALARM" in
yes|no) ;;
*) echo "RTC_ALARM must be yes or no" >&2; exit 2 ;;
esac
case "$BLOCK_PACKED" in
yes|no) ;;
*) echo "BLOCK_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$SCSI_PACKED" in
yes|no) ;;
*) echo "SCSI_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$CONSOLE_PACKED" in
yes|no) ;;
*) echo "CONSOLE_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$INPUT_PACKED" in
yes|no) ;;
*) echo "INPUT_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$NINEP_PACKED" in
yes|no) ;;
*) echo "NINEP_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$FS_PACKED" in
yes|no) ;;
*) echo "FS_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$VSOCK_PACKED" in
yes|no) ;;
*) echo "VSOCK_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$GPU_PACKED" in
yes|no) ;;
*) echo "GPU_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$GPU_BLOB" in
yes|no) ;;
*) echo "GPU_BLOB must be yes or no" >&2; exit 2 ;;
esac
case "$GPU_WIDTH:$GPU_HEIGHT" in
*[!0-9:]*|0:*|*:0|:*|*:) echo "GPU_WIDTH and GPU_HEIGHT must be positive decimal integers" >&2; exit 2 ;;
esac
case "$MEM_PACKED" in
yes|no) ;;
*) echo "MEM_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$PMEM_PACKED" in
yes|no) ;;
*) echo "PMEM_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$SOUND_PACKED" in
yes|no) ;;
*) echo "SOUND_PACKED must be yes or no" >&2; exit 2 ;;
esac
if { [ "$reset_test_default" = yes ] ||
    [ "$reboot_test_default" = yes ] ||
    [ "$reset_soak_iterations" -gt 0 ]; } &&
    case " $TRANSPORTS " in *" modern "*) true ;; *) false ;; esac; then
	for topology in $TOPOLOGIES; do
		case "$topology" in
		input|combined)
			echo "modern reset/reboot lifecycle runs cannot include " \
			    "topology=$topology because its input provider is " \
			    "one-shot; select explicit reset-capable topologies" >&2
			exit 2
			;;
		esac
	done
fi

case "$VM_FREE_GATES" in
yes)
	echo "==== VM-free boundary and lifecycle device harnesses ===="
	srctop=${SRCTOP:-/usr/src}
	device_harness="$srctop/tests/sys/kern/vsock_device_harness/run.sh"
	[ -f "$device_harness" ] || {
		echo "device harness source not found: $device_harness" >&2
		echo "set SRCTOP or use VM_FREE_GATES=no for a VM-only rerun" >&2
		exit 1
	}
	rx_harness="$srctop/tests/sys/kern/vsock_rx_harness/run.sh"
	[ -f "$rx_harness" ] || {
		echo "RX harness source not found: $rx_harness" >&2
		echo "set SRCTOP or use VM_FREE_GATES=no for a VM-only rerun" >&2
		exit 1
	}
	SRCTOP="$srctop" sh "$device_harness"
	SRCTOP="$srctop" sh "$rx_harness"
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
	for transport in $TRANSPORTS; do
		backend=userspace
		iommu=no
		reset_test=$reset_test_default
		reboot_test=$reboot_test_default
		case "$topology:$transport" in
		net:*) devices=net ;;
		vsock-userspace:*) devices=vsock ;;
		vsock-kernel:*)
			devices=vsock
			backend=kernel
			# Exercise VSOCK_IOC_TRANSPORT_RESET on driver reset and
			# provider detach/re-attach across monitor-mode reboot.
			reset_test=yes
			reboot_test=yes
			;;
		rng:*) devices=rng ;;
		balloon:modern) devices=balloon ;;
		balloon:legacy)
			echo "==== topology=balloon transport=legacy: SKIP (modern-only device) ===="
			continue
			;;
		rtc:modern) devices=rtc ;;
		rtc:legacy)
			echo "==== topology=rtc transport=legacy: SKIP (modern-only device) ===="
			continue
			;;
		block:*) devices=block ;;
		scsi:*) devices=scsi ;;
		console:*) devices=console ;;
		9p:*) devices=9p ;;
		fs:modern) devices=fs ;;
		fs:legacy)
			echo "==== topology=fs transport=legacy: SKIP (modern-only device) ===="
			continue
			;;
		input:modern) devices=input ;;
		input:legacy)
			echo "==== topology=input transport=legacy: SKIP (VirtIO 1.4 defines no transitional input device) ===="
			continue
			;;
		gpu:modern) devices=gpu ;;
		gpu:legacy)
			echo "==== topology=gpu transport=legacy: SKIP (modern-only device) ===="
			continue
			;;
		mem:modern) devices=mem ;;
		mem:legacy)
			echo "==== topology=mem transport=legacy: SKIP (modern-only device) ===="
			continue
			;;
		pmem:modern) devices=pmem ;;
		pmem:legacy)
			echo "==== topology=pmem transport=legacy: SKIP (modern-only device) ===="
			continue
			;;
		sound:modern) devices=sound ;;
		sound:legacy)
			echo "==== topology=sound transport=legacy: SKIP (modern-only device) ===="
			continue
			;;
		iommu:modern)
			devices="net block"
			iommu=yes
			;;
		iommu:legacy)
			echo "==== topology=iommu transport=legacy: SKIP (modern-only device) ===="
			continue
			;;
		combined:modern) devices="net vsock rng balloon rtc block scsi console 9p fs input gpu mem pmem sound" ;;
		combined:legacy)
			devices="net vsock rng block scsi console 9p"
			echo "==== topology=combined transport=legacy: input omitted (no VirtIO 1.4 transitional identity) ===="
			;;
		esac
		echo "==== topology=$topology transport=$transport backend=$backend devices=$devices ===="
		env ISO="$ISO" TRANSPORTS="$transport" DEVICES="$devices" \
		    VSOCK_BACKEND="$backend" RESET_TEST="$reset_test" \
		    REBOOT_TEST="$reboot_test" RNG_PACKED="$RNG_PACKED" \
		    NET_PACKED="$NET_PACKED" \
		    BALLOON_PACKED="$BALLOON_PACKED" \
		    BALLOON_DEFLATE_ON_OOM="$BALLOON_DEFLATE_ON_OOM" \
		    BALLOON_FREE_PAGE_REPORTING="$BALLOON_FREE_PAGE_REPORTING" \
		    BALLOON_PAGE_POISON="$BALLOON_PAGE_POISON" \
		    RTC_PACKED="$RTC_PACKED" \
		    RTC_ALARM="$RTC_ALARM" \
		    BLOCK_PACKED="$BLOCK_PACKED" \
		    SCSI_PACKED="$SCSI_PACKED" \
		    CONSOLE_PACKED="$CONSOLE_PACKED" \
		    INPUT_PACKED="$INPUT_PACKED" \
		    NINEP_PACKED="$NINEP_PACKED" \
		    FS_PACKED="$FS_PACKED" FS_QUEUES="$FS_QUEUES" \
		    VSOCK_PACKED="$VSOCK_PACKED" \
		    GPU_PACKED="$GPU_PACKED" \
		    GPU_BLOB="$GPU_BLOB" \
		    GPU_WIDTH="$GPU_WIDTH" GPU_HEIGHT="$GPU_HEIGHT" \
		    MEM_PACKED="$MEM_PACKED" \
		    PMEM_PACKED="$PMEM_PACKED" \
		    SOUND_PACKED="$SOUND_PACKED" \
		    VIRTIO_IOMMU="$iommu" IOMMU_PACKED="$IOMMU_PACKED" \
		    WORKDIR="$WORKDIR/$topology" \
		    sh "$here/run-alpine-auto.sh"
	done
done

echo "Alpine topology/transport matrix completed successfully"
