#!/bin/sh
# Root-only, disposable Alpine ISO test: boot, provision over the serial
# console, and run the requested transport test.
set -eu

# Release-ledger anchors for state checks made after a live restore.
# VIRTIO_ACTIVATION_ASSERTION: checkpoint-and-post-restore-bidirectional-vsock
# VIRTIO_ACTIVATION_ASSERTION: checkpoint-and-post-restore-stream-and-seqpacket-vsock
# VIRTIO_ACTIVATION_ASSERTION: active-vsock-checkpoint-reject-rollback
# VIRTIO_ACTIVATION_ASSERTION: active-console-checkpoint-reject-rollback
# VIRTIO_ACTIVATION_ASSERTION: two-input-providers-isolated
# VIRTIO_ACTIVATION_ASSERTION: checkpoint-and-post-restore-digest
# VIRTIO_ACTIVATION_ASSERTION: checkpoint-and-post-restore-network-traffic
# VIRTIO_ACTIVATION_ASSERTION: two-named-console-ports-bidirectional
# VIRTIO_ACTIVATION_ASSERTION: notification-data-doorbell-payload
# VIRTIO_ACTIVATION_ASSERTION: active-checkpoint-balloon-statistics
# VIRTIO_ACTIVATION_ASSERTION: active-checkpoint-virtio-mem-pages
# VIRTIO_ACTIVATION_ASSERTION: active-checkpoint-sound-host-progress
# VIRTIO_ACTIVATION_ASSERTION: pmem-shared-region-flush-host-backing
# VIRTIO_ACTIVATION_ASSERTION: checkpoint-and-post-restore-pmem-marker

here=$(cd "$(dirname "$0")" && pwd)
. "$here/virtio-ring-trace.sh"
ISO=${ISO:?set ISO to an Alpine virt ISO}
BHYVE=${BHYVE:-}
BHYVECTL=${BHYVECTL:-}
VIRTIOFSD=${VIRTIOFSD:-}
UEFI=${UEFI:-}
SRCTOP=${SRCTOP:-$(cd "$here/../../../.." && pwd)}
OBJROOT=${OBJROOT:-/usr/obj}
WORKDIR=${WORKDIR:-/tmp/bhyve-vsock-alpine}
TRANSPORTS=${TRANSPORTS:-modern}
DEVICES=${DEVICES:-"vsock rng input"}
VSOCK_BACKEND=${VSOCK_BACKEND:-userspace}
CID=${CID:-4}
PORT_OFFSET=${PORT_OFFSET:-0}
# The churn matrix reserves four disjoint ranges of up to 64 endpoints.  Keep
# the offset validation synchronized with its highest possible endpoint.
VSOCK_TEST_MAX_BASE_PORT=7474
VSOCK_BARRIER_DIR=${VSOCK_BARRIER_DIR:-}
VSOCK_BARRIER_CIDS=${VSOCK_BARRIER_CIDS:-}
CONSOLE_PORT=${CONSOLE_PORT:-}
CONSOLE_MULTIPORT=${CONSOLE_MULTIPORT:-no}
CHECKPOINT_ACTIVE_9P_REJECT=${CHECKPOINT_ACTIVE_9P_REJECT:-no}
CHECKPOINT_ACTIVE_FS=${CHECKPOINT_ACTIVE_FS:-no}
CHECKPOINT_ACTIVE_VSOCK_REJECT=${CHECKPOINT_ACTIVE_VSOCK_REJECT:-no}
CHECKPOINT_ACTIVE_CONSOLE_REJECT=${CHECKPOINT_ACTIVE_CONSOLE_REJECT:-no}
CHECKPOINT_ACTIVE_MEM=${CHECKPOINT_ACTIVE_MEM:-no}
KEEP_VM=${KEEP_VM:-no}
# VSOCK_DEBUG is the harness-facing spelling.  Also honor bhyve's direct
# environment name so an operator's direct BHYVE_VTVSOCK_DEBUG setting is not
# silently overwritten by the harness default.
VSOCK_DEBUG=${VSOCK_DEBUG:-${BHYVE_VTVSOCK_DEBUG:-1}}
VIRTIO_DEBUG=${VIRTIO_DEBUG:-${BHYVE_VIRTIO_DEBUG:-0}}
INPUT_DEBUG=${INPUT_DEBUG:-1}
INPUT_DEVICES=${INPUT_DEVICES:-1}
SCSI_DEBUG=${SCSI_DEBUG:-1}
VIRTIO_MSIX=${VIRTIO_MSIX:-yes}
NET_PACKED=${NET_PACKED:-no}
RNG_PACKED=${RNG_PACKED:-no}
BALLOON_PACKED=${BALLOON_PACKED:-no}
BALLOON_STATS_INTERVAL=${BALLOON_STATS_INTERVAL:-0}
BALLOON_DEFLATE_ON_OOM=${BALLOON_DEFLATE_ON_OOM:-no}
BALLOON_FREE_PAGE_HINTING=${BALLOON_FREE_PAGE_HINTING:-no}
BALLOON_FREE_PAGE_REPORTING=${BALLOON_FREE_PAGE_REPORTING:-no}
BALLOON_PAGE_POISON=${BALLOON_PAGE_POISON:-no}
RTC_PACKED=${RTC_PACKED:-no}
RTC_ALARM=${RTC_ALARM:-no}
RTC_CHECKPOINT_ALARM_SECONDS=${RTC_CHECKPOINT_ALARM_SECONDS:-20}
BLOCK_PACKED=${BLOCK_PACKED:-no}
BLOCK_READONLY=${BLOCK_READONLY:-no}
BLOCK_DISCARD=${BLOCK_DISCARD:-no}
VERIFY_NOTIFICATION_DATA=${VERIFY_NOTIFICATION_DATA:-no}
VERIFY_RING_ACTIVITY=${VERIFY_RING_ACTIVITY:-no}
VERIFY_GPU_BLOB_ACTIVITY=${VERIFY_GPU_BLOB_ACTIVITY:-no}
VERIFY_DEVICE_RING_NAME=${VERIFY_DEVICE_RING_NAME:-}
VERIFY_DEVICE_RING_LAYOUT=${VERIFY_DEVICE_RING_LAYOUT:-}
SCSI_PACKED=${SCSI_PACKED:-no}
SCSI_EVENTS=${SCSI_EVENTS:-no}
CONSOLE_PACKED=${CONSOLE_PACKED:-no}
INPUT_PACKED=${INPUT_PACKED:-no}
NINEP_PACKED=${NINEP_PACKED:-no}
FS_PACKED=${FS_PACKED:-no}
FS_QUEUES=${FS_QUEUES:-2}
FS_IDENTITY=${FS_IDENTITY:-}
VSOCK_PACKED=${VSOCK_PACKED:-no}
GPU_PACKED=${GPU_PACKED:-no}
GPU_BLOB=${GPU_BLOB:-no}
GPU_DISPLAY=${GPU_DISPLAY:-no}
GPU_WIDTH=${GPU_WIDTH:-1024}
GPU_HEIGHT=${GPU_HEIGHT:-768}
MEM_PACKED=${MEM_PACKED:-no}
PMEM_PACKED=${PMEM_PACKED:-no}
PMEM_IMAGE_MB=${PMEM_IMAGE_MB:-64}
PMEM_IDENTITY=${PMEM_IDENTITY:-waspnest-pmem}
SOUND_PACKED=${SOUND_PACKED:-no}
SOUND_BACKEND=${SOUND_BACKEND:-null}
SOUND_PLAY=${SOUND_PLAY:-/dev/dsp}
SOUND_RECORD=${SOUND_RECORD:-/dev/dsp}
MEM_REGION_MB=${MEM_REGION_MB:-256}
MEM_REQUESTED_MB=${MEM_REQUESTED_MB:-128}
MEM_CHECKPOINT_ALLOC_MB=${MEM_CHECKPOINT_ALLOC_MB:-0}
VM_MEMORY_MB=${VM_MEMORY_MB:-2048}
VIRTIO_IOMMU=${VIRTIO_IOMMU:-no}
IOMMU_PACKED=${IOMMU_PACKED:-no}
case "$VIRTIO_DEBUG" in
''|*[!0-9]*) echo "VIRTIO_DEBUG must be a non-negative integer" >&2; exit 2 ;;
esac
BALLOON_TARGET_MB=${BALLOON_TARGET_MB:-64}
RESET_TEST=${RESET_TEST:-no}
REBOOT_TEST=${REBOOT_TEST:-no}
CHECKPOINT_TEST=${CHECKPOINT_TEST:-no}
CHECKPOINT_NEGATIVE_QUEUE_RESTORE=${CHECKPOINT_NEGATIVE_QUEUE_RESTORE:-no}
CHECKPOINT_NEGATIVE_FEATURE_RESTORE=${CHECKPOINT_NEGATIVE_FEATURE_RESTORE:-no}
CHECKPOINT_NEGATIVE_PMEM_RESTORE=${CHECKPOINT_NEGATIVE_PMEM_RESTORE:-no}
CHECKPOINT_REPEAT_PMEM_RESTORE=${CHECKPOINT_REPEAT_PMEM_RESTORE:-no}
CHECKPOINT_REPEAT_FS_RESTORE=${CHECKPOINT_REPEAT_FS_RESTORE:-no}
BLOCK_TEST_MB=${BLOCK_TEST_MB:-256}
BLOCK_IMAGE_MB=${BLOCK_IMAGE_MB:-1024}
BLOCK_QUEUES=${BLOCK_QUEUES:-2}
NET_QUEUES=${NET_QUEUES:-2}
SCSI_TEST_MB=${SCSI_TEST_MB:-32}
SCSI_IMAGE_MB=${SCSI_IMAGE_MB:-128}
SCSI_QUEUES=${SCSI_QUEUES:-2}
VSOCK_SOAK_ITERATIONS=${VSOCK_SOAK_ITERATIONS:-0}
VSOCK_SOAK_CONNECTIONS=${VSOCK_SOAK_CONNECTIONS:-8}
VSOCK_SOAK_RESET_EVERY=${VSOCK_SOAK_RESET_EVERY:-10}
VSOCK_SOAK_MAX_FD_GROWTH=${VSOCK_SOAK_MAX_FD_GROWTH:-0}
VSOCK_SOAK_MAX_RSS_KB=${VSOCK_SOAK_MAX_RSS_KB:-16384}
VIRTIO_RESET_SOAK_ITERATIONS=${VIRTIO_RESET_SOAK_ITERATIONS:-0}
VIRTIO_RESET_SOAK_VERIFY_EVERY=${VIRTIO_RESET_SOAK_VERIFY_EVERY:-10}
VIRTIO_RESET_SOAK_MAX_FD_GROWTH=${VIRTIO_RESET_SOAK_MAX_FD_GROWTH:-0}
VIRTIO_RESET_SOAK_MAX_RSS_KB=${VIRTIO_RESET_SOAK_MAX_RSS_KB:-16384}
BRIDGE=${BRIDGE:-bridge0}
UPLINK=${UPLINK:-}
NONVIRTIO_DEVICE=${NONVIRTIO_DEVICE:-none}
NONVIRTIO_IMAGE_MB=${NONVIRTIO_IMAGE_MB:-128}
NONVIRTIO_HDA_PLAY=${NONVIRTIO_HDA_PLAY:-/dev/dsp0}
NONVIRTIO_HDA_RECORD=${NONVIRTIO_HDA_RECORD:-/dev/dsp1}
NONVIRTIO_TPM_TYPE=${NONVIRTIO_TPM_TYPE:-swtpm}
NONVIRTIO_TPM_PATH=${NONVIRTIO_TPM_PATH:-}
NONVIRTIO_PASSTHRU=${NONVIRTIO_PASSTHRU:-}
NONVIRTIO_PASSTHRU_GUEST_ASSERT=${NONVIRTIO_PASSTHRU_GUEST_ASSERT:-}
NONVIRTIO_PASSTHRU_LINUX_ASSERT=${NONVIRTIO_PASSTHRU_LINUX_ASSERT:-$NONVIRTIO_PASSTHRU_GUEST_ASSERT}
NONVIRTIO_FWCFG_NAME=opt/waspnest/checkpoint
NONVIRTIO_FWCFG_VALUE=WASPNEST-FWCFG-CURSOR-0123456789ABCDEF

case "$NONVIRTIO_DEVICE" in
none|ahci|nvme|e82545|hda|xhci|fbuf|pci-uart|lpc-uart|tpm-crb|pvpanic|i6300esb|hostbridge|passthru|qemu-fwcfg) ;;
*) echo "unknown NONVIRTIO_DEVICE: $NONVIRTIO_DEVICE" >&2; exit 2 ;;
esac
case "$NONVIRTIO_IMAGE_MB" in
''|*[!0-9]*|0) echo "NONVIRTIO_IMAGE_MB must be positive" >&2; exit 2 ;;
esac
case "$NONVIRTIO_TPM_TYPE" in passthru|swtpm) ;; *) echo "invalid NONVIRTIO_TPM_TYPE" >&2; exit 2 ;; esac
[ "$NONVIRTIO_DEVICE" != tpm-crb ] || [ -n "$NONVIRTIO_TPM_PATH" ] || {
	echo "tpm-crb requires NONVIRTIO_TPM_PATH" >&2
	exit 2
}
[ "$NONVIRTIO_DEVICE" != passthru ] || {
	[ -n "$NONVIRTIO_PASSTHRU" ] && [ -n "$NONVIRTIO_PASSTHRU_LINUX_ASSERT" ] || {
		echo "passthru requires NONVIRTIO_PASSTHRU and NONVIRTIO_PASSTHRU_LINUX_ASSERT" >&2
		exit 2
	}
}

if [ -z "$BHYVE" ]; then
	object_bhyve="$OBJROOT$SRCTOP/$(uname -p).$(uname -p)/usr.sbin/bhyve/bhyve"
	if [ -x "$object_bhyve" ]; then
		BHYVE=$object_bhyve
	else
		BHYVE=$(command -v bhyve 2>/dev/null || true)
	fi
fi
if [ -z "$UEFI" ]; then
	for candidate in \
	    /usr/local/share/uefi-firmware/BHYVE_UEFI.fd \
	    /usr/local/share/edk2-bhyve/BHYVE_UEFI.fd; do
		if [ -f "$candidate" ]; then
			UEFI=$candidate
			break
		fi
	done
fi
if [ -z "$BHYVECTL" ]; then
	object_bhyvectl="$OBJROOT$SRCTOP/$(uname -p).$(uname -p)/usr.sbin/bhyvectl/bhyvectl"
	if [ -x "$object_bhyvectl" ]; then
		BHYVECTL=$object_bhyvectl
	else
		BHYVECTL=$(command -v bhyvectl 2>/dev/null || true)
	fi
fi
if [ -z "$VIRTIOFSD" ]; then
	object_virtiofsd="$OBJROOT$SRCTOP/$(uname -p).$(uname -p)/usr.sbin/virtiofsd/virtiofsd"
	if [ -x "$object_virtiofsd" ]; then
		VIRTIOFSD=$object_virtiofsd
	else
		VIRTIOFSD=$(command -v virtiofsd 2>/dev/null || true)
	fi
fi

[ "$(id -u)" -eq 0 ] || { echo "run-alpine-auto.sh must run as root" >&2; exit 1; }
[ -f "$ISO" ] || { echo "ISO not found: $ISO" >&2; exit 1; }
[ -x "$BHYVE" ] || { echo "bhyve not found: $BHYVE" >&2; exit 1; }
[ "$CHECKPOINT_TEST" = no ] || [ -x "$BHYVECTL" ] || {
	echo "CHECKPOINT_TEST requires bhyvectl" >&2
	exit 1
}
if [ "$CHECKPOINT_TEST" = yes ]; then
	"$BHYVE" -h 2>&1 | grep -q -- '-r: path to checkpoint file' || {
		echo "CHECKPOINT_TEST requires a snapshot-enabled bhyve" >&2
		exit 1
	}
	checkpoint_usage=$("$BHYVECTL" --help 2>&1 || true)
	printf '%s\n' "$checkpoint_usage" | grep -q -- '--checkpoint=<filename>' || {
		echo "CHECKPOINT_TEST requires a snapshot-enabled bhyvectl" >&2
		exit 1
	}
	sysctl -n kern.conftxt 2>/dev/null |
	    grep -Eq '^options[[:space:]]+BHYVE_SNAPSHOT([[:space:]]|$)' || {
		echo "CHECKPOINT_TEST requires a kernel built with BHYVE_SNAPSHOT" >&2
		exit 1
	}
fi
[ -f "$UEFI" ] || { echo "UEFI firmware not found: $UEFI" >&2; exit 1; }
echo "BHYVE path=$BHYVE sha256=$(sha256 -q "$BHYVE")"
echo "HOST kernel=$(uname -K) userland=$(uname -U)"
case "$VSOCK_BACKEND" in
userspace|kernel) ;;
*) echo "VSOCK_BACKEND must be userspace or kernel" >&2; exit 2 ;;
esac
case "$NET_PACKED" in
yes|no) ;;
*) echo "NET_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$RNG_PACKED" in
yes|no) ;;
*) echo "RNG_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$BALLOON_PACKED" in
yes|no) ;;
*) echo "BALLOON_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$BALLOON_STATS_INTERVAL" in
''|*[!0-9]*) echo "BALLOON_STATS_INTERVAL must be an integer" >&2; exit 2 ;;
esac
[ "$BALLOON_STATS_INTERVAL" -le 3600 ] || {
	echo "BALLOON_STATS_INTERVAL must be in [0, 3600]" >&2
	exit 2
}
balloon_stats_opt=
if [ "$BALLOON_STATS_INTERVAL" -ne 0 ]; then
	balloon_stats_opt=",stats_interval=$BALLOON_STATS_INTERVAL"
	[ "$VIRTIO_DEBUG" -ge 2 ] || VIRTIO_DEBUG=2
fi
case "$BALLOON_DEFLATE_ON_OOM" in
yes) balloon_deflate_on_oom_opt=",deflate_on_oom=true" ;;
no) balloon_deflate_on_oom_opt= ;;
*) echo "BALLOON_DEFLATE_ON_OOM must be yes or no" >&2; exit 2 ;;
esac
case "$BALLOON_FREE_PAGE_HINTING" in
yes)
	balloon_hinting_opt=",free_page_hinting=true"
	[ "$VIRTIO_DEBUG" -ge 1 ] || VIRTIO_DEBUG=1
	;;
no) balloon_hinting_opt= ;;
*) echo "BALLOON_FREE_PAGE_HINTING must be yes or no" >&2; exit 2 ;;
esac
case "$BALLOON_FREE_PAGE_REPORTING" in
yes)
	balloon_reporting_opt=",free_page_reporting=true"
	[ "$VIRTIO_DEBUG" -ge 1 ] || VIRTIO_DEBUG=1
	;;
no) balloon_reporting_opt= ;;
*) echo "BALLOON_FREE_PAGE_REPORTING must be yes or no" >&2; exit 2 ;;
esac
case "$BALLOON_PAGE_POISON" in
yes) balloon_page_poison_opt=",page_poison=true" ;;
no) balloon_page_poison_opt= ;;
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
case "$RTC_CHECKPOINT_ALARM_SECONDS" in
''|*[!0-9]*) echo "RTC_CHECKPOINT_ALARM_SECONDS must be numeric" >&2; exit 2 ;;
esac
if [ "$RTC_CHECKPOINT_ALARM_SECONDS" -lt 5 ] ||
    [ "$RTC_CHECKPOINT_ALARM_SECONDS" -gt 120 ]; then
	echo "RTC_CHECKPOINT_ALARM_SECONDS must be between 5 and 120" >&2
	exit 2
fi
case "$BLOCK_PACKED" in
yes|no) ;;
*) echo "BLOCK_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$PMEM_PACKED" in
yes|no) ;;
*) echo "PMEM_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$PMEM_IMAGE_MB" in
''|*[!0-9]*|0) echo "PMEM_IMAGE_MB must be a positive integer" >&2; exit 2 ;;
esac
[ "$PMEM_IMAGE_MB" -ge 4 ] || {
	echo "PMEM_IMAGE_MB must be at least 4" >&2
	exit 2
}
case "$PMEM_IDENTITY" in
''|*[!A-Za-z0-9_.-]*) echo "PMEM_IDENTITY contains unsafe characters" >&2; exit 2 ;;
esac
case "$BLOCK_READONLY" in
yes|no) ;;
*) echo "BLOCK_READONLY must be yes or no" >&2; exit 2 ;;
esac
case "$BLOCK_DISCARD" in
yes|no) ;;
*) echo "BLOCK_DISCARD must be yes or no" >&2; exit 2 ;;
esac
case "$VERIFY_NOTIFICATION_DATA" in
yes|no) ;;
*) echo "VERIFY_NOTIFICATION_DATA must be yes or no" >&2; exit 2 ;;
esac
case "$VERIFY_RING_ACTIVITY" in
yes|no) ;;
*) echo "VERIFY_RING_ACTIVITY must be yes or no" >&2; exit 2 ;;
esac
if [ "$VERIFY_RING_ACTIVITY" = yes ]; then
	[ "$TRANSPORTS" = modern ] || {
		echo "VERIFY_RING_ACTIVITY=yes requires TRANSPORTS=modern" >&2
		exit 2
	}
fi
[ "$BLOCK_READONLY:$BLOCK_DISCARD" != yes:yes ] || {
	echo "BLOCK_READONLY=yes conflicts with BLOCK_DISCARD=yes" >&2
	exit 2
}
case "$SCSI_PACKED" in
yes|no) ;;
*) echo "SCSI_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$SCSI_EVENTS" in
yes|no) ;;
*) echo "SCSI_EVENTS must be yes or no" >&2; exit 2 ;;
esac
case "$CONSOLE_PACKED" in
yes|no) ;;
*) echo "CONSOLE_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$CONSOLE_MULTIPORT" in
yes|no) ;;
*) echo "CONSOLE_MULTIPORT must be yes or no" >&2; exit 2 ;;
esac
case "$CHECKPOINT_ACTIVE_9P_REJECT" in
yes|no) ;;
*) echo "CHECKPOINT_ACTIVE_9P_REJECT must be yes or no" >&2; exit 2 ;;
esac
case "$CHECKPOINT_ACTIVE_FS" in
yes|no) ;;
*) echo "CHECKPOINT_ACTIVE_FS must be yes or no" >&2; exit 2 ;;
esac
case "$CHECKPOINT_ACTIVE_VSOCK_REJECT" in
yes|no) ;;
*) echo "CHECKPOINT_ACTIVE_VSOCK_REJECT must be yes or no" >&2; exit 2 ;;
esac
case "$CHECKPOINT_ACTIVE_CONSOLE_REJECT" in
yes|no) ;;
*) echo "CHECKPOINT_ACTIVE_CONSOLE_REJECT must be yes or no" >&2; exit 2 ;;
esac
case "$CHECKPOINT_NEGATIVE_QUEUE_RESTORE" in
yes|no) ;;
*) echo "CHECKPOINT_NEGATIVE_QUEUE_RESTORE must be yes or no" >&2; exit 2 ;;
esac
case "$CHECKPOINT_NEGATIVE_FEATURE_RESTORE" in
yes|no) ;;
*) echo "CHECKPOINT_NEGATIVE_FEATURE_RESTORE must be yes or no" >&2; exit 2 ;;
esac
case "$CHECKPOINT_NEGATIVE_PMEM_RESTORE" in
yes|no) ;;
*) echo "CHECKPOINT_NEGATIVE_PMEM_RESTORE must be yes or no" >&2; exit 2 ;;
esac
case "$CHECKPOINT_REPEAT_PMEM_RESTORE" in
yes|no) ;;
*) echo "CHECKPOINT_REPEAT_PMEM_RESTORE must be yes or no" >&2; exit 2 ;;
esac
case "$CHECKPOINT_REPEAT_FS_RESTORE" in
yes|no) ;;
*) echo "CHECKPOINT_REPEAT_FS_RESTORE must be yes or no" >&2; exit 2 ;;
esac
case "$CHECKPOINT_ACTIVE_MEM" in
yes|no) ;;
*) echo "CHECKPOINT_ACTIVE_MEM must be yes or no" >&2; exit 2 ;;
esac
case "$INPUT_PACKED" in
yes|no) ;;
*) echo "INPUT_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$INPUT_DEVICES" in
1|2) ;;
*) echo "INPUT_DEVICES must be 1 or 2" >&2; exit 2 ;;
esac
case "$NINEP_PACKED" in
yes|no) ;;
*) echo "NINEP_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$FS_PACKED" in
yes|no) ;;
*) echo "FS_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$FS_QUEUES" in
''|*[!0-9]*) echo "FS_QUEUES must be an integer in [1, 64]" >&2; exit 2 ;;
esac
[ "$FS_QUEUES" -ge 1 ] && [ "$FS_QUEUES" -le 64 ] || {
	echo "FS_QUEUES must be an integer in [1, 64]" >&2
	exit 2
}
case "$FS_IDENTITY" in
*[!A-Za-z0-9._:-]*)
	echo "FS_IDENTITY contains an unsupported character" >&2
	exit 2
	;;
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
case "$GPU_DISPLAY" in
yes|no) ;;
*) echo "GPU_DISPLAY must be yes or no" >&2; exit 2 ;;
esac
case "$GPU_WIDTH:$GPU_HEIGHT" in
*[!0-9:]*|0:*|*:0|:*|*:) echo "GPU_WIDTH and GPU_HEIGHT must be positive decimal integers" >&2; exit 2 ;;
esac
case "$MEM_PACKED" in
yes|no) ;;
*) echo "MEM_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$SOUND_PACKED" in
yes|no) ;;
*) echo "SOUND_PACKED must be yes or no" >&2; exit 2 ;;
esac
case "$SOUND_BACKEND" in
null)
	sound_backend_opt=
	;;
oss)
	case "$SOUND_PLAY:$SOUND_RECORD" in
	:*|*:|*[,]*) echo "SOUND_PLAY and SOUND_RECORD must be nonempty paths without commas" >&2; exit 2 ;;
	esac
	sound_backend_opt=",play=$SOUND_PLAY,record=$SOUND_RECORD"
	;;
*) echo "SOUND_BACKEND must be null or oss" >&2; exit 2 ;;
esac
for memory_size in "$MEM_REGION_MB" "$MEM_REQUESTED_MB" \
    "$MEM_CHECKPOINT_ALLOC_MB" "$VM_MEMORY_MB"; do
	case "$memory_size" in
	''|*[!0-9]*)
		echo "memory sizes must be non-negative decimal integers" >&2
		exit 2
		;;
	esac
done
[ "$MEM_REGION_MB" -gt 0 ] &&
    [ "$MEM_REQUESTED_MB" -gt 0 ] &&
    [ "$MEM_REQUESTED_MB" -le "$MEM_REGION_MB" ] || {
	echo "require 0 < MEM_REQUESTED_MB <= MEM_REGION_MB" >&2
	exit 2
}
mem_requested_bytes=$((MEM_REQUESTED_MB * 1024 * 1024))
[ "$VM_MEMORY_MB" -gt 0 ] || {
	echo "VM_MEMORY_MB must be positive" >&2
	exit 2
}

# Packed-ring qualification requires host-side proof that the queue was
# actually mapped and used as packed.  Enable the common modern trace
# automatically for packed cases instead of relying on a feature bit alone.
for packed_setting in "$NET_PACKED" "$RNG_PACKED" "$BALLOON_PACKED" \
    "$RTC_PACKED" "$BLOCK_PACKED" "$SCSI_PACKED" "$CONSOLE_PACKED" \
    "$INPUT_PACKED" "$NINEP_PACKED" "$VSOCK_PACKED" "$GPU_PACKED" \
    "$MEM_PACKED" "$SOUND_PACKED" "$IOMMU_PACKED"; do
	if [ "$packed_setting" = yes ] && [ "$VIRTIO_DEBUG" -lt 2 ]; then
		VIRTIO_DEBUG=2
	fi
done
case "$VIRTIO_IOMMU" in
yes|no) ;;
*) echo "VIRTIO_IOMMU must be yes or no" >&2; exit 2 ;;
esac
case "$IOMMU_PACKED" in
yes|no) ;;
*) echo "IOMMU_PACKED must be yes or no" >&2; exit 2 ;;
esac
[ "$IOMMU_PACKED" = no ] || [ "$VIRTIO_IOMMU" = yes ] || {
	echo "IOMMU_PACKED=yes requires VIRTIO_IOMMU=yes" >&2
	exit 2
}
case "$BALLOON_TARGET_MB" in
''|*[!0-9]*) echo "BALLOON_TARGET_MB must be a positive integer" >&2; exit 2 ;;
esac
[ "$BALLOON_TARGET_MB" -gt 0 ] &&
    [ "$BALLOON_TARGET_MB" -le "$VM_MEMORY_MB" ] || {
	echo "BALLOON_TARGET_MB must fit the test guest memory" >&2
	exit 2
}
balloon_target_pages=$((BALLOON_TARGET_MB * 256))
case "$CID" in
''|*[!0-9]*) echo "CID must be numeric" >&2; exit 2 ;;
esac
[ "$CID" -ge 3 ] && [ "$CID" -le 4294967294 ] || {
	echo "CID must be a non-reserved 32-bit guest CID" >&2
	exit 2
}
[ "$VSOCK_BACKEND" != kernel ] || [ -c /dev/vsock ] || {
	echo "backend=kernel requires /dev/vsock" >&2
	exit 1
}
for setting in "$VSOCK_SOAK_ITERATIONS" "$VSOCK_SOAK_CONNECTIONS" \
    "$VSOCK_SOAK_RESET_EVERY" \
    "$VSOCK_SOAK_MAX_FD_GROWTH" "$VSOCK_SOAK_MAX_RSS_KB" \
    "$VIRTIO_RESET_SOAK_ITERATIONS" \
    "$VIRTIO_RESET_SOAK_VERIFY_EVERY" \
    "$VIRTIO_RESET_SOAK_MAX_FD_GROWTH" \
    "$VIRTIO_RESET_SOAK_MAX_RSS_KB"; do
	case "$setting" in
	''|*[!0-9]*) echo "soak limits must be non-negative integers" >&2; exit 2 ;;
	esac
done
[ "$VIRTIO_RESET_SOAK_VERIFY_EVERY" -gt 0 ] || {
	echo "VIRTIO_RESET_SOAK_VERIFY_EVERY must be positive" >&2
	exit 2
}
[ "$VSOCK_SOAK_CONNECTIONS" -ge 2 ] &&
    [ "$VSOCK_SOAK_CONNECTIONS" -le 64 ] || {
	echo "VSOCK_SOAK_CONNECTIONS must be in [2, 64]" >&2
	exit 2
}
case "$PORT_OFFSET" in
''|*[!0-9]*) echo "PORT_OFFSET must be a non-negative integer" >&2; exit 2 ;;
esac
[ "$PORT_OFFSET" -le $((65535 - VSOCK_TEST_MAX_BASE_PORT)) ] || {
	echo "PORT_OFFSET places a test port above 65535" >&2
	exit 2
}

run_vsock=no
run_net_device=no
run_rng_device=no
run_balloon_device=no
run_rtc_device=no
run_input_device=no
run_block_device=no
run_scsi_device=no
run_console_device=no
run_9p_device=no
run_fs_device=no
run_gpu_device=no
run_mem_device=no
run_pmem_device=no
run_sound_device=no
for device in $DEVICES; do
	case "$device" in
	vsock) run_vsock=yes ;;
	net) run_net_device=yes ;;
	rng) run_rng_device=yes ;;
	balloon) run_balloon_device=yes ;;
	rtc) run_rtc_device=yes ;;
	input) run_input_device=yes ;;
	block) run_block_device=yes ;;
	scsi) run_scsi_device=yes ;;
	console) run_console_device=yes ;;
	9p) run_9p_device=yes ;;
	fs) run_fs_device=yes ;;
	gpu) run_gpu_device=yes ;;
	mem) run_mem_device=yes ;;
	pmem) run_pmem_device=yes ;;
	sound) run_sound_device=yes ;;
	*) echo "invalid device test: $device" >&2; exit 2 ;;
	esac
done
[ "$run_vsock" = yes ] || [ "$run_net_device" = yes ] ||
    [ "$run_rng_device" = yes ] ||
    [ "$run_balloon_device" = yes ] ||
    [ "$run_rtc_device" = yes ] ||
    [ "$run_input_device" = yes ] || [ "$run_block_device" = yes ] ||
    [ "$run_scsi_device" = yes ] || [ "$run_console_device" = yes ] ||
    [ "$run_9p_device" = yes ] || [ "$run_fs_device" = yes ] ||
    [ "$run_gpu_device" = yes ] ||
    [ "$run_mem_device" = yes ] || [ "$run_pmem_device" = yes ] ||
    [ "$run_sound_device" = yes ] || {
	echo "DEVICES must select net, vsock, rng, balloon, rtc, input, block, scsi, console, 9p, fs, gpu, mem, pmem, sound, or a combination" >&2
	exit 2
}
[ "$run_fs_device" = no ] || [ -x "$VIRTIOFSD" ] || {
	echo "virtiofsd not found; set VIRTIOFSD or build usr.sbin/virtiofsd" >&2
	exit 1
}
[ "$CHECKPOINT_ACTIVE_9P_REJECT" = no ] ||
    { [ "$CHECKPOINT_TEST" = yes ] && [ "$run_9p_device" = yes ]; } || {
	echo "CHECKPOINT_ACTIVE_9P_REJECT=yes requires CHECKPOINT_TEST=yes and DEVICES including 9p" >&2
	exit 2
}
[ "$CHECKPOINT_ACTIVE_FS" = no ] || [ "$run_fs_device" = yes ] || {
	echo "CHECKPOINT_ACTIVE_FS=yes requires DEVICES including fs" >&2
	exit 2
}
[ "$CHECKPOINT_ACTIVE_FS" = no ] || [ "$CHECKPOINT_TEST" != no ] || {
	echo "CHECKPOINT_ACTIVE_FS=yes requires CHECKPOINT_TEST" >&2
	exit 2
}
[ "$CHECKPOINT_ACTIVE_VSOCK_REJECT" = no ] ||
    { [ "$CHECKPOINT_TEST" = yes ] && [ "$run_vsock" = yes ]; } || {
	echo "CHECKPOINT_ACTIVE_VSOCK_REJECT=yes requires CHECKPOINT_TEST=yes and DEVICES including vsock" >&2
	exit 2
}
[ "$CHECKPOINT_ACTIVE_CONSOLE_REJECT" = no ] ||
    { [ "$CHECKPOINT_TEST" = yes ] && [ "$run_console_device" = yes ]; } || {
	echo "CHECKPOINT_ACTIVE_CONSOLE_REJECT=yes requires CHECKPOINT_TEST=yes and DEVICES including console" >&2
	exit 2
}
[ "$CHECKPOINT_NEGATIVE_QUEUE_RESTORE" = no ] ||
    [ "$CHECKPOINT_TEST" = yes ] || {
	echo "CHECKPOINT_NEGATIVE_QUEUE_RESTORE=yes requires CHECKPOINT_TEST=yes" >&2
	exit 2
}
[ "$CHECKPOINT_NEGATIVE_FEATURE_RESTORE" = no ] ||
    { [ "$CHECKPOINT_TEST" = yes ] && [ "$TRANSPORTS" = modern ]; } || {
	echo "CHECKPOINT_NEGATIVE_FEATURE_RESTORE=yes requires a modern checkpoint test" >&2
	exit 2
}
[ "$CHECKPOINT_NEGATIVE_PMEM_RESTORE" = no ] ||
    { [ "$CHECKPOINT_TEST" = yes ] && [ "$run_pmem_device" = yes ]; } || {
	echo "CHECKPOINT_NEGATIVE_PMEM_RESTORE=yes requires a PMEM checkpoint test" >&2
	exit 2
}
[ "$CHECKPOINT_REPEAT_PMEM_RESTORE" = no ] ||
    { [ "$CHECKPOINT_TEST" = yes ] && [ "$run_pmem_device" = yes ]; } || {
	echo "CHECKPOINT_REPEAT_PMEM_RESTORE=yes requires a PMEM checkpoint test" >&2
	exit 2
}
[ "$CHECKPOINT_REPEAT_FS_RESTORE" = no ] ||
    { [ "$CHECKPOINT_TEST" = yes ] && [ "$run_fs_device" = yes ] &&
    [ "$CHECKPOINT_ACTIVE_FS" = yes ]; } || {
	echo "CHECKPOINT_REPEAT_FS_RESTORE=yes requires an active FS checkpoint test" >&2
	exit 2
}
[ "$CHECKPOINT_ACTIVE_MEM" = no ] ||
    { [ "$CHECKPOINT_TEST" = yes ] && [ "$run_mem_device" = yes ] &&
    [ "$MEM_CHECKPOINT_ALLOC_MB" -gt 0 ] &&
    [ "$MEM_CHECKPOINT_ALLOC_MB" -lt \
    $((VM_MEMORY_MB + MEM_REQUESTED_MB)) ]; } || {
	echo "CHECKPOINT_ACTIVE_MEM=yes requires a mem checkpoint and a positive allocation smaller than total guest memory" >&2
	exit 2
}
[ "$VERIFY_GPU_BLOB_ACTIVITY" = no ] ||
    { [ "$run_gpu_device" = yes ] && [ "$GPU_BLOB" = yes ]; } || {
	echo "VERIFY_GPU_BLOB_ACTIVITY=yes requires DEVICES including gpu and GPU_BLOB=yes" >&2
	exit 2
}
[ "$GPU_DISPLAY" = no ] || [ "$run_gpu_device" = yes ] || {
	echo "GPU_DISPLAY=yes requires DEVICES including gpu" >&2
	exit 2
}
case "$VERIFY_DEVICE_RING_NAME" in
''|*[!A-Za-z0-9_-]*)
	[ -z "$VERIFY_DEVICE_RING_NAME" ] || {
		echo "invalid VERIFY_DEVICE_RING_NAME" >&2
		exit 2
	}
	;;
esac
if [ -z "$VERIFY_DEVICE_RING_NAME" ]; then
	[ -z "$VERIFY_DEVICE_RING_LAYOUT" ] || {
		echo "VERIFY_DEVICE_RING_LAYOUT requires VERIFY_DEVICE_RING_NAME" >&2
		exit 2
	}
else
	case "$VERIFY_DEVICE_RING_LAYOUT" in
	split|packed) ;;
	*)
		echo "VERIFY_DEVICE_RING_LAYOUT must be split or packed" >&2
		exit 2
		;;
	esac
fi
[ "$run_sound_device" = no ] || [ "$VIRTIO_DEBUG" -ge 2 ] ||
    VIRTIO_DEBUG=2

for setting in "VIRTIO_MSIX:$VIRTIO_MSIX" "RESET_TEST:$RESET_TEST" \
    "REBOOT_TEST:$REBOOT_TEST" "CHECKPOINT_TEST:$CHECKPOINT_TEST" \
    "KEEP_VM:$KEEP_VM" \
    "VERIFY_GPU_BLOB_ACTIVITY:$VERIFY_GPU_BLOB_ACTIVITY"; do
	name=${setting%%:*}
	value=${setting#*:}
	case "$value" in
	yes|no) ;;
	*) echo "$name must be yes or no" >&2; exit 2 ;;
	esac
done
case "$BLOCK_TEST_MB:$BLOCK_IMAGE_MB" in
*[!0-9:]*|:*|*:) echo "block sizes must be positive integer MiB values" >&2; exit 2 ;;
esac
[ "$BLOCK_TEST_MB" -ge 3 ] && [ "$BLOCK_IMAGE_MB" -gt 0 ] &&
    [ "$BLOCK_TEST_MB" -le "$BLOCK_IMAGE_MB" ] || {
	echo "require 3 <= BLOCK_TEST_MB <= BLOCK_IMAGE_MB" >&2
	exit 2
}
case "$BLOCK_QUEUES" in
''|*[!0-9]*) echo "BLOCK_QUEUES must be an integer from 1 through 8" >&2; exit 2 ;;
esac
[ "$BLOCK_QUEUES" -ge 1 ] && [ "$BLOCK_QUEUES" -le 8 ] || {
	echo "BLOCK_QUEUES must be an integer from 1 through 8" >&2
	exit 2
}
case "$NET_QUEUES" in
''|*[!0-9]*) echo "NET_QUEUES must be an integer from 1 through 8" >&2; exit 2 ;;
esac
[ "$NET_QUEUES" -ge 1 ] && [ "$NET_QUEUES" -le 8 ] || {
	echo "NET_QUEUES must be an integer from 1 through 8" >&2
	exit 2
}
case "$SCSI_TEST_MB:$SCSI_IMAGE_MB" in
*[!0-9:]*|:*|*:) echo "SCSI sizes must be positive integer MiB values" >&2; exit 2 ;;
esac
[ "$SCSI_TEST_MB" -gt 0 ] && [ "$SCSI_IMAGE_MB" -gt 0 ] &&
    [ "$SCSI_TEST_MB" -le "$SCSI_IMAGE_MB" ] || {
	echo "require 0 < SCSI_TEST_MB <= SCSI_IMAGE_MB" >&2
	exit 2
}
case "$SCSI_QUEUES" in
''|*[!0-9]*) echo "SCSI_QUEUES must be an integer from 1 through 8" >&2; exit 2 ;;
esac
[ "$SCSI_QUEUES" -ge 1 ] && [ "$SCSI_QUEUES" -le 8 ] || {
	echo "SCSI_QUEUES must be an integer from 1 through 8" >&2
	exit 2
}
if [ "$CHECKPOINT_TEST" = yes ]; then
	for device in $DEVICES; do
		case "$device:$VSOCK_BACKEND" in
		net:*|block:*|rng:*|balloon:*|rtc:*|scsi:*|console:*|input:*|9p:*|fs:*|gpu:*|mem:*|pmem:*|sound:*|vsock:*) ;;
		*)
			echo "CHECKPOINT_TEST does not support device: $device" >&2
			exit 2
			;;
		esac
	done
fi

for transport in $TRANSPORTS; do
	case "$transport" in
	modern) ;;
	legacy)
		[ "$run_input_device" = no ] || {
			echo "the Alpine verifier cannot bind bhyve's historical virtio-input interface; use transport=modern or remove input from DEVICES" >&2
			exit 2
		}
		[ "$run_balloon_device" = no ] || {
			echo "virtio-balloon is implemented as a modern-only device" >&2
			exit 2
		}
		[ "$run_rtc_device" = no ] || {
			echo "virtio-rtc is implemented as a modern-only device" >&2
			exit 2
		}
		[ "$run_gpu_device" = no ] || {
			echo "virtio-gpu is implemented as a modern-only device" >&2
			exit 2
		}
		[ "$run_mem_device" = no ] || {
			echo "virtio-mem is implemented as a modern-only device" >&2
			exit 2
		}
		[ "$run_pmem_device" = no ] || {
			echo "virtio-pmem is implemented as a modern-only device" >&2
			exit 2
		}
		[ "$run_sound_device" = no ] || {
			echo "virtio-sound is implemented as a modern-only device" >&2
			exit 2
		}
		;;
	*) echo "invalid transport: $transport" >&2; exit 2 ;;
	esac
done

prepare_workdir()
{
	path=$1
	[ ! -L "$path" ] || {
		echo "WORKDIR must not be a symbolic link: $path" >&2
		return 1
	}
	mkdir -p -m 0700 "$path"
	[ -d "$path" ] || {
		echo "WORKDIR is not a directory: $path" >&2
		return 1
	}
	owner=$(stat -f %u "$path")
	[ "$owner" -eq 0 ] || {
		echo "WORKDIR must be owned by root: $path (uid $owner)" >&2
		return 1
	}
	mode=$(stat -f %Lp "$path")
	[ "$mode" = 700 ] || {
		echo "WORKDIR must have mode 0700: $path (mode $mode)" >&2
		return 1
	}
}
prepare_workdir "$WORKDIR"
if [ -n "$VSOCK_BARRIER_DIR" ]; then
	[ "$VSOCK_BACKEND" = kernel ] || {
		echo "VSOCK_BARRIER_DIR is valid only with backend=kernel" >&2
		exit 2
	}
	[ ! -L "$VSOCK_BARRIER_DIR" ] &&
	    [ -d "$VSOCK_BARRIER_DIR" ] ||
	    { echo "invalid VSOCK_BARRIER_DIR: $VSOCK_BARRIER_DIR" >&2; exit 2; }
	[ "$(stat -f %u "$VSOCK_BARRIER_DIR")" -eq 0 ] &&
	    [ "$(stat -f %Lp "$VSOCK_BARRIER_DIR")" = 700 ] ||
	    { echo "VSOCK_BARRIER_DIR must be root-owned mode 0700" >&2; exit 2; }
	barrier_has_cid=no
	for barrier_cid in $VSOCK_BARRIER_CIDS; do
		case "$barrier_cid" in
		''|*[!0-9]*) echo "VSOCK_BARRIER_CIDS must be numeric" >&2; exit 2 ;;
		esac
		[ "$barrier_cid" != "$CID" ] || barrier_has_cid=yes
	done
	[ "$barrier_has_cid" = yes ] || {
		echo "VSOCK_BARRIER_CIDS must include CID $CID" >&2
		exit 2
	}
fi
if [ -f "$here/Makefile" ]; then
	case "${VM_FREE_GATES:-yes}" in
	yes) make -C "$here" ;;
	no) ;;
	*) echo "VM_FREE_GATES must be yes or no" >&2; exit 2 ;;
	esac
	tools=${TOOLS:-$(make -C "$here" -V .OBJDIR)}
else
	tools=${TOOLS:-$here}
fi
required_tools=
[ "$run_vsock" = no ] || required_tools="unix-pipe vsock-pipe vsh-connect vsh-connect-test-server uinput-inject"
[ "$run_console_device" = no ] || required_tools="$required_tools unix-pipe"
[ "$run_input_device" = no ] || required_tools="$required_tools uinput-inject"
[ "$GPU_DISPLAY" = no ] || required_tools="$required_tools gpu-rfb-check"
[ "$NONVIRTIO_DEVICE" != fbuf ] || required_tools="$required_tools gpu-rfb-check"
for tool in $required_tools; do
	[ -x "$tools/$tool" ] || {
		echo "built helper not found: $tools/$tool" >&2
		exit 1
	}
done
if [ "$run_vsock" != no ] && [ "${VM_FREE_GATES:-yes}" = yes ]; then
	TOOLS="$tools" sh "$here/host-tools-selftest.sh"
fi
kldload -n vmm
[ "$run_input_device" = no ] || kldload -n uinput
[ "$run_input_device" = no ] || "$tools/uinput-inject" --kernel-self-test
[ "$run_scsi_device" = no ] || kldload -n ctl
sysctl net.link.tap.up_on_open=1 >/dev/null

if [ -z "$CONSOLE_PORT" ]; then
	CONSOLE_PORT=4400
	while nc -z 127.0.0.1 "$CONSOLE_PORT" >/dev/null 2>&1; do
		CONSOLE_PORT=$((CONSOLE_PORT + 1))
		[ "$CONSOLE_PORT" -lt 4500 ] || {
			echo "no free TCP console port in 4400..4499" >&2
			exit 1
		}
	done
fi

bridge_created=no
if ! ifconfig "$BRIDGE" >/dev/null 2>&1; then
	ifconfig "$BRIDGE" create
	bridge_created=yes
	nic=$UPLINK
	[ -n "$nic" ] || nic=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
	[ -z "$nic" ] || ifconfig "$BRIDGE" addm "$nic"
	ifconfig "$BRIDGE" up
fi
tap=$(ifconfig tap create)
ifconfig "$BRIDGE" addm "$tap"
ifconfig "$tap" up
nonvirtio_tap=
if [ "$NONVIRTIO_DEVICE" = e82545 ]; then
	nonvirtio_tap=$(ifconfig tap create)
	ifconfig "$BRIDGE" addm "$nonvirtio_tap"
	ifconfig "$nonvirtio_tap" up
fi

vm_pid=
console_pid=
input_pid=
input_pid2=
vsock_checkpoint_host_pid=
console_checkpoint_host_pid=
reboot_stream_pid=
reboot_seq_pid=
console_exchange_pid=
virtiofsd_pid=
vmname=
console_log=
bhyve_log=
input_log=
input_log2=
reboot_stream_log=
reboot_seq_log=
scsi_create_log=
scsi_lun_id=
scsi_size_bytes=
scsi_event_create_log=
scsi_event_lun_id=
console_exchange_log=
virtiofsd_log=
stop_console()
{
	[ -z "$console_pid" ] || pkill -TERM -P "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || kill "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || wait "$console_pid" 2>/dev/null || true
	console_pid=
}
cleanup_vm()
{
	exec 9>&- 2>/dev/null || true
	virtio_ring_trace_stop
	if [ -n "$console_checkpoint_host_pid" ]; then
		kill "$console_checkpoint_host_pid" 2>/dev/null || true
		wait "$console_checkpoint_host_pid" 2>/dev/null || true
	fi
	console_checkpoint_host_pid=
	if [ -n "$vsock_checkpoint_host_pid" ]; then
		kill "$vsock_checkpoint_host_pid" 2>/dev/null || true
		wait "$vsock_checkpoint_host_pid" 2>/dev/null || true
	fi
	vsock_checkpoint_host_pid=
	if [ -n "$console_exchange_pid" ]; then
		pkill -TERM -P "$console_exchange_pid" 2>/dev/null || true
		kill "$console_exchange_pid" 2>/dev/null || true
		wait "$console_exchange_pid" 2>/dev/null || true
	fi
	console_exchange_pid=
	for hold_pid in "$reboot_stream_pid" "$reboot_seq_pid"; do
		[ -z "$hold_pid" ] || kill "$hold_pid" 2>/dev/null || true
		[ -z "$hold_pid" ] || wait "$hold_pid" 2>/dev/null || true
	done
	reboot_stream_pid=
	reboot_seq_pid=
	stop_console
	if [ -n "$vm_pid" ]; then
		kill "$vm_pid" 2>/dev/null || true
		i=0
		while kill -0 "$vm_pid" 2>/dev/null && [ "$i" -lt 5 ]; do
			sleep 1
			i=$((i + 1))
		done
		kill -KILL "$vm_pid" 2>/dev/null || true
		wait "$vm_pid" 2>/dev/null || true
	fi
	vm_pid=
	[ -z "$vmname" ] || "$BHYVECTL" --vm="$vmname" --destroy >/dev/null 2>&1 || true
	if [ -n "$input_pid" ]; then
		kill "$input_pid" 2>/dev/null || true
		wait "$input_pid" 2>/dev/null || true
	fi
	input_pid=
	if [ -n "$input_pid2" ]; then
		kill "$input_pid2" 2>/dev/null || true
		wait "$input_pid2" 2>/dev/null || true
	fi
	input_pid2=
	if [ -n "$virtiofsd_pid" ]; then
		kill "$virtiofsd_pid" 2>/dev/null || true
		wait "$virtiofsd_pid" 2>/dev/null || true
	fi
	virtiofsd_pid=
}
cleanup_all()
{
	if [ "$KEEP_VM" = yes ]; then
		echo "KEEP_VM=yes: preserving VM, console, provider, and tap $tap" >&2
		return
	fi
	cleanup_vm
	if [ -n "$scsi_lun_id" ]; then
		ctladm remove -b ramdisk -l "$scsi_lun_id" >/dev/null ||
		    echo "warning: failed to remove CTL LUN $scsi_lun_id" >&2
		scsi_lun_id=
	fi
	if [ -n "$scsi_event_lun_id" ]; then
		ctladm remove -b ramdisk -l "$scsi_event_lun_id" >/dev/null ||
		    echo "warning: failed to remove CTL event-test LUN $scsi_event_lun_id" >&2
		scsi_event_lun_id=
	fi
	ifconfig "$BRIDGE" deletem "$tap" >/dev/null 2>&1 || true
	ifconfig "$tap" destroy >/dev/null 2>&1 || true
	if [ -n "$nonvirtio_tap" ]; then
		ifconfig "$BRIDGE" deletem "$nonvirtio_tap" >/dev/null 2>&1 || true
		ifconfig "$nonvirtio_tap" destroy >/dev/null 2>&1 || true
	fi
	[ "$bridge_created" = no ] || ifconfig "$BRIDGE" destroy >/dev/null 2>&1 || true
}
report_failure()
{
	echo "==== retained failure diagnostics ====" >&2
	for item in "bhyve:$bhyve_log" "input-provider:$input_log" \
	    "input-provider-2:$input_log2" \
	    "virtiofsd:$virtiofsd_log" \
	    "scsi-create:$scsi_create_log" \
	    "scsi-event-create:$scsi_event_create_log" \
	    "console-exchange:$console_exchange_log" \
	    "reboot-stream:$reboot_stream_log" "reboot-seq:$reboot_seq_log" \
	    "guest-console:$console_log"; do
		label=${item%%:*}
		path=${item#*:}
		if [ -n "$path" ] && [ -r "$path" ]; then
			echo "---- $label ($path), last 80 lines ----" >&2
			tail -n 80 "$path" >&2 || true
		fi
	done
	echo "full logs remain under $WORKDIR" >&2
}
on_exit()
{
	status=$?
	trap - EXIT
	[ "$status" -eq 0 ] || report_failure
	cleanup_all
	exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

if [ "$run_scsi_device" = yes ]; then
	scsi_create_log="$WORKDIR/scsi-create.log"
	scsi_size_bytes=$((SCSI_IMAGE_MB * 1024 * 1024 + ($$ % 8192) * 512))
	# A ramdisk without capacity is CTL's intentionally fake backend: it
	# discards writes and returns zeroes.  Back the full advertised LUN so
	# the guest test verifies real data persistence.
	ctladm create -b ramdisk -s "$scsi_size_bytes" \
	    -o "capacity=$scsi_size_bytes" > "$scsi_create_log"
	scsi_lun_id=$(awk '/^LUN ID:/ {print $NF}' "$scsi_create_log")
	case "$scsi_lun_id" in
	''|*[!0-9]*) echo "invalid CTL LUN ID: $scsi_lun_id" >&2; exit 1 ;;
	esac
	[ "$scsi_lun_id" -le 16383 ] || {
		echo "CTL LUN ID exceeds virtio-scsi limit: $scsi_lun_id" >&2
		exit 1
	}
	grep -q '^LUN created successfully$' "$scsi_create_log"
fi

wait_for()
{
	pattern=$1
	limit=$2
	i=0
	while [ "$i" -lt "$limit" ]; do
		grep -q "$pattern" "$console_log" 2>/dev/null && return 0
		sleep 1
		i=$((i + 1))
	done
	echo "timed out waiting for console pattern: $pattern" >&2
	return 1
}

wait_for_login()
{
	limit=$1
	i=0
	while [ "$i" -lt "$limit" ]; do
		grep -q 'login:' "$console_log" 2>/dev/null && return 0
		# A TCP console attached after boot misses the getty's first prompt.
		# A carriage return asks getty to print a fresh one; repeat in case
		# the first write races the new monitor child accepting the socket.
		[ $((i % 5)) -ne 0 ] || printf '\r' >> "$console_input"
		kill -0 "$vm_pid" 2>/dev/null || {
			echo "bhyve exited while waiting for the guest login" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	echo "timed out waiting for console pattern: login:" >&2
	return 1
}

start_console()
{
	: > "$console_input"
	: > "$console_log"
	i=0
	while ! sockstat -4 -l | grep -q ":${CONSOLE_PORT}[[:space:]]"; do
		kill -0 "$vm_pid" 2>/dev/null || {
			echo "bhyve exited before its console became ready:" >&2
			tail -n 20 "$bhyve_log" >&2
			return 1
		}
		[ "$i" -lt 30 ] || { echo "bhyve console did not listen" >&2; return 1; }
		sleep 1
		i=$((i + 1))
	done
	(tail -f "$console_input" | nc 127.0.0.1 "$CONSOLE_PORT" > "$console_log" 2>&1) &
	console_pid=$!
}

launch_vm()
{
	restore_file=${1:-}
	set -- "$BHYVE" -c "$vm_cpus" -m "${VM_MEMORY_MB}M" -H -w \
	    -s "0,hostbridge$nonvirtio_hostbridge_opt" -s "3,ahci-cd,$ISO" \
	    -s "4,virtio-net,$tap$net_transport_opt$net_queues_opt$net_packed_opt"
	[ "$VIRTIO_MSIX" = yes ] || set -- "$@" -W
	[ "$REBOOT_TEST" = no ] || set -- "$@" -M
	[ -z "$restore_file" ] || set -- "$@" -r "$restore_file"
	[ "$run_vsock" = no ] || set -- "$@" \
	    -s "5,virtio-vsock,cid=$CID$vsock_backend_opt$vsock_transport_opt$vsock_packed_opt"
	[ "$run_input_device" = no ] || set -- "$@" \
	    -s "6,virtio-input,$input_path$input_transport_opt$input_packed_opt"
	[ "$run_input_device" = no ] || [ "$INPUT_DEVICES" -eq 1 ] ||
	    set -- "$@" \
		-s "18,virtio-input,$input_path2$input_transport_opt$input_packed_opt"
	[ "$run_rng_device" = no ] || set -- "$@" \
	    -s "7,virtio-rnd$rng_transport_opt$rng_packed_opt"
	[ "$run_balloon_device" = no ] || set -- "$@" \
	    -s "12,virtio-balloon,target=${BALLOON_TARGET_MB}M$balloon_packed_opt$balloon_stats_opt$balloon_deflate_on_oom_opt$balloon_hinting_opt$balloon_reporting_opt$balloon_page_poison_opt"
	[ "$run_rtc_device" = no ] || set -- "$@" \
	    -s "13,virtio-rtc$rtc_packed_opt$rtc_alarm_opt"
	[ "$run_gpu_device" = no ] || set -- "$@" \
	    -s "14,virtio-gpu,width=$GPU_WIDTH,height=$GPU_HEIGHT$gpu_packed_opt$gpu_blob_opt$gpu_display_opt"
	[ "$run_gpu_device" = no ] || [ "$GPU_DISPLAY" = no ] || set -- "$@" \
	    -s "29,fbuf,rfb=unix:$DIR/gpu-vnc.sock,w=$GPU_WIDTH,h=$GPU_HEIGHT,vga=off,source=external"
	[ "$run_mem_device" = no ] || set -- "$@" \
	    -s "16,virtio-mem,size=${MEM_REGION_MB}M,requested=${MEM_REQUESTED_MB}M$mem_packed_opt"
	[ "$run_pmem_device" = no ] || set -- "$@" \
	    -s "20,virtio-pmem,path=$pmem_image,id=$PMEM_IDENTITY$pmem_packed_opt"
	[ "$run_sound_device" = no ] || set -- "$@" \
	    -s "17,virtio-snd,backend=$SOUND_BACKEND$sound_backend_opt$sound_packed_opt"
	[ "$VIRTIO_IOMMU" = no ] || set -- "$@" \
	    -s "15,virtio-iommu$iommu_packed_opt"
	[ "$run_block_device" = no ] || set -- "$@" \
	    -s "8,virtio-blk,$block_image$block_transport_opt$block_queues_opt$block_packed_opt"
	[ "$run_scsi_device" = no ] || set -- "$@" \
	    -s "9,virtio-scsi,/dev/cam/ctl$scsi_transport_opt$scsi_queues_opt$scsi_packed_opt"
	[ "$run_console_device" = no ] || set -- "$@" \
	    -s "10,virtio-console,$console_ports_opt$console_transport_opt$console_packed_opt"
	[ "$run_9p_device" = no ] || set -- "$@" \
	    -s "11,virtio-9p,$ninep_tag=$ninep_share$ninep_transport_opt$ninep_packed_opt"
	[ "$run_fs_device" = no ] || set -- "$@" \
	    -s "19,virtio-fs,path=$fs_socket,tag=$fs_tag,queues=$FS_QUEUES$fs_packed_opt$fs_identity_opt"
	case "$NONVIRTIO_DEVICE" in
	none|pvpanic|lpc-uart|tpm-crb|hostbridge|qemu-fwcfg) ;;
	ahci) set -- "$@" -s "21,ahci-hd,$nonvirtio_image,checkpoint_identity=waspnest-ahci" ;;
	nvme) set -- "$@" -s "21,nvme,$nonvirtio_image,ser=WASPNESTNVME,ioslots=64,maxq=8,qsz=64" ;;
	e82545) set -- "$@" -s "21,e1000,$nonvirtio_tap" ;;
	hda) set -- "$@" -s "21,hda,play=$NONVIRTIO_HDA_PLAY,rec=$NONVIRTIO_HDA_RECORD" ;;
	xhci) set -- "$@" -s "21,xhci,tablet" ;;
	fbuf) set -- "$@" -s "21,fbuf,rfb=unix:$nonvirtio_fbuf_socket,w=1024,h=768,vga=off" ;;
	pci-uart) set -- "$@" -s "21,uart,tcp=127.0.0.1:$nonvirtio_uart_port,log=$nonvirtio_uart_log" ;;
	i6300esb) set -- "$@" -s "21,i6300esb,action=notify,timeout=2" ;;
	passthru) set -- "$@" -S -s "21,passthru,$NONVIRTIO_PASSTHRU" ;;
	esac
	set -- "$@" -s 31,lpc -l "com1,tcp=127.0.0.1:$CONSOLE_PORT"
	[ "$NONVIRTIO_DEVICE" != lpc-uart ] || set -- "$@" \
	    -l "com2,tcp=127.0.0.1:$nonvirtio_uart_port,log=$nonvirtio_uart_log"
	[ "$NONVIRTIO_DEVICE" != pvpanic ] || set -- "$@" -l "pvpanic,action=none"
	[ "$NONVIRTIO_DEVICE" != tpm-crb ] || set -- "$@" \
	    -l "tpm,$NONVIRTIO_TPM_TYPE,$NONVIRTIO_TPM_PATH,version=2.0"
	[ "$NONVIRTIO_DEVICE" != qemu-fwcfg ] || set -- "$@" \
	    -l fwcfg,qemu -f "$NONVIRTIO_FWCFG_NAME,string=$NONVIRTIO_FWCFG_VALUE"
	set -- "$@" -l "bootrom,$UEFI" "$vmname"
	env BHYVE_VTVSOCK_DEBUG="$VSOCK_DEBUG" \
	    BHYVE_VIRTIO_DEBUG="$VIRTIO_DEBUG" \
	    BHYVE_VTINPUT_DEBUG="$INPUT_DEBUG" \
	    BHYVE_VTSCSI_DEBUG="$SCSI_DEBUG" "$@" \
	    >> "$bhyve_log" 2>&1 &
	vm_pid=$!
	start_console
}

wait_checkpoint_manifest()
{
	checkpoint=$1
	old_contents=${2:-}
	i=0
	while [ "$i" -lt 180 ]; do
		if [ -f "$checkpoint" ]; then
			contents=$(cat "$checkpoint")
			header=$(printf '%s\n' "$contents" | sed -n '1p')
			if [ "$header" = "BHYVE-CHECKPOINT-MANIFEST-3" ] &&
			    { [ -z "$old_contents" ] ||
			    [ "$contents" != "$old_contents" ]; }; then
				valid=yes
				for key in data kern meta; do
					member=$(printf '%s\n' "$contents" |
					    sed -n "s/^$key=//p")
					case "$member" in
					''|*/*|.|..) valid=no; break ;;
					esac
					if [ ! -f "$(dirname "$checkpoint")/$member" ]; then
						valid=no
						break
					fi
				done
				[ "$valid" = no ] || return 0
			fi
		fi
		if [ -n "$vm_pid" ]; then
			kill -0 "$vm_pid" 2>/dev/null || return 1
		fi
		sleep 1
		i=$((i + 1))
	done
	echo "timed out waiting for checkpoint manifest: $checkpoint" >&2
	return 1
}

expect_incompatible_restore_rejected()
{
	contract=$1
	negative_log=$2
	log_line=$(( $(wc -l < "$bhyve_log") + 1 ))

	if launch_vm "$checkpoint"; then
		kill "$vm_pid" 2>/dev/null || true
		wait "$vm_pid" 2>/dev/null || true
		vm_pid=
		stop_console
		echo "checkpoint restore unexpectedly accepted changed $contract" >&2
		return 1
	fi
	if kill -0 "$vm_pid" 2>/dev/null; then
		kill "$vm_pid" 2>/dev/null || true
		wait "$vm_pid" 2>/dev/null || true
		vm_pid=
		stop_console
		echo "incompatible restore remained alive instead of rejecting $contract during preflight" >&2
		return 1
	fi
	process_status=0
	wait "$vm_pid" 2>/dev/null || process_status=$?
	vm_pid=
	stop_console
	sed -n "${log_line},\$p" "$bhyve_log" > "$negative_log"
	[ "$process_status" -ne 0 ] || {
		echo "incompatible restore did not return a failure status" >&2
		return 1
	}
	grep -Eq 'incompatible|Failed to restore|not supported' "$negative_log" || {
		echo "incompatible restore did not identify its rejection" >&2
		cat "$negative_log" >&2
		return 1
	}
	echo "PASS incompatible checkpoint restore rejected contract=$contract"
}

verify_incompatible_queue_restore_rejected()
{
	[ "$CHECKPOINT_NEGATIVE_QUEUE_RESTORE" = yes ] || return 0

	saved_net_queues_opt=$net_queues_opt
	case "$NET_QUEUES" in
	1) net_queues_opt=,queues=2 ;;
	*) net_queues_opt=,queues=1 ;;
	esac
	negative_log="$WORKDIR/$transport.incompatible-queue-restore.log"
	status=0
	expect_incompatible_restore_rejected net-queue-geometry \
	    "$negative_log" || status=$?
	net_queues_opt=$saved_net_queues_opt
	return "$status"
}

verify_incompatible_feature_restore_rejected()
{
	[ "$CHECKPOINT_NEGATIVE_FEATURE_RESTORE" = yes ] || return 0

	saved_net_packed_opt=$net_packed_opt
	if [ "$NET_PACKED" = yes ]; then
		# The source negotiated PACKED; the destination must not lose it.
		net_packed_opt=
	else
		# Offered-feature identity is also part of the restore contract.
		net_packed_opt=,packed=true
	fi
	negative_log="$WORKDIR/$transport.incompatible-feature-restore.log"
	status=0
	expect_incompatible_restore_rejected net-ring-feature-set \
	    "$negative_log" || status=$?
	net_packed_opt=$saved_net_packed_opt
	return "$status"
}

verify_incompatible_pmem_restore_rejected()
{
	[ "$CHECKPOINT_NEGATIVE_PMEM_RESTORE" = yes ] || return 0

	saved_identity=$PMEM_IDENTITY
	PMEM_IDENTITY="$saved_identity.mismatch"
	negative_log="$WORKDIR/$transport.incompatible-pmem-identity.log"
	status=0
	expect_incompatible_restore_rejected pmem-backend-identity \
	    "$negative_log" || status=$?
	PMEM_IDENTITY=$saved_identity
	[ "$status" -eq 0 ] || return "$status"

	saved_size=$(wc -c < "$pmem_image")
	changed_size=$((saved_size + 4096))
	truncate -s "$changed_size" "$pmem_image"
	negative_log="$WORKDIR/$transport.incompatible-pmem-capacity.log"
	status=0
	expect_incompatible_restore_rejected pmem-capacity \
	    "$negative_log" || status=$?
	truncate -s "$saved_size" "$pmem_image"
	return "$status"
}

verify_incompatible_nonvirtio_restore_rejected()
{
	[ "$NONVIRTIO_DEVICE" = hostbridge ] || return 0
	saved_hostbridge_opt=$nonvirtio_hostbridge_opt
	nonvirtio_hostbridge_opt=',vendor=0x8086,devid=0x1237'
	negative_log="$WORKDIR/$transport.incompatible-hostbridge-topology.log"
	status=0
	expect_incompatible_restore_rejected hostbridge-topology \
	    "$negative_log" || status=$?
	nonvirtio_hostbridge_opt=$saved_hostbridge_opt
	return "$status"
}

terminate_vm_for_repeat_restore()
{

	[ -n "$vm_pid" ] || return 0
	kill "$vm_pid" 2>/dev/null || true
	i=0
	while kill -0 "$vm_pid" 2>/dev/null && [ "$i" -lt 5 ]; do
		sleep 1
		i=$((i + 1))
	done
	kill -KILL "$vm_pid" 2>/dev/null || true
	wait "$vm_pid" 2>/dev/null || true
	vm_pid=
	stop_console
	"$BHYVECTL" --vm="$vmname" --destroy >/dev/null 2>&1 || true
}

run_checkpoint_roundtrip()
{
	checkpoint="$WORKDIR/$transport.checkpoint"
	marker="checkpoint-$transport-$$"

	echo "== Alpine $transport: live checkpoint and restore =="
	rm -f "$checkpoint" "$checkpoint".*
	guest_cmd "printf %s '$marker' > /tmp/bhyve-checkpoint-marker" 30
	verify_active_console_checkpoint_rejected
	verify_active_vsock_checkpoint_rejected
	verify_active_9p_checkpoint_rejected
	prepare_checkpoint_backends
	start_checkpoint_workloads
	"$BHYVECTL" --vm="$vmname" --checkpoint="$checkpoint"
	wait_checkpoint_manifest "$checkpoint"
	first_manifest=$(cat "$checkpoint")
	guest_cmd "test \"\$(cat /tmp/bhyve-checkpoint-marker)\" = '$marker'" 30
	verify_active_fs_checkpoint
	verify_checkpoint_workloads
	stop_checkpoint_workloads
	run_lifecycle_smokes

	prepare_checkpoint_backends
	start_checkpoint_workloads
	"$BHYVECTL" --vm="$vmname" --suspend="$checkpoint"
	i=0
	while kill -0 "$vm_pid" 2>/dev/null && [ "$i" -lt 180 ]; do
		sleep 1
		i=$((i + 1))
	done
	[ "$i" -lt 180 ] || {
		echo "timed out waiting for suspended bhyve to exit" >&2
		return 1
	}
	wait "$vm_pid" 2>/dev/null || true
	vm_pid=
	stop_console
	wait_checkpoint_manifest "$checkpoint" "$first_manifest"

	verify_incompatible_queue_restore_rejected
	verify_incompatible_feature_restore_rejected
	verify_incompatible_pmem_restore_rejected
	verify_incompatible_nonvirtio_restore_rejected
	launch_vm "$checkpoint"
	guest_cmd "test \"\$(cat /tmp/bhyve-checkpoint-marker)\" = '$marker'" 60
	verify_active_fs_checkpoint
	verify_checkpoint_workloads
	stop_checkpoint_workloads
	run_lifecycle_smokes
	if [ "$CHECKPOINT_REPEAT_PMEM_RESTORE" = yes ] ||
	    [ "$CHECKPOINT_REPEAT_FS_RESTORE" = yes ]; then
		terminate_vm_for_repeat_restore
		launch_vm "$checkpoint"
		guest_cmd "test \"\$(cat /tmp/bhyve-checkpoint-marker)\" = '$marker'" 60
		verify_active_fs_checkpoint
		verify_checkpoint_workloads
		stop_checkpoint_workloads
		run_lifecycle_smokes
		if [ "$CHECKPOINT_REPEAT_FS_RESTORE" = yes ]; then
			echo "PASS repeated checkpoint restore contract=virtio-fs-active-handles"
		else
			echo "PASS repeated checkpoint restore contract=pmem-backend"
		fi
	fi
	cleanup_active_fs_checkpoint
	echo "PASS checkpoint restore transport=$transport manifest=$checkpoint"
}

run_nonvirtio_checkpoint_rejection()
{
	checkpoint="$WORKDIR/$transport.$NONVIRTIO_DEVICE.rejected.checkpoint"
	rm -f "$checkpoint" "$checkpoint".*
	if "$BHYVECTL" --vm="$vmname" --checkpoint="$checkpoint" \
	    >"$checkpoint.stdout" 2>"$checkpoint.stderr"; then
		echo "$NONVIRTIO_DEVICE unexpectedly accepted checkpoint" >&2
		return 1
	fi
	grep -Eqi 'not supported|unsupported|cannot snapshot' \
	    "$checkpoint.stdout" "$checkpoint.stderr" "$bhyve_log" || {
		echo "$NONVIRTIO_DEVICE rejection lacked an unsupported-state diagnostic" >&2
		return 1
	}
	kill -0 "$vm_pid"
	run_nonvirtio
	[ ! -e "$checkpoint" ] || {
		echo "rejected checkpoint published a manifest: $checkpoint" >&2
		return 1
	}
	echo "PASS checkpoint-rejected guest=alpine device=$NONVIRTIO_DEVICE"
}

verify_active_console_checkpoint_rejected()
{
	[ "$CHECKPOINT_ACTIVE_CONSOLE_REJECT" = yes ] || return 0
	rejected="$WORKDIR/$transport.active-console-rejected.checkpoint"
	active_fifo="$WORKDIR/$transport.active-console.fifo"
	active_out="$WORKDIR/$transport.active-console.out"
	active_err="$WORKDIR/$transport.active-console.err"
	first_token="ACTIVE-CONSOLE-BEFORE-$transport-$$"
	second_token="ACTIVE-CONSOLE-AFTER-$transport-$$"
	ready_token="ACTIVE-CONSOLE-READY-$transport-$$"
	console_guest_opt=
	[ "$CONSOLE_PACKED" = no ] || console_guest_opt=" packed"

	rm -f "$rejected" "$rejected".* "$active_fifo" \
	    "$active_out" "$active_err"
	mkfifo -m 0600 "$active_fifo"
	"$tools/unix-pipe" "$console_socket" < "$active_fifo" \
	    > "$active_out" 2> "$active_err" &
	console_checkpoint_host_pid=$!
	exec 9>"$active_fifo"
	guest_cmd "set -eu; rm -f /tmp/gcheckpoint-console-active.log /tmp/gcheckpoint-console-active.pid; nohup python3 /tmp/gconsole.py hold '$transport' '$console_name' '$ready_token'$console_guest_opt >/tmp/gcheckpoint-console-active.log 2>&1 & echo \$! >/tmp/gcheckpoint-console-active.pid; i=0; while ! grep -q '^READY$' /tmp/gcheckpoint-console-active.log 2>/dev/null && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; pid=\$(cat /tmp/gcheckpoint-console-active.pid); kill -0 \"\$pid\"; grep -q '^READY$' /tmp/gcheckpoint-console-active.log" 45
	i=0
	while ! grep -q "$ready_token" "$active_out" 2>/dev/null &&
	    kill -0 "$console_checkpoint_host_pid" 2>/dev/null &&
	    [ "$i" -lt 30 ]; do
		sleep 1
		i=$((i + 1))
	done
	grep -q "$ready_token" "$active_out" 2>/dev/null || {
		cat "$active_err" >&2
		return 1
	}
	printf %s "$first_token" >&9
	i=0
	while ! grep -q "$first_token" "$active_out" 2>/dev/null &&
	    kill -0 "$console_checkpoint_host_pid" 2>/dev/null &&
	    [ "$i" -lt 30 ]; do
		sleep 1
		i=$((i + 1))
	done
	grep -q "$first_token" "$active_out" 2>/dev/null || {
		cat "$active_err" >&2
		return 1
	}
	if "$BHYVECTL" --vm="$vmname" --checkpoint="$rejected"; then
		echo "active console checkpoint unexpectedly succeeded" >&2
		return 1
	fi
	printf %s "$second_token" >&9
	i=0
	while ! grep -q "$second_token" "$active_out" 2>/dev/null &&
	    kill -0 "$console_checkpoint_host_pid" 2>/dev/null &&
	    [ "$i" -lt 30 ]; do
		sleep 1
		i=$((i + 1))
	done
	grep -q "$second_token" "$active_out" 2>/dev/null || {
		cat "$active_err" >&2
		return 1
	}
	exec 9>&-
	i=0
	while kill -0 "$console_checkpoint_host_pid" 2>/dev/null &&
	    [ "$i" -lt 30 ]; do
		sleep 1
		i=$((i + 1))
	done
	[ "$i" -lt 30 ] || {
		echo "active console host endpoint did not drain" >&2
		return 1
	}
	wait "$console_checkpoint_host_pid"
	console_checkpoint_host_pid=
	guest_cmd "set -eu; pid=\$(cat /tmp/gcheckpoint-console-active.pid); i=0; while kill -0 \"\$pid\" 2>/dev/null && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; ! kill -0 \"\$pid\" 2>/dev/null; grep -q '^PASS hold-echo-closed$' /tmp/gcheckpoint-console-active.log" 45
	rm -f "$rejected" "$rejected".* "$active_fifo"
	echo "PASS active console checkpoint rejected and live session survived rollback"
}

verify_active_vsock_checkpoint_rejected()
{
	[ "$CHECKPOINT_ACTIVE_VSOCK_REJECT" = yes ] || return 0
	rejected="$WORKDIR/$transport.active-vsock-rejected.checkpoint"
	active_fifo="$WORKDIR/$transport.active-vsock.fifo"
	active_out="$WORKDIR/$transport.active-vsock.out"
	active_err="$WORKDIR/$transport.active-vsock.err"
	active_port=$((7474 + PORT_OFFSET))
	first_token="ACTIVE-VSOCK-BEFORE-$transport-$$"
	second_token="ACTIVE-VSOCK-AFTER-$transport-$$"

	rm -f "$rejected" "$rejected".* "$active_fifo" \
	    "$active_out" "$active_err"
	mkfifo -m 0600 "$active_fifo"
	guest_cmd "set -eu; rm -f /tmp/gcheckpoint-vsock-active.log /tmp/gcheckpoint-vsock-active.pid; nohup python3 /tmp/gvsock.py hold-l stream '$active_port' >/tmp/gcheckpoint-vsock-active.log 2>&1 & echo \$! >/tmp/gcheckpoint-vsock-active.pid; i=0; while ! grep -q '^up$' /tmp/gcheckpoint-vsock-active.log 2>/dev/null && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; pid=\$(cat /tmp/gcheckpoint-vsock-active.pid); kill -0 \"\$pid\"; grep -q '^up$' /tmp/gcheckpoint-vsock-active.log" 45
	(
		i=0
		while [ "$i" -lt 5 ]; do
			if [ "$VSOCK_BACKEND" = kernel ]; then
				if "$tools/vsock-pipe" "$CID" "$active_port" \
				    < "$active_fifo" > "$active_out" \
				    2> "$active_err"; then
					rc=0
				else
					rc=$?
				fi
			else
				if "$tools/vsh-connect" "$sockdir" "$active_port" \
				    < "$active_fifo" > "$active_out" \
				    2> "$active_err"; then
					rc=0
				else
					rc=$?
				fi
			fi
			{ [ "$rc" -eq 1 ] || [ "$rc" -eq 4 ]; } ||
			    exit "$rc"
			sleep 1
			i=$((i + 1))
		done
		exit 4
	) &
	vsock_checkpoint_host_pid=$!
	exec 9>"$active_fifo"
	printf %s "$first_token" >&9
	i=0
	while ! grep -q "$first_token" "$active_out" 2>/dev/null &&
	    kill -0 "$vsock_checkpoint_host_pid" 2>/dev/null &&
	    [ "$i" -lt 30 ]; do
		sleep 1
		i=$((i + 1))
	done
	grep -q "$first_token" "$active_out" 2>/dev/null || {
		cat "$active_err" >&2
		return 1
	}
	if "$BHYVECTL" --vm="$vmname" --checkpoint="$rejected"; then
		echo "active vsock checkpoint unexpectedly succeeded" >&2
		return 1
	fi
	printf %s "$second_token" >&9
	i=0
	while ! grep -q "$second_token" "$active_out" 2>/dev/null &&
	    kill -0 "$vsock_checkpoint_host_pid" 2>/dev/null &&
	    [ "$i" -lt 30 ]; do
		sleep 1
		i=$((i + 1))
	done
	grep -q "$second_token" "$active_out" 2>/dev/null || {
		cat "$active_err" >&2
		return 1
	}
	exec 9>&-
	i=0
	while kill -0 "$vsock_checkpoint_host_pid" 2>/dev/null &&
	    [ "$i" -lt 30 ]; do
		sleep 1
		i=$((i + 1))
	done
	[ "$i" -lt 30 ] || {
		echo "active vsock host endpoint did not drain" >&2
		return 1
	}
	wait "$vsock_checkpoint_host_pid"
	vsock_checkpoint_host_pid=
	guest_cmd "set -eu; pid=\$(cat /tmp/gcheckpoint-vsock-active.pid); i=0; while kill -0 \"\$pid\" 2>/dev/null && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; ! kill -0 \"\$pid\" 2>/dev/null" 45
	rm -f "$rejected" "$rejected".* "$active_fifo"
	echo "PASS active vsock checkpoint rejected backend=$VSOCK_BACKEND and live connection survived rollback"
}

verify_active_9p_checkpoint_rejected()
{
	[ "$CHECKPOINT_ACTIVE_9P_REJECT" = yes ] || return 0
	rejected="$WORKDIR/$transport.active-9p-rejected.checkpoint"
	probe="active-9p-$transport-$$"

	rm -f "$rejected" "$rejected".*
	guest_cmd "set -eu; grep -qs ' /mnt/bhyve-9p ' /proc/mounts; printf %s '$probe' > /mnt/bhyve-9p/checkpoint-reject-probe; sync" 30
	if "$BHYVECTL" --vm="$vmname" --checkpoint="$rejected"; then
		echo "active 9P mount checkpoint unexpectedly succeeded" >&2
		return 1
	fi
	guest_cmd "set -eu; grep -qs ' /mnt/bhyve-9p ' /proc/mounts; [ \"\$(cat /mnt/bhyve-9p/checkpoint-reject-probe)\" = '$probe' ]; printf %s '$probe-after' > /mnt/bhyve-9p/checkpoint-reject-after; sync" 30
	[ "$(cat "$ninep_share/checkpoint-reject-after")" = "$probe-after" ]
	rm -f "$rejected" "$rejected".*
	echo "PASS active 9P checkpoint rejected and source mount remains usable"
}

prepare_active_fs_checkpoint()
{
	[ "$CHECKPOINT_ACTIVE_FS" = yes ] || return 0
	holder_pid=/tmp/bhyve-fs-checkpoint-holder.pid
	holder_ready=/tmp/bhyve-fs-checkpoint-holder.ready

	guest_cmd "set -eu; grep -qs ' /mnt/bhyve-fs ' /proc/mounts; [ \"\$(cat /mnt/bhyve-fs/host-seed)\" = '$fs_seed' ]; rm -f '$holder_pid' '$holder_ready'; mkfifo '$holder_ready'; nohup sh -c 'exec 3</mnt/bhyve-fs/host-seed; printf ready >$holder_ready; sleep 1800' >/dev/null 2>&1 & printf %s \$! >'$holder_pid'; read ready <'$holder_ready'; [ \"\$ready\" = ready ]; rm -f '$holder_ready'; kill -0 \"\$(cat '$holder_pid')\"" 30
	echo "PASS active virtio-fs checkpoint handle established"
}

verify_active_fs_checkpoint()
{
	[ "$CHECKPOINT_ACTIVE_FS" = yes ] || return 0
	holder_pid=/tmp/bhyve-fs-checkpoint-holder.pid
	guest_cmd "set -eu; grep -qs ' /mnt/bhyve-fs ' /proc/mounts; pid=\$(cat '$holder_pid'); kill -0 \"\$pid\"; [ \"\$(cat /proc/\$pid/fd/3)\" = '$fs_seed' ]; [ \"\$(cat /mnt/bhyve-fs/host-seed)\" = '$fs_seed' ]; [ \"\$(readlink /mnt/bhyve-fs/link)\" = host-seed" 30
	kill -0 "$virtiofsd_pid" 2>/dev/null || {
		echo "virtiofsd exited during active checkpoint" >&2
		cat "$fs_log" >&2
		return 1
	}
	echo "PASS active virtio-fs handle and mount remain usable"
}

cleanup_active_fs_checkpoint()
{
	[ "$CHECKPOINT_ACTIVE_FS" = yes ] || return 0
	guest_cmd "set -eu; pid=\$(cat /tmp/bhyve-fs-checkpoint-holder.pid); kill \"\$pid\"; rm -f /tmp/bhyve-fs-checkpoint-holder.pid" 30
}

prepare_checkpoint_backends()
{
	[ "$run_9p_device" = no ] ||
	    guest_cmd "if grep -qs ' /mnt/bhyve-9p ' /proc/mounts; then umount /mnt/bhyve-9p; fi" 30
	[ "$run_fs_device" = no ] || [ "$CHECKPOINT_ACTIVE_FS" = yes ] ||
	    guest_cmd "if grep -qs ' /mnt/bhyve-fs ' /proc/mounts; then umount /mnt/bhyve-fs; fi" 30
}

sound_checkpoint_guest_opt()
{
	if [ "$SOUND_PACKED" = yes ]; then
		printf ' packed'
	fi
}

sound_playback_total()
{
	awk '
	/^vtsnd: device reset requested/ {
		total = 0
	}
	/^vtsnd: playback stream=[0-9]+ bytes=[0-9]+ total=[0-9]+$/ {
		sub(/^.* total=/, "")
		total = $0
	}
	END {
		printf "%.0f\n", total
	}
	' "$bhyve_log"
}

sound_playback_count()
{
	awk '
	/^vtsnd: playback stream=[0-9]+ bytes=[0-9]+ total=[0-9]+$/ {
		count++
	}
	END {
		printf "%.0f\n", count
	}
	' "$bhyve_log"
}

start_checkpoint_workload()
{
	kind=$1
	guest_cmd "set -eu; rm -f /tmp/gcheckpoint-$kind.count /tmp/gcheckpoint-$kind.count.new /tmp/gcheckpoint-$kind.pid /tmp/gcheckpoint-$kind.log; nohup python3 /tmp/gcheckpoint.py '$kind' /tmp/gcheckpoint-$kind.count >/tmp/gcheckpoint-$kind.log 2>&1 & echo \$! >/tmp/gcheckpoint-$kind.pid; i=0; while [ \"\$i\" -lt 30 ]; do pid=\$(cat /tmp/gcheckpoint-$kind.pid); count=\$(cat /tmp/gcheckpoint-$kind.count 2>/dev/null || echo 0); kill -0 \"\$pid\" 2>/dev/null && [ \"\$count\" -ge 2 ] && break; sleep 1; i=\$((i + 1)); done; pid=\$(cat /tmp/gcheckpoint-$kind.pid); count=\$(cat /tmp/gcheckpoint-$kind.count 2>/dev/null || echo 0); kill -0 \"\$pid\"; [ \"\$count\" -ge 2 ]; cp /tmp/gcheckpoint-$kind.count /tmp/gcheckpoint-$kind.baseline" 45
	echo "PASS active-checkpoint-start device=$kind"
}

verify_checkpoint_workload()
{
	kind=$1
	guest_cmd "set -eu; pid=\$(cat /tmp/gcheckpoint-$kind.pid); kill -0 \"\$pid\"; baseline=\$(cat /tmp/gcheckpoint-$kind.baseline); case \"\$baseline\" in ''|*[!0-9]*) exit 1;; esac; i=0; while [ \"\$i\" -lt 30 ]; do now=\$(cat /tmp/gcheckpoint-$kind.count 2>/dev/null || echo 0); case \"\$now\" in ''|*[!0-9]*) now=0;; esac; [ \"\$now\" -gt \"\$baseline\" ] && break; sleep 1; i=\$((i + 1)); done; kill -0 \"\$pid\"; [ \"\$now\" -gt \"\$baseline\" ]; cp /tmp/gcheckpoint-$kind.count /tmp/gcheckpoint-$kind.baseline" 45
	echo "PASS active-checkpoint-progress device=$kind"
}

stop_checkpoint_workload()
{
	kind=$1
	# Active device I/O can be paused while the checkpoint is unwound.  Give
	# the guest worker a bounded graceful stop, then explicitly reap the test
	# workload rather than carrying it into the next case or leaving it behind
	# after a failed restore.  A process still alive after KILL is reported as
	# a real device/lifecycle failure; it is never silently ignored.
	guest_cmd "set -eu; pid=\$(cat /tmp/gcheckpoint-$kind.pid); kill -TERM \"\$pid\" 2>/dev/null || true; i=0; while kill -0 \"\$pid\" 2>/dev/null && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; if kill -0 \"\$pid\" 2>/dev/null; then kill -KILL \"\$pid\" 2>/dev/null || true; i=0; while kill -0 \"\$pid\" 2>/dev/null && [ \"\$i\" -lt 5 ]; do sleep 1; i=\$((i + 1)); done; if kill -0 \"\$pid\" 2>/dev/null; then cat /tmp/gcheckpoint-$kind.log >&2; exit 1; fi; fi; test -s /tmp/gcheckpoint-$kind.count" 45
	echo "PASS active-checkpoint-stop device=$kind"
}

start_mem_checkpoint_workload()
{
	mem_checkpoint_guest_opt=
	[ "$MEM_PACKED" = no ] || mem_checkpoint_guest_opt=" packed"
	guest_cmd "set -eu; rm -f /tmp/gcheckpoint-mem.count /tmp/gcheckpoint-mem.count.new /tmp/gcheckpoint-mem.baseline /tmp/gcheckpoint-mem.pid /tmp/gcheckpoint-mem.log; nohup python3 /tmp/gmem.py checkpoint /tmp/gcheckpoint-mem.count '$mem_requested_bytes' '$MEM_CHECKPOINT_ALLOC_MB'$mem_checkpoint_guest_opt >/tmp/gcheckpoint-mem.log 2>&1 & echo \$! >/tmp/gcheckpoint-mem.pid; i=0; while [ \"\$i\" -lt 90 ]; do pid=\$(cat /tmp/gcheckpoint-mem.pid); count=\$(cat /tmp/gcheckpoint-mem.count 2>/dev/null || echo 0); kill -0 \"\$pid\" 2>/dev/null && [ \"\$count\" -ge 2 ] && break; sleep 1; i=\$((i + 1)); done; pid=\$(cat /tmp/gcheckpoint-mem.pid); count=\$(cat /tmp/gcheckpoint-mem.count 2>/dev/null || echo 0); if ! kill -0 \"\$pid\" 2>/dev/null || [ \"\$count\" -lt 2 ]; then cat /tmp/gcheckpoint-mem.log >&2; exit 1; fi; cp /tmp/gcheckpoint-mem.count /tmp/gcheckpoint-mem.baseline" 105
	echo "PASS active-checkpoint-start device=mem pinned_pages=8 allocation=${MEM_CHECKPOINT_ALLOC_MB}MiB"
}

start_input_checkpoint_workload()
{
	input_checkpoint_guest_opt=
	[ "$INPUT_PACKED" = no ] ||
	    input_checkpoint_guest_opt=" packed"
	staged_before=$(grep -c \
	    'vtinput: staged event type=1 code=30 value=1 count=1' \
	    "$bhyve_log" 2>/dev/null || true)
	guest_cmd "set -eu; rm -f /tmp/gcheckpoint-input.count /tmp/gcheckpoint-input.count.new /tmp/gcheckpoint-input.baseline /tmp/gcheckpoint-input.pid /tmp/gcheckpoint-input.log; nohup python3 /tmp/ginput.py '$input_name' '$transport'$input_checkpoint_guest_opt checkpoint /tmp/gcheckpoint-input.count >/tmp/gcheckpoint-input.log 2>&1 & echo \$! >/tmp/gcheckpoint-input.pid; i=0; while ! grep -q '^READY$' /tmp/gcheckpoint-input.log 2>/dev/null && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; pid=\$(cat /tmp/gcheckpoint-input.pid); kill -0 \"\$pid\"; grep -q '^READY$' /tmp/gcheckpoint-input.log; printf '0\\n' > /tmp/gcheckpoint-input.baseline" 45
	printf 'down\n' > "$input_fifo"
	i=0
	while [ "$i" -lt 20 ]; do
		staged_after=$(grep -c \
		    'vtinput: staged event type=1 code=30 value=1 count=1' \
		    "$bhyve_log" 2>/dev/null || true)
		[ "$staged_after" -gt "$staged_before" ] && break
		kill -0 "$input_pid" 2>/dev/null || {
			cat "$input_log" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	[ "$i" -lt 20 ] || {
		echo "bhyve did not stage the partial input frame" >&2
		tail -n 80 "$bhyve_log" >&2
		return 1
	}
	echo "PASS active-checkpoint-start device=input staged=$staged_after"
}

verify_input_checkpoint_workload()
{
	finished_before=$(grep -c '^PASS finish=' "$input_log" \
	    2>/dev/null || true)
	printf 'finish\n' > "$input_fifo"
	guest_cmd "set -eu; pid=\$(cat /tmp/gcheckpoint-input.pid); kill -0 \"\$pid\"; baseline=\$(cat /tmp/gcheckpoint-input.baseline); case \"\$baseline\" in ''|*[!0-9]*) exit 1;; esac; i=0; while [ \"\$i\" -lt 30 ]; do now=\$(cat /tmp/gcheckpoint-input.count 2>/dev/null || echo 0); case \"\$now\" in ''|*[!0-9]*) now=0;; esac; [ \"\$now\" -gt \"\$baseline\" ] && break; sleep 1; i=\$((i + 1)); done; kill -0 \"\$pid\"; [ \"\$now\" -gt \"\$baseline\" ]; cp /tmp/gcheckpoint-input.count /tmp/gcheckpoint-input.baseline; grep -q \"^PASS checkpoint-frame=\$now\$\" /tmp/gcheckpoint-input.log" 45
	i=0
	while [ "$i" -lt 20 ]; do
		finished_after=$(grep -c '^PASS finish=' "$input_log" \
		    2>/dev/null || true)
		[ "$finished_after" -gt "$finished_before" ] && break
		kill -0 "$input_pid" 2>/dev/null || {
			cat "$input_log" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	[ "$i" -lt 20 ] || {
		echo "host input provider did not observe restored guest status" >&2
		cat "$input_log" >&2
		return 1
	}
	echo "PASS active-checkpoint-progress device=input frame=$finished_after"
}

stop_input_checkpoint_workload()
{
	guest_cmd "set -eu; pid=\$(cat /tmp/gcheckpoint-input.pid); kill -TERM \"\$pid\" 2>/dev/null || true; i=0; while kill -0 \"\$pid\" 2>/dev/null && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; if kill -0 \"\$pid\" 2>/dev/null; then cat /tmp/gcheckpoint-input.log >&2; exit 1; fi; test -s /tmp/gcheckpoint-input.count" 45
	echo "PASS active-checkpoint-stop device=input"
}

start_gpu_checkpoint_workload()
{
	guest_cmd "set -eu; rm -f /tmp/gcheckpoint-gpu.count /tmp/gcheckpoint-gpu.count.new /tmp/gcheckpoint-gpu.control /tmp/gcheckpoint-gpu.baseline /tmp/gcheckpoint-gpu.pid /tmp/gcheckpoint-gpu.log; nohup python3 /tmp/ggpu.py checkpoint '$GPU_WIDTH' '$GPU_HEIGHT' /tmp/gcheckpoint-gpu.count /tmp/gcheckpoint-gpu.control >/tmp/gcheckpoint-gpu.log 2>&1 & echo \$! >/tmp/gcheckpoint-gpu.pid; i=0; while [ \"\$i\" -lt 30 ]; do pid=\$(cat /tmp/gcheckpoint-gpu.pid); count=\$(cat /tmp/gcheckpoint-gpu.count 2>/dev/null || echo 0); kill -0 \"\$pid\" 2>/dev/null && [ \"\$count\" -eq 1 ] && break; sleep 1; i=\$((i + 1)); done; pid=\$(cat /tmp/gcheckpoint-gpu.pid); count=\$(cat /tmp/gcheckpoint-gpu.count 2>/dev/null || echo 0); kill -0 \"\$pid\"; [ \"\$count\" -eq 1 ]; cp /tmp/gcheckpoint-gpu.count /tmp/gcheckpoint-gpu.baseline" 45
	echo "PASS active-checkpoint-start device=gpu framebuffer-marker=1"
}

verify_gpu_checkpoint_workload()
{
	guest_cmd "set -eu; pid=\$(cat /tmp/gcheckpoint-gpu.pid); kill -0 \"\$pid\"; baseline=\$(cat /tmp/gcheckpoint-gpu.baseline); case \"\$baseline\" in ''|*[!0-9]*) exit 1;; esac; requested=\$((baseline + 1)); printf '%s\\n' \"\$requested\" > /tmp/gcheckpoint-gpu.control; i=0; while [ \"\$i\" -lt 30 ]; do now=\$(cat /tmp/gcheckpoint-gpu.count 2>/dev/null || echo 0); case \"\$now\" in ''|*[!0-9]*) now=0;; esac; [ \"\$now\" -eq \"\$requested\" ] && break; sleep 1; i=\$((i + 1)); done; if ! kill -0 \"\$pid\" 2>/dev/null || [ \"\$now\" -ne \"\$requested\" ]; then cat /tmp/gcheckpoint-gpu.log >&2; exit 1; fi; cp /tmp/gcheckpoint-gpu.count /tmp/gcheckpoint-gpu.baseline" 45
	if [ "$GPU_DISPLAY" = yes ]; then
		# checkpoint_pattern(2, ...)[0:4], independently reproduced here.
		"$tools/gpu-rfb-check" "$DIR/gpu-vnc.sock" \
		    "$GPU_WIDTH" "$GPU_HEIGHT" 759abfe4
	fi
	echo "PASS active-checkpoint-progress device=gpu framebuffer-marker=restored"
}

stop_gpu_checkpoint_workload()
{
	guest_cmd "set -eu; pid=\$(cat /tmp/gcheckpoint-gpu.pid); kill -TERM \"\$pid\" 2>/dev/null || true; i=0; while kill -0 \"\$pid\" 2>/dev/null && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; if kill -0 \"\$pid\" 2>/dev/null; then cat /tmp/gcheckpoint-gpu.log >&2; exit 1; fi; test -s /tmp/gcheckpoint-gpu.count" 45
	echo "PASS active-checkpoint-stop device=gpu"
}

start_rtc_checkpoint_workload()
{
	guest_cmd "set -eu; rm -f /tmp/gcheckpoint-rtc.count /tmp/gcheckpoint-rtc.count.new /tmp/gcheckpoint-rtc.pid /tmp/gcheckpoint-rtc.log; nohup python3 /tmp/grtc.py checkpoint-alarm /tmp/gcheckpoint-rtc.count '$RTC_CHECKPOINT_ALARM_SECONDS' >/tmp/gcheckpoint-rtc.log 2>&1 & echo \$! >/tmp/gcheckpoint-rtc.pid; i=0; while [ \"\$i\" -lt 30 ]; do pid=\$(cat /tmp/gcheckpoint-rtc.pid); count=\$(cat /tmp/gcheckpoint-rtc.count 2>/dev/null || echo 0); kill -0 \"\$pid\" 2>/dev/null && [ \"\$count\" -eq 1 ] && break; sleep 1; i=\$((i + 1)); done; pid=\$(cat /tmp/gcheckpoint-rtc.pid); count=\$(cat /tmp/gcheckpoint-rtc.count 2>/dev/null || echo 0); kill -0 \"\$pid\"; [ \"\$count\" -eq 1 ]; grep -q '^READY alarm=[0-9][0-9]*$' /tmp/gcheckpoint-rtc.log" 45
	echo "PASS active-checkpoint-start device=rtc alarm=pending"
}

verify_rtc_checkpoint_workload()
{
	rtc_checkpoint_wait=$((RTC_CHECKPOINT_ALARM_SECONDS + 120))
	guest_cmd "set -eu; pid=\$(cat /tmp/gcheckpoint-rtc.pid); kill -0 \"\$pid\"; i=0; while [ \"\$i\" -lt '$rtc_checkpoint_wait' ]; do count=\$(cat /tmp/gcheckpoint-rtc.count 2>/dev/null || echo 0); [ \"\$count\" -eq 2 ] && break; sleep 1; i=\$((i + 1)); done; if ! kill -0 \"\$pid\" 2>/dev/null || [ \"\$count\" -ne 2 ]; then cat /tmp/gcheckpoint-rtc.log >&2; exit 1; fi; grep -q '^ALARM irq=0x' /tmp/gcheckpoint-rtc.log" "$((rtc_checkpoint_wait + 15))"
	echo "PASS active-checkpoint-progress device=rtc alarm=delivered"
}

stop_rtc_checkpoint_workload()
{
	guest_cmd "set -eu; pid=\$(cat /tmp/gcheckpoint-rtc.pid); kill -TERM \"\$pid\" 2>/dev/null || true; i=0; while kill -0 \"\$pid\" 2>/dev/null && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; if kill -0 \"\$pid\" 2>/dev/null; then cat /tmp/gcheckpoint-rtc.log >&2; exit 1; fi; [ \"\$(cat /tmp/gcheckpoint-rtc.count)\" -eq 2 ]" 45
	echo "PASS active-checkpoint-stop device=rtc"
}

balloon_statistics_count()
{
	grep -c '^vtballoon: statistics sample' "$bhyve_log" 2>/dev/null ||
	    true
}

start_balloon_checkpoint_workload()
{
	[ "$BALLOON_STATS_INTERVAL" -ne 0 ] || {
		echo "balloon checkpoint requires an active statistics interval" >&2
		return 1
	}
	balloon_checkpoint_stats=$(balloon_statistics_count)
	i=0
	while [ "$i" -lt 30 ]; do
		now=$(balloon_statistics_count)
		[ "$now" -gt "$balloon_checkpoint_stats" ] && break
		sleep 1
		i=$((i + 1))
	done
	[ "$i" -lt 30 ] || {
		echo "balloon statistics queue did not refresh before checkpoint" >&2
		return 1
	}
	balloon_checkpoint_stats=$now
	echo "PASS active-checkpoint-start device=balloon statistics=$now"
}

verify_balloon_checkpoint_workload()
{
	i=0
	while [ "$i" -lt 30 ]; do
		now=$(balloon_statistics_count)
		[ "$now" -gt "$balloon_checkpoint_stats" ] && break
		sleep 1
		i=$((i + 1))
	done
	[ "$i" -lt 30 ] || {
		echo "restored balloon statistics queue did not refresh" >&2
		return 1
	}
	balloon_checkpoint_stats=$now
	echo "PASS active-checkpoint-progress device=balloon statistics=$now"
}

start_sound_checkpoint_workload()
{
	sound_before=$(sound_playback_total)
	guest_cmd "python3 /tmp/gsnd.py checkpoint-start '$transport'$(sound_checkpoint_guest_opt) '$SOUND_BACKEND'" 30
	i=0
	while [ "$i" -lt 20 ]; do
		sound_after=$(sound_playback_total)
		if [ "$sound_after" -gt "$sound_before" ]; then
			sound_checkpoint_playback=$(sound_playback_count)
			echo "PASS host-sound-checkpoint-active playback_before=$sound_before playback_after=$sound_after"
			return 0
		fi
		sleep 1
		i=$((i + 1))
	done
	echo "sound checkpoint workload did not reach the host PCM path" >&2
	return 1
}

verify_sound_checkpoint_workload()
{
	guest_cmd "python3 /tmp/gsnd.py checkpoint-verify '$transport'$(sound_checkpoint_guest_opt) '$SOUND_BACKEND'" 30
	i=0
	while [ "$i" -lt 20 ]; do
		sound_after=$(sound_playback_count)
		if [ "$sound_after" -gt "$sound_checkpoint_playback" ]; then
			echo "PASS active-checkpoint-progress device=sound completions_before=$sound_checkpoint_playback completions_after=$sound_after"
			sound_checkpoint_playback=$sound_after
			return 0
		fi
		sleep 1
		i=$((i + 1))
	done
	echo "restored sound playback queue made no host-side progress" >&2
	return 1
}

start_checkpoint_workloads()
{
	start_checkpoint_workload net
	start_nonvirtio_checkpoint_workload
	[ "$run_rng_device" = no ] || start_checkpoint_workload rng
	[ "$run_block_device" = no ] || start_checkpoint_workload block
	[ "$run_scsi_device" = no ] || start_checkpoint_workload scsi
	[ "$run_pmem_device" = no ] || start_checkpoint_workload pmem
	[ "$run_input_device" = no ] || start_input_checkpoint_workload
	[ "$run_gpu_device" = no ] || start_gpu_checkpoint_workload
	[ "$run_balloon_device" = no ] ||
	    start_balloon_checkpoint_workload
	[ "$CHECKPOINT_ACTIVE_MEM" = no ] ||
	    start_mem_checkpoint_workload
	[ "$run_sound_device" = no ] || start_sound_checkpoint_workload
	# Arm the time-sensitive RTC alarm only after every potentially slow
	# workload has reached its checkpoint boundary.
	[ "$run_rtc_device" = no ] || [ "$RTC_ALARM" = no ] ||
	    start_rtc_checkpoint_workload
}

verify_checkpoint_workloads()
{
	verify_checkpoint_workload net
	verify_nonvirtio_checkpoint_workload
	[ "$run_rng_device" = no ] || verify_checkpoint_workload rng
	[ "$run_block_device" = no ] || verify_checkpoint_workload block
	[ "$run_scsi_device" = no ] || verify_checkpoint_workload scsi
	[ "$run_pmem_device" = no ] || verify_checkpoint_workload pmem
	[ "$run_input_device" = no ] || verify_input_checkpoint_workload
	[ "$run_gpu_device" = no ] || verify_gpu_checkpoint_workload
	[ "$run_rtc_device" = no ] || [ "$RTC_ALARM" = no ] ||
	    verify_rtc_checkpoint_workload
	[ "$run_balloon_device" = no ] ||
	    verify_balloon_checkpoint_workload
	[ "$CHECKPOINT_ACTIVE_MEM" = no ] ||
	    verify_checkpoint_workload mem
	[ "$run_sound_device" = no ] ||
	    verify_sound_checkpoint_workload
}

stop_checkpoint_workloads()
{
	stop_checkpoint_workload net
	stop_nonvirtio_checkpoint_workload
	[ "$run_rng_device" = no ] || stop_checkpoint_workload rng
	[ "$run_block_device" = no ] || stop_checkpoint_workload block
	[ "$run_scsi_device" = no ] || stop_checkpoint_workload scsi
	[ "$run_pmem_device" = no ] || stop_checkpoint_workload pmem
	[ "$run_input_device" = no ] || stop_input_checkpoint_workload
	[ "$run_gpu_device" = no ] || stop_gpu_checkpoint_workload
	[ "$run_rtc_device" = no ] || [ "$RTC_ALARM" = no ] ||
	    stop_rtc_checkpoint_workload
	[ "$CHECKPOINT_ACTIVE_MEM" = no ] ||
	    stop_checkpoint_workload mem
	[ "$run_sound_device" = no ] ||
	    guest_cmd "python3 /tmp/gsnd.py checkpoint-stop '$transport'$(sound_checkpoint_guest_opt) '$SOUND_BACKEND'" 30
}

guest_cmd()
{
	CONSOLE_LOG=$console_log CONSOLE_INPUT=$console_input \
	    sh "$here/acmd-console.sh" "$1" "${2:-30}"
}

copy_guest_file()
{
	source=$1
	destination=$2
	set -- $(cksum < "$source")
	expected_sum=$1
	expected_size=$2

	guest_cmd ": > '$destination.b64'" 30
	{ base64 < "$source" | tr -d '\n'; printf '\n'; } | fold -w 1024 |
	while IFS= read -r chunk; do
		guest_cmd "printf %s '$chunk' >> '$destination.b64'" 30
	done
	guest_cmd "base64 -d '$destination.b64' > '$destination' && rm -f '$destination.b64' && set -- \$(cksum < '$destination') && [ \"\$1\" = '$expected_sum' ] && [ \"\$2\" = '$expected_size' ]" 30
}

provision_guest()
{
	wait_for_login 120
	printf 'root\r' >> "$console_input"
	wait_for ':~#' 30
	if [ "$VIRTIO_IOMMU" = yes ]; then
		guest_cmd 'modprobe virtio_iommu' 30
	fi
	guest_cmd 'set -eu; ip link set eth0 up; udhcpc -n -q -t 5 -T 3 -i eth0; release=$(cut -d. -f1,2 /etc/alpine-release); case "$release" in *.*) ;; *) echo "invalid Alpine release: $release" >&2; exit 1;; esac; major=${release%.*}; minor=${release#*.}; case "$major:$minor" in *[!0-9:]*|:|*:) echo "invalid Alpine release: $release" >&2; exit 1;; esac; repository="https://dl-cdn.alpinelinux.org/alpine/v${release}/main"; printf "%s\n" "$repository" > /etc/apk/repositories; apk add --no-cache ethtool python3; printf "PROVISION alpine=%s kernel=%s repository=%s " "$(cat /etc/alpine-release)" "$(uname -r)" "$repository"; python3 --version' 150
	copy_guest_file "$here/gnet.py" /tmp/gnet.py
	guest_cmd 'python3 /tmp/gnet.py --self-test | grep -q "^SELFTEST PASS$"' 30
	copy_guest_file "$here/gvirtio_features.py" /tmp/gvirtio_features.py
	guest_cmd 'python3 /tmp/gvirtio_features.py --self-test | grep -q "^SELFTEST PASS$"' 30
	if [ "$NONVIRTIO_DEVICE" != none ]; then
		copy_guest_file "$here/gnonvirtio.py" /tmp/gnonvirtio.py
		guest_cmd 'python3 /tmp/gnonvirtio.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	case "$NONVIRTIO_DEVICE" in
	nvme) guest_cmd 'apk add --no-cache nvme-cli; modprobe nvme' 120 ;;
	hda) guest_cmd 'apk add --no-cache alsa-utils; modprobe snd_hda_intel' 120 ;;
	xhci) guest_cmd 'modprobe xhci_pci; modprobe usbhid' 30 ;;
	fbuf) guest_cmd 'modprobe simplefb 2>/dev/null || true' 30 ;;
	pci-uart) guest_cmd 'modprobe 8250_pci' 30 ;;
	tpm-crb) guest_cmd 'apk add --no-cache tpm2-tools; modprobe tpm_crb' 120 ;;
	pvpanic) guest_cmd 'modprobe pvpanic 2>/dev/null || modprobe pvpanic-pci 2>/dev/null || true' 30 ;;
	i6300esb) guest_cmd 'modprobe i6300esb 2>/dev/null || true; i=0; while [ ! -e /sys/class/watchdog/watchdog0 ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done' 30 ;;
	qemu-fwcfg)
		guest_cmd 'apk add --no-cache build-base' 120
		copy_guest_file "$here/freebsd-fwcfg-check.c" /tmp/fwcfg-check.c
		guest_cmd 'cc -O2 -Wall -Wextra -Werror -o /tmp/fwcfg-check /tmp/fwcfg-check.c; /tmp/fwcfg-check --self-test | grep -q "^SELFTEST PASS$"' 60
		;;
	esac
	if [ "$CHECKPOINT_TEST" = yes ]; then
		copy_guest_file "$here/gcheckpoint.py" /tmp/gcheckpoint.py
		guest_cmd 'python3 /tmp/gcheckpoint.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$VIRTIO_IOMMU" = yes ]; then
		copy_guest_file "$here/giommu.py" /tmp/giommu.py
		guest_cmd 'python3 /tmp/giommu.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_vsock" = yes ]; then
		guest_cmd 'modprobe vsock; modprobe vmw_vsock_virtio_transport' 30
		copy_guest_file "$here/gvsock.py" /tmp/gvsock.py
		guest_cmd 'python3 /tmp/gvsock.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_input_device" = yes ]; then
		guest_cmd 'modprobe virtio_input' 30
		copy_guest_file "$here/ginput.py" /tmp/ginput.py
		guest_cmd 'python3 /tmp/ginput.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_rng_device" = yes ]; then
		guest_cmd 'modprobe virtio_rng' 30
		copy_guest_file "$here/grng.py" /tmp/grng.py
		guest_cmd 'python3 /tmp/grng.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_balloon_device" = yes ]; then
		guest_cmd 'modprobe virtio_balloon' 30
		copy_guest_file "$here/gballoon.py" /tmp/gballoon.py
		guest_cmd 'python3 /tmp/gballoon.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_rtc_device" = yes ]; then
		guest_cmd 'modprobe virtio_rtc' 30
		copy_guest_file "$here/grtc.py" /tmp/grtc.py
		guest_cmd 'python3 /tmp/grtc.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_block_device" = yes ]; then
		guest_cmd 'modprobe virtio_blk' 30
		copy_guest_file "$here/gblock.py" /tmp/gblock.py
		guest_cmd 'python3 /tmp/gblock.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_scsi_device" = yes ]; then
		guest_cmd 'modprobe virtio_scsi' 30
		copy_guest_file "$here/gscsi.py" /tmp/gscsi.py
		guest_cmd 'python3 /tmp/gscsi.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_console_device" = yes ]; then
		guest_cmd 'modprobe virtio_console' 30
		copy_guest_file "$here/gconsole.py" /tmp/gconsole.py
		guest_cmd 'python3 /tmp/gconsole.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_9p_device" = yes ]; then
		guest_cmd 'modprobe 9p; modprobe 9pnet; modprobe 9pnet_virtio' 30
		copy_guest_file "$here/g9p.py" /tmp/g9p.py
		guest_cmd 'python3 /tmp/g9p.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_fs_device" = yes ]; then
		guest_cmd 'modprobe virtiofs' 30
	fi
	if [ "$run_gpu_device" = yes ]; then
		guest_cmd 'modprobe virtio_gpu' 30
		copy_guest_file "$here/ggpu.py" /tmp/ggpu.py
		guest_cmd 'python3 /tmp/ggpu.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_mem_device" = yes ]; then
		guest_cmd 'modprobe virtio_mem' 30
		copy_guest_file "$here/gmem.py" /tmp/gmem.py
		guest_cmd 'python3 /tmp/gmem.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_pmem_device" = yes ]; then
		guest_cmd 'modprobe libnvdimm; modprobe nd_pmem; modprobe virtio_pmem' 30
		copy_guest_file "$here/gpmem.py" /tmp/gpmem.py
		guest_cmd 'python3 /tmp/gpmem.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_sound_device" = yes ]; then
		guest_cmd 'apk add --no-cache alsa-utils; modprobe snd_virtio' 120
		copy_guest_file "$here/gsnd.py" /tmp/gsnd.py
		guest_cmd 'python3 /tmp/gsnd.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
}

run_nonvirtio()
{
	case "$NONVIRTIO_DEVICE" in
	none) return 0 ;;
	ahci)
		guest_cmd "python3 /tmp/gnonvirtio.py block-io '$NONVIRTIO_DEVICE' 0000:00:15.0 live-$transport-$$" 45
		;;
	nvme)
		guest_cmd "python3 /tmp/gnonvirtio.py block-io nvme 0000:00:15.0 live-$transport-$$; controller=\$(basename /sys/bus/pci/devices/0000:00:15.0/nvme/nvme*); test \"\$(cat /sys/class/nvme/\$controller/serial)\" = WASPNESTNVME; nvme id-ctrl /dev/\$controller | grep -q 'WASPNESTNVME'; queues=/sys/class/nvme/\$controller/queue_count; test ! -f \$queues || test \"\$(cat \$queues)\" -ge 2" 60
		;;
	e82545)
		guest_cmd "python3 /tmp/gnonvirtio.py probe e82545 0000:00:15.0; iface=\$(basename /sys/bus/pci/devices/0000:00:15.0/net/*); ip link set \"\$iface\" up; udhcpc -n -q -t 5 -T 3 -i \"\$iface\"; gateway=\$(ip route show default dev \"\$iface\" | awk 'NR == 1 { print \$3 }'); test -n \"\$gateway\"; ping -I \"\$iface\" -c 3 \"\$gateway\"; ethtool -i \"\$iface\" | grep -q '^driver: e1000$'" 90
		;;
	hda)
		guest_cmd "python3 /tmp/gnonvirtio.py probe hda 0000:00:15.0; card=\$(basename /sys/bus/pci/devices/0000:00:15.0/sound/card*); unit=\${card#card}; dd if=/dev/zero bs=4096 count=32 2>/dev/null | aplay -q -D hw:\$unit,0 -f S16_LE -c 2 -r 48000; arecord -q -D hw:\$unit,0 -f S16_LE -c 2 -r 48000 -d 1 /tmp/nonvirtio-hda.wav; test -s /tmp/nonvirtio-hda.wav" 45
		;;
	xhci)
		guest_cmd "python3 /tmp/gnonvirtio.py probe xhci 0000:00:15.0; test -n \"\$(find /sys/bus/pci/devices/0000:00:15.0 -name idVendor -o -name descriptors | head -n 1)\"; grep -Rqs 'HID' /sys/bus/pci/devices/0000:00:15.0/usb* 2>/dev/null || find /sys/bus/pci/devices/0000:00:15.0 -path '*/input/input*' | grep -q ." 30
		;;
	fbuf)
		guest_cmd "python3 /tmp/gnonvirtio.py framebuffer-io 0000:00:15.0 live-$transport-$$" 30
		"$tools/gpu-rfb-check" "$nonvirtio_fbuf_socket" 1024 768
		;;
	pci-uart)
		marker="PCI-UART-LIVE-$transport-$$"
		guest_cmd "python3 /tmp/gnonvirtio.py probe pci-uart 0000:00:15.0; tty=\$(basename /sys/bus/pci/devices/0000:00:15.0/tty/ttyS*); stty -F /dev/\$tty 115200 raw -echo; printf '%s\\n' '$marker' > /dev/\$tty" 30
		grep -q "$marker" "$nonvirtio_uart_log"
		;;
	lpc-uart)
		marker="LPC-UART-LIVE-$transport-$$"
		guest_cmd "test -c /dev/ttyS1; stty -F /dev/ttyS1 115200 raw -echo; printf '%s\\n' '$marker' > /dev/ttyS1" 30
		grep -q "$marker" "$nonvirtio_uart_log"
		;;
	tpm-crb)
		guest_cmd "test -c /dev/tpmrm0 -o -c /dev/tpm0; tpm2_getrandom 32 -o /tmp/nonvirtio-tpm.random; test \"\$(wc -c < /tmp/nonvirtio-tpm.random)\" = 32; tpm2_pcrread sha256:0 >/tmp/nonvirtio-pcr" 45
		;;
	pvpanic)
		guest_cmd "test -d /sys/bus/acpi/devices/QEMU0001:00; python3 /tmp/gnonvirtio.py pvpanic 2" 30
		grep -q 'pvpanic: guest reported event 0x02' "$bhyve_log"
		pvpanic_event_count=$(grep -c 'pvpanic: guest reported event 0x02' "$bhyve_log")
		;;
	i6300esb)
		# First, prove the safe path: arm, pat, and disarm without ever
		# letting the timer lapse.  Then, gated by WATCHDOG_EXPECT_RESET, stop
		# feeding and let it fire; bhyve runs action=notify so the guest
		# survives and the host action lands in the log for us to observe.
		guest_cmd "python3 /tmp/gnonvirtio.py watchdog 0000:00:15.0" 30
		guest_cmd "env WATCHDOG_EXPECT_RESET=1 python3 /tmp/gnonvirtio.py watchdog 0000:00:15.0" 60
		grep -q 'i6300esb: watchdog expired, applying action "notify"' "$bhyve_log"
		;;
	qemu-fwcfg)
		guest_cmd "/tmp/fwcfg-check live '$NONVIRTIO_FWCFG_NAME' '$NONVIRTIO_FWCFG_VALUE'" 30
		;;
	hostbridge)
		guest_cmd "python3 /tmp/gnonvirtio.py probe hostbridge 0000:00:00.0; test \"\$(find /sys/bus/pci/devices -mindepth 1 -maxdepth 1 -type l | wc -l)\" -ge 4" 30
		;;
	passthru)
		guest_cmd "$NONVIRTIO_PASSTHRU_LINUX_ASSERT" 60
		;;
	esac
	echo "PASS nonvirtio-live guest=alpine device=$NONVIRTIO_DEVICE"
}

nonvirtio_checkpoint_operation()
{
	case "$NONVIRTIO_DEVICE" in
	ahci|nvme) printf '%s' "python3 /tmp/gnonvirtio.py block-io '$NONVIRTIO_DEVICE' 0000:00:15.0 checkpoint-\$i" ;;
	e82545) printf '%s' 'iface=$(basename /sys/bus/pci/devices/0000:00:15.0/net/*); gateway=$(ip route show default dev "$iface" | awk '\''NR == 1 { print $3 }'\''); ping -I "$iface" -c 1 -W 2 "$gateway" >/dev/null' ;;
	hda) printf '%s' 'card=$(basename /sys/bus/pci/devices/0000:00:15.0/sound/card*); unit=${card#card}; dd if=/dev/zero bs=4096 count=4 2>/dev/null | aplay -q -D hw:$unit,0 -f S16_LE -c 2 -r 48000' ;;
	xhci) printf '%s' 'find /sys/bus/pci/devices/0000:00:15.0 -name descriptors -exec dd if={} of=/dev/null bs=64 count=1 status=none \;' ;;
	fbuf) printf '%s' 'python3 /tmp/gnonvirtio.py framebuffer-io 0000:00:15.0 checkpoint-$i' ;;
	pci-uart) printf '%s' 'tty=$(basename /sys/bus/pci/devices/0000:00:15.0/tty/ttyS*); printf "PCI-UART-CHECKPOINT-%s\n" "$i" > /dev/$tty' ;;
	lpc-uart) printf '%s' 'printf "LPC-UART-CHECKPOINT-%s\n" "$i" > /dev/ttyS1' ;;
	pvpanic) printf '%s' 'python3 /tmp/gnonvirtio.py probe hostbridge 0000:00:00.0 >/dev/null' ;;
	i6300esb) printf '%s' 'python3 /tmp/gnonvirtio.py watchdog 0000:00:15.0 >/dev/null' ;;
	hostbridge) printf '%s' 'python3 /tmp/gnonvirtio.py probe hostbridge 0000:00:00.0 >/dev/null' ;;
	*) return 1 ;;
	esac
}

start_nonvirtio_checkpoint_workload()
{
	[ "$NONVIRTIO_DEVICE" = none ] && return 0
	case "$NONVIRTIO_DEVICE" in tpm-crb|passthru) return 0 ;; esac
	if [ "$NONVIRTIO_DEVICE" = qemu-fwcfg ]; then
		nonvirtio_checkpoint_phase=${nonvirtio_checkpoint_phase:-0}
		phase=$((nonvirtio_checkpoint_phase + 1))
		guest_cmd "set -eu; rm -f /tmp/fwcfg.ready.$phase /tmp/fwcfg.go.$phase /tmp/fwcfg.result.$phase /tmp/nonvirtio-checkpoint.log; nohup /tmp/fwcfg-check active '$NONVIRTIO_FWCFG_NAME' '$NONVIRTIO_FWCFG_VALUE' /tmp/fwcfg.ready.$phase /tmp/fwcfg.go.$phase /tmp/fwcfg.result.$phase >/tmp/nonvirtio-checkpoint.log 2>&1 & echo \$! >/tmp/nonvirtio-checkpoint.pid; i=0; while [ ! -s /tmp/fwcfg.ready.$phase ] && kill -0 \$(cat /tmp/nonvirtio-checkpoint.pid) 2>/dev/null && [ \$i -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done; test -s /tmp/fwcfg.ready.$phase; kill -0 \$(cat /tmp/nonvirtio-checkpoint.pid)" 30
		nonvirtio_checkpoint_count=$nonvirtio_checkpoint_phase
		echo "PASS active-checkpoint-start device=qemu-fwcfg cursor-phase=$phase"
		return 0
	fi
	if [ "$NONVIRTIO_DEVICE" = xhci ]; then
		nonvirtio_checkpoint_phase=${nonvirtio_checkpoint_phase:-0}
		event=$((nonvirtio_checkpoint_phase + 1))
		guest_cmd "set -eu; event=\$(find /sys/bus/pci/devices/0000:00:15.0 -path '*/input/input*/event*' -printf '%f\\n' | head -n 1); test -n \"\$event\"; rm -f /tmp/nonvirtio-xhci.event.$event; dd if=/dev/input/\$event of=/tmp/nonvirtio-xhci.event.$event bs=24 count=1 2>/tmp/nonvirtio-checkpoint.log & echo \$! >/tmp/nonvirtio-checkpoint.pid; echo '$event' >/tmp/nonvirtio-checkpoint.event; echo '$nonvirtio_checkpoint_phase' >/tmp/nonvirtio-checkpoint.count" 30
		guest_cmd 'kill -0 $(cat /tmp/nonvirtio-checkpoint.pid)' 10
		nonvirtio_checkpoint_count=$nonvirtio_checkpoint_phase
		echo "PASS active-checkpoint-start device=xhci pending-transfer=$event"
		return 0
	fi
	if [ "$NONVIRTIO_DEVICE" = fbuf ]; then
		nonvirtio_checkpoint_phase=${nonvirtio_checkpoint_phase:-0}
		case $((nonvirtio_checkpoint_phase + 1)) in
		1) nonvirtio_fbuf_expected=759abfe4 ;;
		*) nonvirtio_fbuf_expected=86abc0f5 ;;
		esac
		guest_cmd "set -eu; python3 /tmp/gnonvirtio.py framebuffer-io 0000:00:15.0 checkpoint-$((nonvirtio_checkpoint_phase + 1)) '$nonvirtio_fbuf_expected'; echo '$nonvirtio_checkpoint_phase' >/tmp/nonvirtio-checkpoint.count; sleep 100000 & echo \$! >/tmp/nonvirtio-checkpoint.pid" 30
		nonvirtio_checkpoint_count=$nonvirtio_checkpoint_phase
		echo "PASS active-checkpoint-start device=fbuf pixel=$nonvirtio_fbuf_expected"
		return 0
	fi
	operation=$(nonvirtio_checkpoint_operation)
	guest_cmd "rm -f /tmp/nonvirtio-checkpoint.count /tmp/nonvirtio-checkpoint.log; (i=0; while :; do i=\$((i + 1)); $operation; printf '%s\\n' \"\$i\" > /tmp/nonvirtio-checkpoint.count; sleep 0.05; done) >/tmp/nonvirtio-checkpoint.log 2>&1 & echo \$! > /tmp/nonvirtio-checkpoint.pid" 30
	i=0
	while [ "$i" -lt 30 ]; do
		nonvirtio_checkpoint_count=$(guest_cmd 'cat /tmp/nonvirtio-checkpoint.count 2>/dev/null || echo 0' 10)
		[ "$nonvirtio_checkpoint_count" -gt 0 ] 2>/dev/null && break
		sleep 1; i=$((i + 1))
	done
	[ "$i" -lt 30 ] || { guest_cmd 'cat /tmp/nonvirtio-checkpoint.log' 10 >&2; return 1; }
	echo "PASS active-checkpoint-start device=$NONVIRTIO_DEVICE count=$nonvirtio_checkpoint_count"
}

verify_nonvirtio_checkpoint_workload()
{
	[ "$NONVIRTIO_DEVICE" = none ] && return 0
	case "$NONVIRTIO_DEVICE" in tpm-crb|passthru) return 0 ;; esac
	if [ "$NONVIRTIO_DEVICE" = qemu-fwcfg ]; then
		phase=$((nonvirtio_checkpoint_phase + 1))
		guest_cmd "set -eu; touch /tmp/fwcfg.go.$phase; i=0; while [ ! -s /tmp/fwcfg.result.$phase ] && kill -0 \$(cat /tmp/nonvirtio-checkpoint.pid) 2>/dev/null && [ \$i -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done; cat /tmp/nonvirtio-checkpoint.log; test \"\$(cat /tmp/fwcfg.result.$phase)\" = pass; i=0; while kill -0 \$(cat /tmp/nonvirtio-checkpoint.pid) 2>/dev/null && [ \$i -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done; ! kill -0 \$(cat /tmp/nonvirtio-checkpoint.pid) 2>/dev/null" 30
		nonvirtio_checkpoint_phase=$phase
		nonvirtio_checkpoint_count=$phase
		echo "PASS active-checkpoint-state device=qemu-fwcfg cursor-phase=$phase"
		return 0
	fi
	if [ "$NONVIRTIO_DEVICE" = xhci ]; then
		event=$((nonvirtio_checkpoint_phase + 1))
		"$tools/gpu-rfb-check" "$nonvirtio_fbuf_socket" 1024 768 \
		    --pointer $((300 + event)) $((320 + event)) 1
		guest_cmd "set -eu; pid=\$(cat /tmp/nonvirtio-checkpoint.pid); i=0; while kill -0 \$pid 2>/dev/null && [ \$i -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done; ! kill -0 \$pid 2>/dev/null; input_event=\$(cat /tmp/nonvirtio-checkpoint.event); test -s /tmp/nonvirtio-xhci.event.\$input_event; echo '$event' >/tmp/nonvirtio-checkpoint.count" 20
		nonvirtio_checkpoint_phase=$event
		nonvirtio_checkpoint_count=$event
		echo "PASS active-checkpoint-progress device=xhci pending-transfer=$event"
		return 0
	fi
	if [ "$NONVIRTIO_DEVICE" = fbuf ]; then
		# Inspect the restored BAR before any guest-side framebuffer writer can
		# repair lost state.
		"$tools/gpu-rfb-check" "$nonvirtio_fbuf_socket" 1024 768 \
		    "$nonvirtio_fbuf_expected"
		guest_cmd 'kill -0 $(cat /tmp/nonvirtio-checkpoint.pid)' 10
		nonvirtio_checkpoint_phase=$((nonvirtio_checkpoint_phase + 1))
		nonvirtio_checkpoint_count=$nonvirtio_checkpoint_phase
		echo "PASS active-checkpoint-state device=fbuf phase=$nonvirtio_checkpoint_phase pixel=$nonvirtio_fbuf_expected"
		return 0
	fi
	before=$nonvirtio_checkpoint_count
	i=0
	while [ "$i" -lt 30 ]; do
		after=$(guest_cmd 'cat /tmp/nonvirtio-checkpoint.count 2>/dev/null || echo 0' 10)
		[ "$after" -gt "$before" ] 2>/dev/null && break
		sleep 1; i=$((i + 1))
	done
	[ "$i" -lt 30 ] || { guest_cmd 'cat /tmp/nonvirtio-checkpoint.log' 10 >&2; return 1; }
	nonvirtio_checkpoint_count=$after
	if [ "$NONVIRTIO_DEVICE" = pvpanic ]; then
		before_events=${pvpanic_event_count:-0}
		guest_cmd 'python3 /tmp/gnonvirtio.py pvpanic 2' 30
		pvpanic_event_count=$(grep -c 'pvpanic: guest reported event 0x02' "$bhyve_log")
		[ "$pvpanic_event_count" -gt "$before_events" ] || {
			echo "restored pvpanic event did not reach host" >&2; return 1
		}
	fi
	echo "PASS active-checkpoint-progress device=$NONVIRTIO_DEVICE before=$before after=$after"
}

stop_nonvirtio_checkpoint_workload()
{
	[ "$NONVIRTIO_DEVICE" = none ] && return 0
	case "$NONVIRTIO_DEVICE" in tpm-crb|passthru) return 0 ;; esac
	guest_cmd 'test ! -s /tmp/nonvirtio-checkpoint.pid || kill $(cat /tmp/nonvirtio-checkpoint.pid) 2>/dev/null || true' 15
}

run_vsock_driver()
{
	case "$1" in
	full|smoke|churn) ;;
	*) echo "invalid vsock driver mode: $1" >&2; return 2 ;;
	esac
	DIR=$sockdir TRANSPORT=$transport VSOCK_BACKEND=$VSOCK_BACKEND \
	BACKEND=$VSOCK_BACKEND GUEST_CID=$CID GPY=/tmp/gvsock.py \
	VSOCK_PACKED="$VSOCK_PACKED" \
	TOOLS="$tools" MODE="$1" CHURN_CONNECTIONS="$VSOCK_SOAK_CONNECTIONS" \
	HOST_WORK="$2" \
	PORT_OFFSET="$PORT_OFFSET" \
	BHYVE_LOG="$bhyve_log" CONSOLE_LOG_PATH="$console_log" \
	ACMD="env CONSOLE_LOG=$console_log CONSOLE_INPUT=$console_input sh $here/acmd-console.sh" \
	    sh "$here/run-linux.sh"
}

run_matrix()
{
	run_vsock_driver full "$WORKDIR/$transport.host"
}

wait_vsock_provider_barrier()
{
	barrier_stage=$1

	[ -n "$VSOCK_BARRIER_DIR" ] || return 0
	case "$barrier_stage" in
	initial|pre-reset|post-reset|pre-checkpoint|post-checkpoint) ;;
	*) echo "invalid VSOCK provider barrier stage: $barrier_stage" >&2; return 2 ;;
	esac
	: > "$VSOCK_BARRIER_DIR/$barrier_stage-cid-$CID"
	i=0
	while :; do
		barrier_ready=yes
		for barrier_cid in $VSOCK_BARRIER_CIDS; do
			[ -f "$VSOCK_BARRIER_DIR/$barrier_stage-cid-$barrier_cid" ] ||
			    barrier_ready=no
		done
		[ "$barrier_ready" = yes ] && break
		[ "$i" -lt 180 ] || {
			echo "timed out waiting for VSOCK provider barrier" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	echo "PASS provider barrier stage=$barrier_stage CIDs=$VSOCK_BARRIER_CIDS"
}

process_fd_count()
{
	procstat -f "${1:-$vm_pid}" 2>/dev/null |
	    awk 'NR > 1 && $1 ~ /^[0-9]+$/ { n++ } END { print n + 0 }'
}

process_rss_kb()
{
	ps -o rss= -p "${1:-$vm_pid}" | awk '{ print $1 + 0 }'
}

kernel_vsock_malloc_stats()
{
	vmstat -m | awk '$1 == "vtvsock" { print $2, $3; found = 1 }
	    END { if (!found) print "0 0" }'
}

check_vsock_soak_resources()
{
	resource_stage=$1
	kill -0 "$vm_pid"
	cur_fds=$(process_fd_count)
	cur_rss=$(process_rss_kb)
	[ "$cur_fds" -le "$peak_fds" ] || peak_fds=$cur_fds
	[ "$cur_rss" -le "$peak_rss" ] || peak_rss=$cur_rss
	[ "$cur_fds" -gt 0 ] && [ "$cur_rss" -gt 0 ] || {
		echo "could not read bhyve resources after $resource_stage" >&2
		return 1
	}
	[ "$cur_fds" -le "$max_fds" ] || {
		echo "vsock soak fd growth after $resource_stage: baseline=$base_fds current=$cur_fds limit=$max_fds" >&2
		return 1
	}
	[ "$cur_rss" -le "$max_rss" ] || {
		echo "vsock soak RSS growth after $resource_stage: baseline=${base_rss}KB current=${cur_rss}KB limit=${max_rss}KB" >&2
		return 1
	}
	cur_conns=-
	cur_kallocs=-
	cur_kmem=-
	cur_drops=-
	if [ "$VSOCK_BACKEND" = kernel ]; then
		j=0
		while [ "$(sysctl -n kern.vsock.cur_connections)" -ne "$base_conns" ] &&
		    [ "$j" -lt 10 ]; do
			sleep 1
			j=$((j + 1))
		done
		cur_conns=$(sysctl -n kern.vsock.cur_connections)
		[ "$cur_conns" -eq "$base_conns" ] || {
			echo "vsock soak connection growth after $resource_stage: baseline=$base_conns current=$cur_conns" >&2
			return 1
		}
		set -- $(kernel_vsock_malloc_stats)
		cur_kallocs=$1
		cur_kmem=$2
		cur_drops=$(sysctl -n kern.vsock.rx_drops)
		[ "$cur_kallocs" -eq "$base_kallocs" ] &&
		    [ "$cur_kmem" -eq "$base_kmem" ] || {
			echo "vsock soak kernel allocation growth after $resource_stage: baseline=${base_kallocs}/${base_kmem} current=${cur_kallocs}/${cur_kmem}" >&2
			return 1
		}
		[ "$cur_drops" -eq "$base_drops" ] || {
			echo "vsock soak unexpected RX drops after $resource_stage: baseline=$base_drops current=$cur_drops" >&2
			return 1
		}
	fi
}

run_vsock_soak()
{
	[ "$VSOCK_SOAK_ITERATIONS" -gt 0 ] || return 0
	command -v procstat >/dev/null
	command -v ps >/dev/null
	sleep 2
	base_fds=$(process_fd_count)
	base_rss=$(process_rss_kb)
	[ "$base_fds" -gt 0 ] && [ "$base_rss" -gt 0 ] || {
		echo "could not read bhyve resource baseline for pid $vm_pid" >&2
		return 1
	}
	max_fds=$((base_fds + VSOCK_SOAK_MAX_FD_GROWTH))
	max_rss=$((base_rss + VSOCK_SOAK_MAX_RSS_KB))
	peak_fds=$base_fds
	peak_rss=$base_rss
	soak_started=$(date +%s)
	base_conns=-
	base_kallocs=-
	base_kmem=-
	base_drops=-
	if [ "$VSOCK_BACKEND" = kernel ]; then
		command -v vmstat >/dev/null
		base_conns=$(sysctl -n kern.vsock.cur_connections)
		set -- $(kernel_vsock_malloc_stats)
		base_kallocs=$1
		base_kmem=$2
		base_drops=$(sysctl -n kern.vsock.rx_drops)
	fi
	echo "== Alpine $transport: vsock $VSOCK_BACKEND soak " \
	    "iterations=$VSOCK_SOAK_ITERATIONS " \
	    "connections_per_iteration=$((4 * VSOCK_SOAK_CONNECTIONS)) " \
	    "base_fds=$base_fds " \
	    "base_rss_kb=$base_rss base_connections=$base_conns " \
	    "base_kernel_allocs=$base_kallocs base_kernel_bytes=$base_kmem " \
	    "base_rx_drops=$base_drops =="
	i=1
	while [ "$i" -le "$VSOCK_SOAK_ITERATIONS" ]; do
		run_vsock_driver churn "$WORKDIR/$transport.soak.$i"
		if [ "$VSOCK_SOAK_RESET_EVERY" -gt 0 ] &&
		    [ $((i % VSOCK_SOAK_RESET_EVERY)) -eq 0 ]; then
			echo "== Alpine $transport: vsock soak reset iteration=$i =="
			guest_rebind_virtio 0000:00:05.0
			run_vsock_driver smoke "$WORKDIR/$transport.soak-reset.$i"
		fi
		check_vsock_soak_resources "iteration $i"
		echo "PASS vsock-soak iteration=$i fds=$cur_fds rss_kb=$cur_rss " \
		    "connections=${cur_conns:--} kernel_allocs=${cur_kallocs:--} " \
		    "kernel_bytes=${cur_kmem:--} rx_drops=${cur_drops:--}"
		i=$((i + 1))
	done
	echo "== Alpine $transport: vsock soak final conformance =="
	run_vsock_driver full "$WORKDIR/$transport.soak-final"
	check_vsock_soak_resources "final conformance"
	echo "PASS vsock-soak final-conformance fds=$cur_fds rss_kb=$cur_rss " \
	    "connections=$cur_conns kernel_allocs=$cur_kallocs " \
	    "kernel_bytes=$cur_kmem rx_drops=$cur_drops"
	connection_delta=-
	if [ "$VSOCK_BACKEND" = kernel ]; then
		connection_delta=$((cur_conns - base_conns))
	fi
	soak_elapsed=$(($(date +%s) - soak_started))
	echo "PASS vsock-soak-summary backend=$VSOCK_BACKEND " \
	    "iterations=$VSOCK_SOAK_ITERATIONS elapsed_seconds=$soak_elapsed " \
	    "connections=$((4 * VSOCK_SOAK_CONNECTIONS * VSOCK_SOAK_ITERATIONS)) " \
	    "fd_delta=$((cur_fds - base_fds)) peak_fds=$peak_fds " \
	    "rss_delta_kb=$((cur_rss - base_rss)) " \
	    "peak_rss_kb=$peak_rss " \
	    "connection_delta=$connection_delta kernel_allocs=${cur_kallocs:--} " \
	    "kernel_bytes=${cur_kmem:--} rx_drops=${cur_drops:--}"
}

run_input_port()
{
	test_input_name=$1
	test_input_fifo=$2
	test_input_log=$3
	test_input_pid=$4
	test_input_suffix=$5
	input_guest_opt=
	[ "$INPUT_PACKED" = no ] || input_guest_opt=" packed"
	input_passes_before=$(grep -c '^PASS tap=' "$test_input_log" \
	    2>/dev/null || true)
	if ! guest_cmd "rm -f /tmp/ginput-$test_input_suffix.out; nohup python3 /tmp/ginput.py '$test_input_name' '$transport'$input_guest_opt >/tmp/ginput-$test_input_suffix.out 2>&1 & i=0; while ! grep -q '^READY$' /tmp/ginput-$test_input_suffix.out 2>/dev/null && [ \"\$i\" -lt 15 ]; do sleep 1; i=\$((i + 1)); done; grep -q '^READY$' /tmp/ginput-$test_input_suffix.out" 20 >/dev/null; then
		echo "guest virtio-input verifier failed to become ready" >&2
		guest_cmd "cat /tmp/ginput-$test_input_suffix.out 2>/dev/null || true" 12 >&2 || true
		return 1
	fi
	printf 'tap\n' > "$test_input_fifo"
	if ! guest_cmd "i=0; while ! grep -q '^PASS\$' /tmp/ginput-$test_input_suffix.out 2>/dev/null && [ \"\$i\" -lt 20 ]; do sleep 1; i=\$((i + 1)); done; cat /tmp/ginput-$test_input_suffix.out; grep -q '^PASS\$' /tmp/ginput-$test_input_suffix.out" 25; then
		echo "guest virtio-input event verification failed" >&2
		return 1
	fi
	i=0
	while [ "$(grep -c '^PASS tap=' "$test_input_log" 2>/dev/null || true)" \
	    -le "$input_passes_before" ] &&
	    kill -0 "$test_input_pid" 2>/dev/null &&
	    [ "$i" -lt 20 ]; do
		sleep 1
		i=$((i + 1))
	done
	if ! kill -0 "$test_input_pid" 2>/dev/null; then
		cat "$test_input_log" >&2
		return 1
	fi
	[ "$(grep -c '^PASS tap=' "$test_input_log" 2>/dev/null || true)" \
	    -gt "$input_passes_before" ] || {
		echo "host input provider did not observe the guest LED response" >&2
		cat "$test_input_log" >&2
		return 1
	}
	echo "PASS input isolation name=$test_input_name provider=$test_input_suffix"
}

run_input()
{
	run_input_port "$input_name" "$input_fifo" "$input_log" \
	    "$input_pid" port0
	[ "$INPUT_DEVICES" -eq 1 ] ||
	    run_input_port "$input_name2" "$input_fifo2" "$input_log2" \
		"$input_pid2" port1
}

run_rng()
{
	rng_guest_opt=
	[ "$RNG_PACKED" = no ] || rng_guest_opt=" packed"
	output=$(guest_cmd "python3 /tmp/grng.py '$transport'$rng_guest_opt" 60) || {
		status=$?
		echo "guest virtio-rng verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS rng bytes='
}

run_balloon()
{
	balloon_guest_opt=
	[ "$BALLOON_PACKED" = no ] || balloon_guest_opt=" packed"
	[ "$BALLOON_STATS_INTERVAL" -eq 0 ] ||
	    balloon_guest_opt="$balloon_guest_opt stats"
	[ "$BALLOON_DEFLATE_ON_OOM" = no ] ||
	    balloon_guest_opt="$balloon_guest_opt deflate-on-oom"
	[ "$BALLOON_FREE_PAGE_HINTING" = no ] ||
	    balloon_guest_opt="$balloon_guest_opt hinting"
	[ "$BALLOON_FREE_PAGE_REPORTING" = no ] ||
	    balloon_guest_opt="$balloon_guest_opt reporting"
	[ "$BALLOON_PAGE_POISON" = no ] ||
	    balloon_guest_opt="$balloon_guest_opt poison"
	output=$(guest_cmd "python3 /tmp/gballoon.py '$balloon_target_pages'$balloon_guest_opt" 90) || {
		status=$?
		echo "guest virtio-balloon verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS balloon '
	if [ "$BALLOON_STATS_INTERVAL" -ne 0 ]; then
		grep -q 'vtballoon: statistics sample' "$bhyve_log" || {
			echo "host did not consume a balloon statistics sample" >&2
			return 1
		}
	fi
	if [ "$BALLOON_FREE_PAGE_HINTING" = yes ]; then
		grep -q 'vtballoon: free-page hint ' "$bhyve_log" || {
			echo "guest negotiated free-page hinting but submitted no hint" >&2
			return 1
		}
	fi
	if [ "$BALLOON_FREE_PAGE_REPORTING" = yes ]; then
		if [ "$BALLOON_PAGE_POISON" = yes ]; then
			report_pattern='vtballoon: preserving poisoned free-page report'
		else
			report_pattern='vtballoon: free-page report'
		fi
		grep -q "$report_pattern" "$bhyve_log" || {
			echo "guest negotiated page reporting but did not submit a report" >&2
			return 1
		}
	fi
	if [ "$BALLOON_PAGE_POISON" = yes ]; then
		grep -q 'vtballoon: poison value=' "$bhyve_log" || {
			echo "guest negotiated page poison but did not configure poison_val" >&2
			return 1
		}
	fi
}

run_rtc()
{
	rtc_guest_opt=
	[ "$RTC_PACKED" = no ] || rtc_guest_opt=" packed"
	[ "$RTC_ALARM" = no ] || rtc_guest_opt="$rtc_guest_opt alarm"
	output=$(guest_cmd "python3 /tmp/grtc.py$rtc_guest_opt" 60) || {
		status=$?
		echo "guest virtio-rtc verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS rtc '
}

run_gpu()
{
	gpu_guest_opt=
	[ "$GPU_PACKED" = no ] || gpu_guest_opt=" packed"
	[ "$GPU_BLOB" = no ] || gpu_guest_opt="$gpu_guest_opt blob"
	output=$(guest_cmd "python3 /tmp/ggpu.py '$transport' '$GPU_WIDTH' '$GPU_HEIGHT'$gpu_guest_opt" 60) || {
		status=$?
		echo "guest virtio-gpu verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS gpu '
	if [ "$GPU_DISPLAY" = yes ]; then
		"$tools/gpu-rfb-check" "$DIR/gpu-vnc.sock" \
		    "$GPU_WIDTH" "$GPU_HEIGHT"
	fi
}

run_mem()
{
	mem_guest_opt=
	[ "$MEM_PACKED" = no ] || mem_guest_opt=" packed"
	output=$(guest_cmd \
	    "python3 /tmp/gmem.py '$mem_requested_bytes'$mem_guest_opt" 120) || {
		status=$?
		echo "guest virtio-mem verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS memory '
	grep -Eq 'vtmem: request type=0 .*response=0' "$bhyve_log" || {
		echo "virtio-mem test did not observe a successful Linux PLUG request" >&2
		return 1
	}
}

run_pmem()
{
	pmem_generation=$((pmem_generation + 1))
	pmem_label="$transport-$PMEM_PACKED-$$-$pmem_generation"
	pmem_guest_opt=
	[ "$PMEM_PACKED" = no ] || pmem_guest_opt=" packed"
	output=$(guest_cmd "python3 /tmp/gpmem.py '$pmem_label'$pmem_guest_opt" 90) || {
		status=$?
		echo "guest virtio-pmem verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	guest_digest=$(printf '%s\n' "$output" |
	    sed -n 's/^PASS pmem .* sha256=\([0-9a-f][0-9a-f]*\) .*/\1/p')
	[ "${#guest_digest}" -eq 64 ] || {
		echo "invalid virtio-pmem guest digest evidence" >&2
		return 1
	}
	host_digest=$(dd if="$pmem_image" bs=4096 skip=512 count=1 2>/dev/null |
	    sha256 -q)
	[ "$host_digest" = "$guest_digest" ] || {
		echo "virtio-pmem host backing mismatch: $host_digest != $guest_digest" >&2
		return 1
	}
	echo "PASS pmem-host-persistence offset=2097152 bytes=4096 sha256=$host_digest"
}

run_sound()
{
	sound_guest_opt=
	[ "$SOUND_PACKED" = no ] || sound_guest_opt=" packed"
	sound_before=$(awk '
	/^vtsnd: device reset requested/ {
		playback = 0
		capture = 0
	}
	/^vtsnd: playback stream=[0-9]+ bytes=[0-9]+ total=[0-9]+$/ {
		sub(/^.* total=/, "")
		playback = $0
	}
	/^vtsnd: capture stream=[0-9]+ bytes=[0-9]+ total=[0-9]+$/ {
		sub(/^.* total=/, "")
		capture = $0
	}
	END {
		printf "%.0f %.0f\n", playback, capture
	}
	' "$bhyve_log")
	set -- $sound_before
	playback_before=$1
	capture_before=$2
	output=$(guest_cmd \
	    "python3 /tmp/gsnd.py '$transport'$sound_guest_opt '$SOUND_BACKEND'" 90) || {
		status=$?
		echo "guest virtio-sound verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q \
	    "^PASS sound .*playback_bytes=[1-9][0-9]* capture_bytes=[1-9][0-9]* backend=$SOUND_BACKEND "
	playback_bytes=$(printf '%s\n' "$output" |
	    sed -nE 's/^PASS sound .* playback_bytes=([0-9]+) capture_bytes=[0-9]+ .*/\1/p')
	capture_bytes=$(printf '%s\n' "$output" |
	    sed -nE 's/^PASS sound .* playback_bytes=[0-9]+ capture_bytes=([0-9]+) .*/\1/p')
	case "$playback_bytes:$capture_bytes" in
	''|*[!0-9:]*|0:*|*:0)
		echo "invalid virtio-sound guest byte evidence" >&2
		return 1
		;;
	esac
	playback_after=$((playback_before + playback_bytes))
	capture_after=$((capture_before + capture_bytes))
	grep -Eq "^vtsnd: playback stream=[0-9]+ bytes=[1-9][0-9]* total=$playback_after$" \
	    "$bhyve_log" || {
		echo "host playback total did not match the guest workload" >&2
		return 1
	}
	grep -Eq "^vtsnd: capture stream=[0-9]+ bytes=[1-9][0-9]* total=$capture_after$" \
	    "$bhyve_log" || {
		echo "host capture total did not match the guest workload" >&2
		return 1
	}
	echo "PASS host-sound-io playback_bytes=$playback_bytes capture_bytes=$capture_bytes"
}

run_iommu()
{
	iommu_guest_opt=
	set -- $virtio_endpoint_bdfs
	iommu_expected_endpoints=$#
	# Balloon PFN queues describe guest memory directly and intentionally
	# do not use the guest DMA API or negotiate ACCESS_PLATFORM.
	[ "$run_balloon_device" = no ] ||
	    iommu_expected_endpoints=$((iommu_expected_endpoints - 1))
	[ "$iommu_expected_endpoints" -gt 0 ] || {
		echo "virtio-iommu topology has no DMA-capable endpoint" >&2
		return 1
	}
	[ "$IOMMU_PACKED" = no ] || iommu_guest_opt="packed "
	output=$(guest_cmd \
	    "python3 /tmp/giommu.py ${iommu_guest_opt}auto '$iommu_expected_endpoints'" 60) || {
		status=$?
		echo "$output"
		echo "guest virtio-iommu verification failed (status $status)" >&2
		return "$status"
	}
	echo "$output"
	printf '%s\n' "$output" | grep -q '^PASS iommu '
}

discover_guest_virtio_bdfs()
{
	set -- $virtio_endpoint_bdfs
	expected_endpoints=$#
	output=$(guest_cmd 'set -eu
	    endpoints=
	    iommu=
	    network=
	    for path in /sys/bus/pci/devices/*; do
		[ "$(cat "$path/vendor" 2>/dev/null || true)" = 0x1af4 ] ||
		    continue
		set -- "$path"/virtio*
		[ "$#" -eq 1 ] && [ -e "$1" ] || continue
		bdf=${path##*/}
		device=$(cat "$path/device")
		if [ "$device" = 0x1057 ]; then
			[ -z "$iommu" ] || exit 1
			iommu=$bdf
		else
			endpoints="$endpoints $bdf"
			case "$device" in
			0x1000|0x1041)
				[ -z "$network" ] || exit 1
				network=$bdf
				;;
			esac
		fi
	    done
	    set -- $endpoints
	    [ "$#" -gt 0 ]
	    printf "ENDPOINTS"
	    printf " %s" "$@"
	    printf "\nIOMMU %s\nNETWORK %s\n" "$iommu" "$network"' 30) || {
		status=$?
		echo "guest VirtIO PCI inventory failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	discovered_endpoints=$(printf '%s\n' "$output" |
	    sed -n 's/^ENDPOINTS //p')
	discovered_iommu=$(printf '%s\n' "$output" |
	    sed -n 's/^IOMMU //p')
	discovered_network=$(printf '%s\n' "$output" |
	    sed -n 's/^NETWORK //p')
	set -- $discovered_endpoints
	[ "$#" -eq "$expected_endpoints" ] || {
		echo "guest discovered $# VirtIO endpoints, expected $expected_endpoints" >&2
		printf '%s\n' "$output" >&2
		return 1
	}
	case "$discovered_network" in
	''|*[!0-9A-Fa-f:.]*)
		echo "guest VirtIO inventory does not contain the network endpoint" >&2
		return 1
		;;
	esac
	case " $discovered_endpoints " in
	*" $discovered_network "*) ;;
	*)
		echo "guest network endpoint is absent from the VirtIO inventory" >&2
		return 1
		;;
	esac
	if [ "$VIRTIO_IOMMU" = yes ]; then
		[ -n "$discovered_iommu" ] || {
			echo "guest VirtIO inventory does not contain the IOMMU" >&2
			return 1
		}
	else
		[ -z "$discovered_iommu" ] || {
			echo "unexpected guest VirtIO-IOMMU function $discovered_iommu" >&2
			return 1
		}
	fi
	virtio_endpoint_bdfs=$discovered_endpoints
	iommu_bdf=$discovered_iommu
	virtio_bdfs=$virtio_endpoint_bdfs
	[ -z "$iommu_bdf" ] || virtio_bdfs="$virtio_bdfs $iommu_bdf"
	echo "PASS guest-virtio-inventory endpoints=$expected_endpoints " \
	    "iommu=${iommu_bdf:-none}"
}

audit_guest_virtio_features()
{
	packed=
	[ "$NET_PACKED" = no ] || packed="$packed,0000:00:04.0"
	[ "$run_vsock" = no ] || [ "$VSOCK_PACKED" = no ] || packed="$packed,0000:00:05.0"
	[ "$run_input_device" = no ] || [ "$INPUT_PACKED" = no ] || packed="$packed,0000:00:06.0"
	[ "$run_rng_device" = no ] || [ "$RNG_PACKED" = no ] || packed="$packed,0000:00:07.0"
	[ "$run_block_device" = no ] || [ "$BLOCK_PACKED" = no ] || packed="$packed,0000:00:08.0"
	[ "$run_scsi_device" = no ] || [ "$SCSI_PACKED" = no ] || packed="$packed,0000:00:09.0"
	[ "$run_console_device" = no ] || [ "$CONSOLE_PACKED" = no ] || packed="$packed,0000:00:0a.0"
	[ "$run_9p_device" = no ] || [ "$NINEP_PACKED" = no ] || packed="$packed,0000:00:0b.0"
	[ "$run_balloon_device" = no ] || [ "$BALLOON_PACKED" = no ] || packed="$packed,0000:00:0c.0"
	[ "$run_rtc_device" = no ] || [ "$RTC_PACKED" = no ] || packed="$packed,0000:00:0d.0"
	[ "$run_gpu_device" = no ] || [ "$GPU_PACKED" = no ] || packed="$packed,0000:00:0e.0"
	[ "$VIRTIO_IOMMU" = no ] || [ "$IOMMU_PACKED" = no ] || packed="$packed,0000:00:0f.0"
	[ "$run_mem_device" = no ] || [ "$MEM_PACKED" = no ] || packed="$packed,0000:00:10.0"
	[ "$run_sound_device" = no ] || [ "$SOUND_PACKED" = no ] || packed="$packed,0000:00:11.0"
	[ "$run_fs_device" = no ] || [ "$FS_PACKED" = no ] || packed="$packed,0000:00:13.0"
	[ "$run_pmem_device" = no ] || [ "$PMEM_PACKED" = no ] || packed="$packed,0000:00:14.0"
	packed=${packed#,}
	[ -n "$packed" ] || packed=-
	set -- $virtio_bdfs
	output=$(guest_cmd "python3 /tmp/gvirtio_features.py '$transport' '$#' '$packed'" 30) || {
		status=$?
		echo "guest VirtIO feature audit failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
}

run_block()
{
	block_bytes=$((BLOCK_TEST_MB * 1024 * 1024))
	block_guest_opt=
	[ "$BLOCK_PACKED" = no ] || block_guest_opt=" packed"
	[ "$BLOCK_DISCARD" = no ] || block_guest_opt="$block_guest_opt discard"
	block_command=write
	[ "$BLOCK_READONLY" = no ] || block_command=readonly
	output=$(guest_cmd "python3 /tmp/gblock.py '$block_command' '$transport' '$block_bytes' '$block_queues_expected'$block_guest_opt" 180) || {
		status=$?
		echo "guest virtio-blk verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	if [ "$BLOCK_READONLY" = yes ]; then
		printf '%s\n' "$output" | grep -q '^PASS block-readonly bytes='
		return
	fi
	block_sha256=$(printf '%s\n' "$output" |
	    sed -n 's/^PASS block bytes=[0-9][0-9]* sha256=\([0-9a-f][0-9a-f]*\) device=.*/\1/p')
	[ "${#block_sha256}" -eq 64 ]
}

verify_block()
{
	block_guest_opt=
	[ "$BLOCK_PACKED" = no ] || block_guest_opt=" packed"
	[ "$BLOCK_DISCARD" = no ] || block_guest_opt="$block_guest_opt discard"
	if [ "$BLOCK_READONLY" = yes ]; then
		output=$(guest_cmd "python3 /tmp/gblock.py readonly '$transport' '$block_bytes' '$block_queues_expected'$block_guest_opt" 120) || {
			status=$?
			echo "post-lifecycle read-only virtio-blk verification failed (status $status)" >&2
			[ -z "$output" ] || printf '%s\n' "$output" >&2
			return "$status"
		}
		printf '%s\n' "$output"
		printf '%s\n' "$output" | grep -q '^PASS block-readonly bytes='
		return
	fi
	output=$(guest_cmd "python3 /tmp/gblock.py verify '$transport' '$block_bytes' '$block_sha256' '$block_queues_expected'$block_guest_opt" 120) || {
		status=$?
		echo "post-lifecycle virtio-blk verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS block-persist bytes='
}

run_scsi()
{
	scsi_bytes=$((SCSI_TEST_MB * 1024 * 1024))
	scsi_guest_opt=
	[ "$SCSI_PACKED" = no ] || scsi_guest_opt=" packed"
	output=$(guest_cmd "python3 /tmp/gscsi.py write '$transport' '$scsi_size_bytes' '$scsi_bytes' '$scsi_queues_expected'$scsi_guest_opt" 120) || {
		status=$?
		echo "guest virtio-scsi verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	scsi_sha256=$(printf '%s\n' "$output" |
	    sed -n 's/^PASS scsi bytes=[0-9][0-9]* sha256=\([0-9a-f][0-9a-f]*\) device=.*/\1/p')
	[ "${#scsi_sha256}" -eq 64 ]
}

run_scsi_events()
{
	[ "$transport" = modern ] || {
		echo "SCSI_EVENTS=yes currently requires modern transport" >&2
		return 2
	}
	scsi_event_create_log="$WORKDIR/$transport.scsi-event-create.log"
	scsi_event_size=$((scsi_size_bytes + 32 * 1024 * 1024))
	scsi_event_changed_size=$((scsi_event_size + 16 * 1024 * 1024))

	# No guest rescan command is issued in this test.  Appearance, capacity
	# change, and removal must all be driven by the negotiated event queue.
	ctladm create -b ramdisk -s "$scsi_event_size" \
	    -o "capacity=$scsi_event_size" > "$scsi_event_create_log"
	scsi_event_lun_id=$(awk '/^LUN ID:/ {print $NF}' \
	    "$scsi_event_create_log")
	case "$scsi_event_lun_id" in
	''|*[!0-9]*)
		echo "invalid CTL event-test LUN ID: $scsi_event_lun_id" >&2
		return 1
		;;
	esac
	[ "$scsi_event_lun_id" -le 16383 ] || {
		echo "CTL event-test LUN ID exceeds virtio-scsi limit" >&2
		return 1
	}
	grep -q '^LUN created successfully$' "$scsi_event_create_log"
	guest_cmd "python3 /tmp/gscsi.py event-add '$transport' '$scsi_event_size'" 45

	ctladm modify -b ramdisk -l "$scsi_event_lun_id" \
	    -s "$scsi_event_changed_size" >/dev/null
	guest_cmd "python3 /tmp/gscsi.py event-change '$transport' '$scsi_event_changed_size'" 45

	ctladm remove -b ramdisk -l "$scsi_event_lun_id" >/dev/null
	scsi_event_lun_id=
	guest_cmd "python3 /tmp/gscsi.py event-remove '$transport' '$scsi_event_changed_size'" 45
}

verify_scsi()
{
	scsi_guest_opt=
	[ "$SCSI_PACKED" = no ] || scsi_guest_opt=" packed"
	output=$(guest_cmd "python3 /tmp/gscsi.py verify '$transport' '$scsi_size_bytes' '$scsi_bytes' '$scsi_sha256' '$scsi_queues_expected'$scsi_guest_opt" 120) || {
		status=$?
		echo "post-lifecycle virtio-scsi verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS scsi-persist bytes='
}

run_console_port()
{
	port_name=$1
	port_socket=$2
	port_suffix=$3
	host_token="host-$transport-$port_suffix-$$"
	guest_token="guest-$transport-$port_suffix-$$"
	console_guest_opt=
	[ "$CONSOLE_PACKED" = no ] || console_guest_opt=" packed"
	console_exchange_log="$WORKDIR/$transport.console-exchange-$port_suffix.log"
	console_exchange_done="$WORKDIR/$transport.console-exchange-$port_suffix.done"
	console_guest_command=exchange
	console_expected_token=$guest_token
	if [ "$transport" = modern ] && [ "$port_suffix" = port0-first ]; then
		console_guest_command=exchange-emergency
		console_expected_token="${guest_token}E"
	fi
	guest_cmd "i=0; until python3 /tmp/gconsole.py check '$transport' '$port_name'$console_guest_opt; do i=\$((i + 1)); [ \"\$i\" -lt 20 ]; sleep 1; done" 30
	i=0
	while [ ! -S "$port_socket" ] && [ "$i" -lt 20 ]; do
		sleep 1
		i=$((i + 1))
	done
	[ -S "$port_socket" ] || {
		echo "virtio-console host socket did not appear: $port_socket" >&2
		return 1
	}
	: > "$console_exchange_log"
	rm -f "$console_exchange_done"
	mkfifo "$console_exchange_done"
	exec 9<>"$console_exchange_done"
	# Do not send until the guest has opened the port and sent its token.
	# The port node can exist before the virtio PORT_READY handshake, and bytes
	# written in that interval are allowed to be discarded by the backend.
	( { i=0; until grep -q "$guest_token" "$console_exchange_log" 2>/dev/null; do
	        [ "$i" -lt 20 ] || exit 1
	        sleep 1
	        i=$((i + 1))
	    done
	    printf '%s' "$host_token"
	    IFS= read -r _ <&9
	  } |
	    timeout 35 "$tools/unix-pipe" "$port_socket" > "$console_exchange_log" ) &
	console_exchange_pid=$!
	guest_status=0
	guest_cmd "python3 /tmp/gconsole.py '$console_guest_command' '$transport' '$port_name' '$host_token' '$guest_token'$console_guest_opt" 30 ||
	    guest_status=$?
	printf 'done\n' >&9
	exec 9>&-
	exec 9<&-
	rm -f "$console_exchange_done"
	[ "$guest_status" -eq 0 ] || return "$guest_status"
	i=0
	while ! grep -q "^$console_expected_token$" "$console_exchange_log" 2>/dev/null; do
		kill -0 "$console_exchange_pid" 2>/dev/null || {
			echo "virtio-console host exchange exited early" >&2
			return 1
		}
		[ "$i" -lt 20 ] || {
			echo "timed out waiting for virtio-console guest payload" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	pkill -TERM -P "$console_exchange_pid" 2>/dev/null || true
	kill "$console_exchange_pid" 2>/dev/null || true
	wait "$console_exchange_pid" 2>/dev/null || true
	console_exchange_pid=
	if [ "$console_guest_command" = exchange-emergency ]; then
		echo "PASS console emergency-write transport=$transport name=$port_name"
	fi
	echo "PASS console bidirectional transport=$transport name=$port_name"
}

run_console()
{
	run_console_port "$console_name" "$console_socket" port0-first
	run_console_port "$console_name" "$console_socket" port0-reconnect
	[ "$CONSOLE_MULTIPORT" = no ] ||
	    run_console_port "$console_name2" "$console_socket2" port1
	[ "$CONSOLE_MULTIPORT" = no ] ||
	    run_console_port "$console_name2" "$console_socket2" port1-reconnect
}

run_9p()
{
	mountpoint=/mnt/bhyve-9p
	guest_token="guest-9p-$transport-$$"
	host_token="host-9p-$transport-$$"
	ninep_guest_opt=
	[ "$NINEP_PACKED" = no ] || ninep_guest_opt=" packed"
	guest_cmd "python3 /tmp/g9p.py '$transport'$ninep_guest_opt" 30
	guest_cmd "set -eu; mkdir -p '$mountpoint'; grep -qs ' $mountpoint ' /proc/mounts || mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 '$ninep_tag' '$mountpoint'; [ \"\$(cat '$mountpoint/host-seed')\" = '$ninep_seed' ]; printf %s '$guest_token' > '$mountpoint/guest-to-host'; sync" 45
	guest_cmd "set -eu; [ \"\$(readlink '$mountpoint/escape')\" = '..' ]; if cat '$mountpoint/escape/$ninep_outside_name' >/tmp/9p-escape-read 2>/dev/null; then echo '9P export escape read unexpectedly succeeded' >&2; exit 1; fi; if printf compromised >'$mountpoint/escape/$ninep_outside_name' 2>/tmp/9p-escape-write; then echo '9P export escape write unexpectedly succeeded' >&2; exit 1; fi; if printf created >'$mountpoint/escape/$ninep_escape_create_name' 2>/tmp/9p-escape-create; then echo '9P export escape create unexpectedly succeeded' >&2; exit 1; fi" 30
	[ "$(cat "$ninep_share/guest-to-host")" = "$guest_token" ]
	[ "$(cat "$ninep_outside")" = "must-not-cross-9p-export" ] &&
	    [ ! -e "$ninep_escape_create" ]
	printf %s "$host_token" > "$ninep_share/host-to-guest"
	guest_cmd "[ \"\$(cat '$mountpoint/host-to-guest')\" = '$host_token' ]" 30
	echo "PASS 9p bidirectional transport=$transport tag=$ninep_tag"
}

run_fs()
{
	mountpoint=/mnt/bhyve-fs
	guest_cmd "set -eu
	    grep -qx 0x105a /sys/bus/pci/devices/0000:00:13.0/device
	    readlink /sys/bus/pci/devices/0000:00:13.0/driver |
	        grep -q '/virtio-pci\$'
	    fsdir=
	    for candidate in /sys/fs/virtiofs/*; do
		    [ -f \"\$candidate/tag\" ] || continue
		    [ \"\$(cat \"\$candidate/tag\")\" = '$fs_tag' ] || continue
		    fsdir=\$candidate
		    break
	    done
	    [ -n \"\$fsdir\" ]
	    [ \"\$(cat \"\$fsdir/mqs/0/name\")\" = hiprio ]
	    request_count=0
	    request_names=
	    for namefile in \"\$fsdir\"/mqs/*/name; do
		    name=\$(cat \"\$namefile\")
		    case \"\$name\" in
		    requests.*)
			    request_names=\"\$request_names \$name\"
			    request_count=\$((request_count + 1))
			    ;;
		    esac
	    done
	    [ \"\$request_count\" -eq '$FS_QUEUES' ]
	    queue=0
	    while [ \"\$queue\" -lt '$FS_QUEUES' ]; do
		    case \" \$request_names \" in
		    *\" requests.\$queue \"*) ;;
		    *) echo \"missing active virtio-fs request queue \$queue\" >&2
		       exit 1 ;;
		    esac
		    queue=\$((queue + 1))
	    done
	    mkdir -p '$mountpoint'
	    grep -qs ' $mountpoint ' /proc/mounts ||
	        mount -t virtiofs -o ro '$fs_tag' '$mountpoint'
	    [ \"\$(cat '$mountpoint/host-seed')\" = '$fs_seed' ]
	    [ \"\$(readlink '$mountpoint/link')\" = 'host-seed' ]
	    if printf bad > '$mountpoint/must-fail' 2>/dev/null; then
		    echo 'read-only virtio-fs export accepted a write' >&2
		    exit 1
	    fi
	    grep -qs ' $mountpoint virtiofs ro,' /proc/mounts
	    echo 'PASS virtio-fs readonly mount tag=$fs_tag queues=$FS_QUEUES'" 60
	kill -0 "$virtiofsd_pid" 2>/dev/null || {
		echo "virtiofsd exited while the guest export was active" >&2
		cat "$fs_log" >&2
		return 1
	}
}

run_vsock_smoke()
{
	run_vsock_driver smoke "$WORKDIR/$transport.lifecycle.host"
}

run_network_smoke()
{
	net_guest_opt=
	[ "$NET_PACKED" = no ] || net_guest_opt=" packed"
	output=$(guest_cmd "python3 /tmp/gnet.py '$transport' '$net_queues_expected'$net_guest_opt" 30) || {
		status=$?
		echo "guest virtio-net verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS net interface=eth0 '
	guest_cmd 'set -eu; ip link set eth0 up; udhcpc -n -q -t 5 -T 3 -i eth0; gateway=$(ip route | awk '\''/^default/{print $3; exit}'\''); [ -n "$gateway" ]; ping -c 3 -W 2 "$gateway"; echo "PASS network gateway=$gateway"' 45
	if [ "$net_queues_expected" -gt 1 ] && [ "$VIRTIO_DEBUG" -ge 2 ]; then
		guest_cmd "set -eu; gateway=\$(ip route | awk '/^default/{print \$3; exit}'); pids=; cpu=0; while [ \"\$cpu\" -lt '$net_queues_expected' ]; do taskset -c \"\$cpu\" ping -c 4 -W 2 \"\$gateway\" >\"/tmp/net-mq-\$cpu.log\" 2>&1 & pids=\"\$pids \$!\"; cpu=\$((cpu + 1)); done; for pid in \$pids; do wait \"\$pid\"; done; echo 'PASS network multiqueue traffic queues=$net_queues_expected'" 45
		if grep -Eq 'control chain .*valid=1 class=4 command=0' \
		    "$bhyve_log"; then
			echo "PASS host-net-mq-control queue_pairs=$net_queues_expected"
		else
			echo "host did not observe a valid virtio-net MQ control command" >&2
			return 1
		fi
		pair=0
		while [ "$pair" -lt "$net_queues_expected" ]; do
			txq=$((pair * 2 + 1))
			grep -Eq "vtnet: modern notify q=$txq([[:space:]]|$)" \
			    "$bhyve_log" || {
				echo "host did not observe traffic on virtio-net TX queue $txq" >&2
				return 1
			}
			pair=$((pair + 1))
		done
		echo "PASS host-net-mq-data queue_pairs=$net_queues_expected"
	fi
}

verify_no_msix()
{
	[ "$VIRTIO_MSIX" = no ] || return 0
	guest_cmd "set -eu; for bdf in $virtio_bdfs; do d=/sys/bus/pci/devices/\$bdf; [ -d \"\$d\" ]; vectors=0; [ ! -d \"\$d/msi_irqs\" ] || vectors=\$(find \"\$d/msi_irqs\" -mindepth 1 -maxdepth 1 | wc -l); [ \"\$vectors\" -le 1 ]; irq=\$(cat \"\$d/irq\"); line=\$(grep \"^ *\$irq:\" /proc/interrupts); case \"\$line\" in *MSI-X*) exit 1;; esac; printf 'PASS no-msix bdf=%s irq=%s vectors=%s\\n' \"\$bdf\" \"\$irq\" \"\$vectors\"; done" 30
}

verify_notification_data()
{
	[ "$VERIFY_NOTIFICATION_DATA" = yes ] || return 0
	[ "$transport" = modern ] || {
		echo "notification-data verification requires modern transport" >&2
		return 1
	}
	[ "$run_block_device" = yes ] || {
		echo "notification-data verification currently requires block" >&2
		return 1
	}
	[ "$VIRTIO_DEBUG" -ge 2 ] || {
		echo "notification-data verification requires VIRTIO_DEBUG >= 2" >&2
		return 1
	}
	grep -Eq \
	    'vtblk: modern notify q=[0-9]+ next_avail=[1-9][0-9]* ' \
	    "$bhyve_log" || {
		echo "host did not observe a nonzero notification-data available index" >&2
		return 1
	}
	echo "PASS notification-data device=vtblk payload=queue+available-index"
}

reset_devices()
{
	echo "== Alpine $transport: reset and rebind virtio devices =="
	rebind_devices
	run_lifecycle_smokes
}

guest_unmount_for_rebind()
{
	mountpoint=$1

	#
	# A successful PCI reset may have already invalidated a 9P or virtio-fs
	# superblock before the guest's mount-table update is observed.  Prefer a
	# normal unmount; only its reset-specific EINVAL outcome may use a lazy
	# detach.  A busy or any other unmount failure remains a test failure.  The
	# next lifecycle smoke must start from an unmounted backend.
	#
	guest_cmd "set -eu
	    if grep -qs ' $mountpoint ' /proc/mounts; then
		if ! unmount_output=\$(LC_ALL=C umount '$mountpoint' 2>&1); then
			case \"\$unmount_output\" in
			*'Invalid argument'*)
				# Reset can invalidate the superblock between the mount-table
				# check and either unmount operation.  A lazy detach is only
				# needed while the mount still exists; if it reports EINVAL
				# after that race, accept it only after proving the table no
				# longer names this mountpoint.
				if grep -qs ' $mountpoint ' /proc/mounts; then
					if ! lazy_output=\$(LC_ALL=C umount -l '$mountpoint' 2>&1); then
						if grep -qs ' $mountpoint ' /proc/mounts; then
							printf '%s\\n' \"\$lazy_output\" >&2
							exit 1
						fi
					fi
				fi
				;;
			*) printf '%s\\n' \"\$unmount_output\" >&2; exit 1 ;;
			esac
		fi
	    fi
	    ! grep -qs ' $mountpoint ' /proc/mounts" 30
}

rebind_devices()
{
	[ "$run_9p_device" = no ] ||
	    guest_unmount_for_rebind /mnt/bhyve-9p
	[ "$run_fs_device" = no ] ||
	    guest_unmount_for_rebind /mnt/bhyve-fs
	if [ "$VIRTIO_IOMMU" = yes ]; then
		guest_rebind_iommu_fabric "$virtio_endpoint_bdfs" "$iommu_bdf"
	else
		guest_rebind_virtio $virtio_bdfs
	fi
}

guest_rebind_virtio()
{
	bdfs=$*
	guest_cmd "set -eu; for bdf in $bdfs; do
	    echo \"reset \$bdf\"
	    echo \"\$bdf\" > /sys/bus/pci/drivers/virtio-pci/unbind
	    # A sysfs bind/unbind write completes driver attach/detach before it
	    # returns.  Do not turn that synchronous kernel boundary into a
	    # thirty-second polling loop.  Device-node publication is handled by
	    # the event-manager settle below.
	    [ ! -L \"/sys/bus/pci/devices/\$bdf/driver\" ]
	    echo \"\$bdf\" > /sys/bus/pci/drivers/virtio-pci/bind
	    [ -L \"/sys/bus/pci/devices/\$bdf/driver\" ]
	done
	if command -v udevadm >/dev/null 2>&1; then
		udevadm settle --timeout=30
	elif command -v mdev >/dev/null 2>&1; then
		mdev -s
	fi" 120
}

guest_rebind_iommu_fabric()
{
	endpoints=$1
	iommu=$2
	guest_cmd "set -eu
	assert_unbound()
	{
		bdf=\$1
		[ ! -L \"/sys/bus/pci/devices/\$bdf/driver\" ]
	}
	assert_bound()
	{
		bdf=\$1
		[ -L \"/sys/bus/pci/devices/\$bdf/driver\" ]
	}
	for bdf in $endpoints; do
		echo \"reset endpoint \$bdf\"
		echo \"\$bdf\" > /sys/bus/pci/drivers/virtio-pci/unbind
		assert_unbound \"\$bdf\"
	done
	echo \"reset iommu $iommu\"
	echo \"$iommu\" > /sys/bus/pci/drivers/virtio-pci/unbind
	assert_unbound \"$iommu\"
	echo \"$iommu\" > /sys/bus/pci/drivers/virtio-pci/bind
	assert_bound \"$iommu\"
	for bdf in $endpoints; do
		echo \"\$bdf\" > /sys/bus/pci/drivers/virtio-pci/bind
		assert_bound \"\$bdf\"
	done
	if command -v udevadm >/dev/null 2>&1; then
		udevadm settle --timeout=30
	elif command -v mdev >/dev/null 2>&1; then
		mdev -s
	fi" 180
}

run_lifecycle_smokes()
{
	run_network_smoke
	run_nonvirtio
	[ "$VIRTIO_IOMMU" = no ] || run_iommu
	verify_no_msix
	[ "$run_vsock" = no ] || run_vsock_smoke
	[ "$run_rng_device" = no ] || run_rng
	[ "$run_balloon_device" = no ] || run_balloon
	[ "$run_rtc_device" = no ] || run_rtc
	[ "$run_gpu_device" = no ] || run_gpu
	[ "$run_mem_device" = no ] || run_mem
	[ "$run_pmem_device" = no ] || run_pmem
	[ "$run_sound_device" = no ] || run_sound
	[ "$run_input_device" = no ] || run_input
	[ "$run_block_device" = no ] || verify_block
	[ "$run_scsi_device" = no ] || verify_scsi
	[ "$run_console_device" = no ] || run_console
	[ "$run_9p_device" = no ] || run_9p
	[ "$run_fs_device" = no ] || run_fs
	verify_packed_layout "$run_net_device" "$NET_PACKED" vtnet
	verify_packed_layout "$run_vsock" "$VSOCK_PACKED" vtvsock
	verify_packed_layout "$run_rng_device" "$RNG_PACKED" vtrnd
	verify_packed_layout "$run_balloon_device" "$BALLOON_PACKED" vtballoon
	verify_packed_layout "$run_rtc_device" "$RTC_PACKED" vtrtc
	verify_packed_layout "$run_input_device" "$INPUT_PACKED" vtinput
	verify_packed_layout "$run_block_device" "$BLOCK_PACKED" vtblk
	verify_packed_layout "$run_scsi_device" "$SCSI_PACKED" vtscsi
	verify_packed_layout "$run_console_device" "$CONSOLE_PACKED" vtcon
	verify_packed_layout "$run_9p_device" "$NINEP_PACKED" vt9p
	verify_packed_layout "$run_fs_device" "$FS_PACKED" vtfs
	verify_packed_layout "$run_gpu_device" "$GPU_PACKED" vtgpu
	verify_packed_layout "$run_mem_device" "$MEM_PACKED" vtmem
	verify_packed_layout "$run_pmem_device" "$PMEM_PACKED" vtpmem
	verify_packed_layout "$run_sound_device" "$SOUND_PACKED" vtsnd
	verify_packed_layout "$VIRTIO_IOMMU" "$IOMMU_PACKED" vtiommu
}

verify_packed_layout()
{
	enabled=$1
	packed=$2
	device_name=$3

	[ "$enabled" = yes ] && [ "$packed" = yes ] || return 0
	grep -Eq "^${device_name}: modern queue enable q=[0-9]+ .*enabled=1 .*layout=packed" \
	    "$bhyve_log" || {
		echo "host did not map an active packed queue for $device_name" >&2
		return 1
	}
	echo "PASS host-packed-layout device=$device_name"
}

check_reset_soak_resources()
{
	reset_stage=$1
	kill -0 "$vm_pid"
	reset_cur_fds=$(process_fd_count)
	reset_cur_rss=$(process_rss_kb)
	[ "$reset_cur_fds" -le "$reset_peak_fds" ] ||
	    reset_peak_fds=$reset_cur_fds
	[ "$reset_cur_rss" -le "$reset_peak_rss" ] ||
	    reset_peak_rss=$reset_cur_rss
	[ "$reset_cur_fds" -gt 0 ] && [ "$reset_cur_rss" -gt 0 ] || {
		echo "could not read bhyve resources after $reset_stage" >&2
		return 1
	}
	[ "$reset_cur_fds" -le "$reset_max_fds" ] || {
		echo "virtio reset-soak fd growth after $reset_stage: baseline=$reset_base_fds current=$reset_cur_fds limit=$reset_max_fds" >&2
		return 1
	}
	[ "$reset_cur_rss" -le "$reset_max_rss" ] || {
		echo "virtio reset-soak RSS growth after $reset_stage: baseline=${reset_base_rss}KB current=${reset_cur_rss}KB limit=${reset_max_rss}KB" >&2
		return 1
	}
	if [ "$run_fs_device" = yes ]; then
		kill -0 "$virtiofsd_pid"
		reset_fs_cur_fds=$(process_fd_count "$virtiofsd_pid")
		reset_fs_cur_rss=$(process_rss_kb "$virtiofsd_pid")
		[ "$reset_fs_cur_fds" -le "$reset_fs_peak_fds" ] ||
		    reset_fs_peak_fds=$reset_fs_cur_fds
		[ "$reset_fs_cur_rss" -le "$reset_fs_peak_rss" ] ||
		    reset_fs_peak_rss=$reset_fs_cur_rss
		[ "$reset_fs_cur_fds" -gt 0 ] &&
		    [ "$reset_fs_cur_rss" -gt 0 ] || {
			echo "could not read virtiofsd resources after $reset_stage" >&2
			return 1
		}
		[ "$reset_fs_cur_fds" -le "$reset_fs_max_fds" ] || {
			echo "virtio reset-soak virtiofsd fd growth after $reset_stage: baseline=$reset_fs_base_fds current=$reset_fs_cur_fds limit=$reset_fs_max_fds" >&2
			return 1
		}
		[ "$reset_fs_cur_rss" -le "$reset_fs_max_rss" ] || {
			echo "virtio reset-soak virtiofsd RSS growth after $reset_stage: baseline=${reset_fs_base_rss}KB current=${reset_fs_cur_rss}KB limit=${reset_fs_max_rss}KB" >&2
			return 1
		}
	fi
}

run_reset_soak()
{
	[ "$VIRTIO_RESET_SOAK_ITERATIONS" -gt 0 ] || return 0
	command -v procstat >/dev/null
	command -v ps >/dev/null
	reset_base_fds=$(process_fd_count)
	reset_base_rss=$(process_rss_kb)
	[ "$reset_base_fds" -gt 0 ] && [ "$reset_base_rss" -gt 0 ] || {
		echo "could not read bhyve reset-soak resource baseline for pid $vm_pid" >&2
		return 1
	}
	reset_max_fds=$((reset_base_fds +
	    VIRTIO_RESET_SOAK_MAX_FD_GROWTH))
	reset_max_rss=$((reset_base_rss + VIRTIO_RESET_SOAK_MAX_RSS_KB))
	reset_peak_fds=$reset_base_fds
	reset_peak_rss=$reset_base_rss
	reset_fs_base_fds=0
	reset_fs_base_rss=0
	reset_fs_cur_fds=0
	reset_fs_cur_rss=0
	reset_fs_peak_fds=0
	reset_fs_peak_rss=0
	if [ "$run_fs_device" = yes ]; then
		kill -0 "$virtiofsd_pid"
		reset_fs_base_fds=$(process_fd_count "$virtiofsd_pid")
		reset_fs_base_rss=$(process_rss_kb "$virtiofsd_pid")
		[ "$reset_fs_base_fds" -gt 0 ] &&
		    [ "$reset_fs_base_rss" -gt 0 ] || {
			echo "could not read virtiofsd reset-soak resource baseline for pid $virtiofsd_pid" >&2
			return 1
		}
		reset_fs_max_fds=$((reset_fs_base_fds +
		    VIRTIO_RESET_SOAK_MAX_FD_GROWTH))
		reset_fs_max_rss=$((reset_fs_base_rss +
		    VIRTIO_RESET_SOAK_MAX_RSS_KB))
		reset_fs_peak_fds=$reset_fs_base_fds
		reset_fs_peak_rss=$reset_fs_base_rss
	fi
	reset_started=$(date +%s)
	echo "== Alpine $transport: virtio reset soak " \
	    "iterations=$VIRTIO_RESET_SOAK_ITERATIONS " \
	    "verify_every=$VIRTIO_RESET_SOAK_VERIFY_EVERY " \
	    "base_fds=$reset_base_fds base_rss_kb=$reset_base_rss =="

	reset_i=1
	reset_validations=0
	while [ "$reset_i" -le "$VIRTIO_RESET_SOAK_ITERATIONS" ]; do
		echo "== Alpine $transport: virtio reset soak iteration=$reset_i =="
		rebind_devices
		if [ $((reset_i % VIRTIO_RESET_SOAK_VERIFY_EVERY)) -eq 0 ]; then
			echo "== Alpine $transport: functional validation after reset iteration=$reset_i =="
			run_lifecycle_smokes
			reset_validations=$((reset_validations + 1))
		fi
		check_reset_soak_resources "reset-soak iteration $reset_i"
		echo "PASS virtio-reset-soak iteration=$reset_i " \
		    "fds=$reset_cur_fds rss_kb=$reset_cur_rss"
		reset_i=$((reset_i + 1))
	done
	if [ $((VIRTIO_RESET_SOAK_ITERATIONS %
	    VIRTIO_RESET_SOAK_VERIFY_EVERY)) -ne 0 ]; then
		echo "== Alpine $transport: final reset-soak functional validation =="
		run_lifecycle_smokes
		reset_validations=$((reset_validations + 1))
		check_reset_soak_resources "final reset-soak validation"
	fi

	reset_elapsed=$(($(date +%s) - reset_started))
	echo "PASS virtio-reset-soak-summary " \
	    "iterations=$VIRTIO_RESET_SOAK_ITERATIONS " \
	    "functional_validations=$reset_validations " \
	    "elapsed_seconds=$reset_elapsed " \
	    "fd_delta=$((reset_cur_fds - reset_base_fds)) " \
	    "peak_fds=$reset_peak_fds " \
	    "rss_delta_kb=$((reset_cur_rss - reset_base_rss)) " \
	    "peak_rss_kb=$reset_peak_rss " \
	    "virtiofsd_fd_delta=$((reset_fs_cur_fds - reset_fs_base_fds)) " \
	    "virtiofsd_peak_fds=$reset_fs_peak_fds " \
	    "virtiofsd_rss_delta_kb=$((reset_fs_cur_rss - reset_fs_base_rss)) " \
	    "virtiofsd_peak_rss_kb=$reset_fs_peak_rss"
}

reboot_hold_connector()
{
	type=$1
	port=$2
	log=$3
	shift 3
	attempt=0
	while [ "$attempt" -lt 5 ]; do
		if [ "$VSOCK_BACKEND" = kernel ]; then
			retry_status=3
			if timeout 180 "$tools/vsock-pipe" "$@" -w \
			    "$CID" "$port" > "$log" 2>&1; then
				status=0
			else
				status=$?
			fi
		else
			retry_status=4
			if timeout 180 "$tools/vsh-connect" "$@" -w \
			    "$sockdir" "$port" > "$log" 2>&1; then
				status=0
			else
				status=$?
			fi
		fi
		if [ "$status" -eq 0 ]; then
			return 0
		fi
		# Each backend reports its explicit not-yet-listening response with
		# a different status: the Unix control connector uses 4, while an
		# AF_VSOCK connect rejected with ECONNRESET uses 3.  Retry only that
		# response and never retry after the helper proved establishment.
		[ "$status" -eq "$retry_status" ] &&
		    ! grep -q '^READY$' "$log" || return "$status"
		attempt=$((attempt + 1))
		sleep 1
	done
	echo "$type lifecycle connector exhausted readiness retries" >> "$log"
	return 4
}

start_reboot_vsock_holds()
{
	echo "== Alpine $transport: establish live vsock reboot endpoints =="
	reboot_stream_log="$WORKDIR/$transport.reboot-stream.log"
	reboot_seq_log="$WORKDIR/$transport.reboot-seq.log"
	: > "$reboot_stream_log"
	: > "$reboot_seq_log"
	guest_cmd "set -eu; pkill -9 python3 2>/dev/null || true; rm -f /tmp/reboot-stream.out /tmp/reboot-seq.out; nohup python3 /tmp/gvsock.py echo-l stream $((7011 + PORT_OFFSET)) >/tmp/reboot-stream.out 2>&1 & nohup python3 /tmp/gvsock.py echo-l seq $((7012 + PORT_OFFSET)) >/tmp/reboot-seq.out 2>&1 & i=0; while { ! grep -q '^up$' /tmp/reboot-stream.out 2>/dev/null || ! grep -q '^up$' /tmp/reboot-seq.out 2>/dev/null; } && [ \"\$i\" -lt 15 ]; do sleep 1; i=\$((i + 1)); done; grep -q '^up$' /tmp/reboot-stream.out; grep -q '^up$' /tmp/reboot-seq.out" 20 >/dev/null
	reboot_hold_connector stream "$((7011 + PORT_OFFSET))" \
	    "$reboot_stream_log" &
	reboot_stream_pid=$!
	reboot_hold_connector seq "$((7012 + PORT_OFFSET))" \
	    "$reboot_seq_log" -s &
	reboot_seq_pid=$!

	i=0
	while { ! grep -q '^READY$' "$reboot_stream_log" 2>/dev/null ||
	    ! grep -q '^READY$' "$reboot_seq_log" 2>/dev/null; }; do
		kill -0 "$reboot_stream_pid" 2>/dev/null || {
			cat "$reboot_stream_log" >&2
			return 1
		}
		kill -0 "$reboot_seq_pid" 2>/dev/null || {
			cat "$reboot_seq_log" >&2
			return 1
		}
		[ "$i" -lt 30 ] || {
			echo "timed out establishing reboot lifecycle endpoints" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	# READY must describe endpoints that are still open, not helpers that
	# connected and immediately observed an unrelated close.
	kill -0 "$reboot_stream_pid" 2>/dev/null
	kill -0 "$reboot_seq_pid" 2>/dev/null
	echo "PASS live reboot endpoints stream=$((7011 + PORT_OFFSET)) seq=$((7012 + PORT_OFFSET))"
}

verify_reboot_vsock_disconnects()
{
	i=0
	while { ! grep -q '^DISCONNECTED$' "$reboot_stream_log" 2>/dev/null ||
	    ! grep -q '^DISCONNECTED$' "$reboot_seq_log" 2>/dev/null; } &&
	    [ "$i" -lt 30 ]; do
		kill -0 "$reboot_stream_pid" 2>/dev/null || {
			cat "$reboot_stream_log" >&2
			return 1
		}
		kill -0 "$reboot_seq_pid" 2>/dev/null || {
			cat "$reboot_seq_log" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	[ "$i" -lt 30 ] || {
		echo "old vsock endpoints survived guest reboot for 30s" >&2
		return 1
	}
	stream_status=0
	wait "$reboot_stream_pid" || stream_status=$?
	seq_status=0
	wait "$reboot_seq_pid" || seq_status=$?
	reboot_stream_pid=
	reboot_seq_pid=
	[ "$stream_status" -eq 0 ] && [ "$seq_status" -eq 0 ] &&
	    grep -q '^READY$' "$reboot_stream_log" &&
	    grep -q '^DISCONNECTED$' "$reboot_stream_log" &&
	    grep -q '^READY$' "$reboot_seq_log" &&
	    grep -q '^DISCONNECTED$' "$reboot_seq_log" || {
		echo "vsock reboot disconnect verification failed: stream=$stream_status seq=$seq_status" >&2
		cat "$reboot_stream_log" >&2
		cat "$reboot_seq_log" >&2
		return 1
	}
	echo "PASS reboot disconnected established stream and seqpacket endpoints"
}

reboot_guest()
{
	echo "== Alpine $transport: monitor-mode reboot =="
	old_boot_id=$(guest_cmd 'cat /proc/sys/kernel/random/boot_id' 15)
	negotiations=0
	[ "$run_vsock" = no ] || negotiations=$(grep -c 'negotiated features=' "$bhyve_log" 2>/dev/null || true)
	[ "$run_vsock" = no ] || start_reboot_vsock_holds
	printf 'sync; reboot -f\r' >> "$console_input"

	i=0
	if [ "$run_vsock" = yes ]; then
		while [ "$i" -lt 120 ]; do
			current=$(grep -c 'negotiated features=' "$bhyve_log" 2>/dev/null || true)
			[ "$current" -gt "$negotiations" ] && break
			kill -0 "$vm_pid" 2>/dev/null || {
				echo "bhyve monitor exited during guest reboot" >&2
				return 1
			}
			sleep 1
			i=$((i + 1))
		done
		[ "$i" -lt 120 ] || { echo "timed out waiting for bhyve monitor restart" >&2; return 1; }
	else
		sleep 8
		kill -0 "$vm_pid" 2>/dev/null || { echo "bhyve monitor exited during guest reboot" >&2; return 1; }
	fi
	[ "$run_vsock" = no ] || verify_reboot_vsock_disconnects

	stop_console
	start_console
	wait_for_login 120
	printf 'root\r' >> "$console_input"
	sleep 2
	new_boot_id=$(guest_cmd 'cat /proc/sys/kernel/random/boot_id' 15)
	[ -n "$old_boot_id" ] && [ -n "$new_boot_id" ] &&
	    [ "$old_boot_id" != "$new_boot_id" ] || {
		echo "guest boot ID did not change across reboot" >&2
		return 1
	}
	echo "PASS reboot old_boot_id=$old_boot_id new_boot_id=$new_boot_id"
	provision_guest
	run_lifecycle_smokes
}

for transport in $TRANSPORTS; do
	vmname="alpine-virtio-${transport}-$$"
	sockdir="$WORKDIR/$transport"
	console_input="$WORKDIR/$transport.console.in"
	console_log="$WORKDIR/$transport.console.log"
	bhyve_log="$WORKDIR/$transport.bhyve.log"
	ring_trace="$WORKDIR/$transport.virtio-ring.trace"
	block_image="$WORKDIR/$transport.block.img"
	nonvirtio_image="$WORKDIR/$transport.nonvirtio.img"
	nonvirtio_fbuf_socket="$WORKDIR/$transport.nonvirtio-vnc.sock"
	nonvirtio_uart_log="$WORKDIR/$transport.nonvirtio-uart.log"
	nonvirtio_uart_port=$((CONSOLE_PORT + 1))
	nonvirtio_hostbridge_opt=
	pmem_image="$WORKDIR/$transport.pmem.img"
	pmem_generation=0
	input_fifo="$WORKDIR/$transport.input.fifo"
	input_path_file="$WORKDIR/$transport.input.path"
	input_log="$WORKDIR/$transport.input.log"
	input_name="bhyve-e2e-input-$transport-$$"
	input_fifo2="$WORKDIR/$transport.input-2.fifo"
	input_path_file2="$WORKDIR/$transport.input-2.path"
	input_log2="$WORKDIR/$transport.input-2.log"
	input_name2="bhyve-e2e-input-2-$transport-$$"
	console_socket="$WORKDIR/$transport.virtio-console.sock"
	console_name="bhyve-e2e-console-$transport-$$"
	console_socket2="$WORKDIR/$transport.virtio-console-2.sock"
	console_name2="bhyve-e2e-console-2-$transport-$$"
	console_ports_opt="$console_name=$console_socket,console-port=0"
	[ "$CONSOLE_MULTIPORT" = no ] ||
	    console_ports_opt="$console_ports_opt,$console_name2=$console_socket2"
	ninep_share="$WORKDIR/$transport.9p-share"
	ninep_tag="bhyve-e2e-9p-$transport-$$"
	ninep_seed="seed-9p-$transport-$$"
	ninep_outside="$WORKDIR/$transport.9p-outside"
	ninep_outside_name=$(basename "$ninep_outside")
	ninep_escape_create="$WORKDIR/$transport.9p-escape-created"
	ninep_escape_create_name=$(basename "$ninep_escape_create")
	fs_share="$WORKDIR/$transport.fs-share"
	fs_socket="$WORKDIR/$transport.virtiofsd.sock"
	fs_log="$WORKDIR/$transport.virtiofsd.log"
	virtiofsd_log=$fs_log
	fs_tag="bhyve-e2e-fs-$transport-$$"
	fs_seed="seed-fs-$transport-$$"
	fs_identity_opt=
	[ -z "$FS_IDENTITY" ] || fs_identity_opt=",identity=$FS_IDENTITY"
	if [ "$transport" = modern ]; then
		vm_cpus=2
		if [ "$NET_QUEUES" -gt "$vm_cpus" ]; then
			vm_cpus=$NET_QUEUES
		fi
		if [ "$run_block_device" = yes ] &&
		    [ "$BLOCK_QUEUES" -gt "$vm_cpus" ]; then
			vm_cpus=$BLOCK_QUEUES
		fi
		if [ "$run_scsi_device" = yes ] &&
		    [ "$SCSI_QUEUES" -gt "$vm_cpus" ]; then
			vm_cpus=$SCSI_QUEUES
		fi
		if [ "$run_fs_device" = yes ] &&
		    [ "$FS_QUEUES" -gt "$vm_cpus" ]; then
			vm_cpus=$FS_QUEUES
		fi
		net_transport_opt=",transport=modern"
		net_queues_opt=",queues=$NET_QUEUES"
		net_packed_opt=
		[ "$NET_PACKED" = no ] || net_packed_opt=",packed=true"
		net_queues_expected=$NET_QUEUES
		vsock_transport_opt=",transport=modern"
		vsock_packed_opt=
		[ "$VSOCK_PACKED" = no ] || vsock_packed_opt=",packed=true"
		input_transport_opt=",transport=modern"
		input_packed_opt=
		[ "$INPUT_PACKED" = no ] || input_packed_opt=",packed=true"
		rng_transport_opt=",transport=modern"
		rng_packed_opt=
		[ "$RNG_PACKED" = no ] || rng_packed_opt=",packed=true"
		balloon_packed_opt=
		[ "$BALLOON_PACKED" = no ] || balloon_packed_opt=",packed=true"
		rtc_packed_opt=
		[ "$RTC_PACKED" = no ] || rtc_packed_opt=",packed=true"
		rtc_alarm_opt=
		[ "$RTC_ALARM" = no ] || rtc_alarm_opt=",alarm=true"
		gpu_packed_opt=
		[ "$GPU_PACKED" = no ] || gpu_packed_opt=",packed=true"
		gpu_blob_opt=
		[ "$GPU_BLOB" = no ] || gpu_blob_opt=",blob=true"
		gpu_display_opt=
		[ "$GPU_DISPLAY" = no ] || gpu_display_opt=",display=true"
		mem_packed_opt=
		[ "$MEM_PACKED" = no ] || mem_packed_opt=",packed=true"
		pmem_packed_opt=
		[ "$PMEM_PACKED" = no ] || pmem_packed_opt=",packed=true"
		sound_packed_opt=
		[ "$SOUND_PACKED" = no ] || sound_packed_opt=",packed=true"
		iommu_packed_opt=
		[ "$IOMMU_PACKED" = no ] || iommu_packed_opt=",packed=true"
		block_transport_opt=",transport=modern"
		block_queues_opt=",queues=$BLOCK_QUEUES"
		block_packed_opt=
		[ "$BLOCK_PACKED" = no ] || block_packed_opt=",packed=true"
		[ "$BLOCK_READONLY" = no ] || block_packed_opt="$block_packed_opt,ro=true"
		block_queues_expected=$BLOCK_QUEUES
		scsi_transport_opt=",transport=modern"
		scsi_queues_opt=",queues=$SCSI_QUEUES"
		scsi_packed_opt=
		[ "$SCSI_PACKED" = no ] || scsi_packed_opt=",packed=true"
		scsi_queues_expected=$SCSI_QUEUES
		console_transport_opt=",transport=modern"
		console_packed_opt=
		[ "$CONSOLE_PACKED" = no ] ||
		    console_packed_opt=",packed=true"
		ninep_transport_opt=",transport=modern"
		ninep_packed_opt=
		[ "$NINEP_PACKED" = no ] || ninep_packed_opt=",packed=true"
		fs_packed_opt=
		[ "$FS_PACKED" = no ] || fs_packed_opt=",packed=true"
	else
		vm_cpus=2
		# Deliberately omit the option to exercise the compatibility default.
		net_transport_opt=
		net_queues_opt=
		net_packed_opt=
		[ "$NET_PACKED" = no ] || {
			echo "NET_PACKED=yes requires modern transport" >&2
			exit 2
		}
		net_queues_expected=1
		vsock_transport_opt=
		vsock_packed_opt=
		[ "$VSOCK_PACKED" = no ] || {
			echo "VSOCK_PACKED=yes requires modern transport" >&2
			exit 2
		}
		input_transport_opt=
		input_packed_opt=
		[ "$INPUT_PACKED" = no ] || {
			echo "INPUT_PACKED=yes requires modern transport" >&2
			exit 2
		}
		rng_transport_opt=
		rng_packed_opt=
		balloon_packed_opt=
		rtc_packed_opt=
		rtc_alarm_opt=
		sound_packed_opt=
		[ "$RNG_PACKED" = no ] || {
			echo "RNG_PACKED=yes requires modern transport" >&2
			exit 2
		}
		[ "$BALLOON_PACKED" = no ] || {
			echo "BALLOON_PACKED=yes requires modern transport" >&2
			exit 2
		}
		[ "$SOUND_PACKED" = no ] || {
			echo "SOUND_PACKED=yes requires modern transport" >&2
			exit 2
		}
		[ "$RTC_PACKED" = no ] || {
			echo "RTC_PACKED=yes requires modern transport" >&2
			exit 2
		}
		[ "$RTC_ALARM" = no ] || {
			echo "RTC_ALARM=yes requires modern transport" >&2
			exit 2
		}
		gpu_packed_opt=
		gpu_blob_opt=
		gpu_display_opt=
		mem_packed_opt=
		pmem_packed_opt=
		iommu_packed_opt=
		[ "$VIRTIO_IOMMU" = no ] || {
			echo "virtio-iommu is implemented as a modern-only device" >&2
			exit 2
		}
		[ "$GPU_PACKED" = no ] || {
			echo "GPU_PACKED=yes requires modern transport" >&2
			exit 2
		}
		[ "$GPU_BLOB" = no ] || {
			echo "GPU_BLOB=yes requires modern transport" >&2
			exit 2
		}
		[ "$MEM_PACKED" = no ] || {
			echo "MEM_PACKED=yes requires modern transport" >&2
			exit 2
		}
		[ "$PMEM_PACKED" = no ] || {
			echo "PMEM_PACKED=yes requires modern transport" >&2
			exit 2
		}
		block_transport_opt=
		block_queues_opt=
		block_packed_opt=
		[ "$BLOCK_PACKED" = no ] || {
			echo "BLOCK_PACKED=yes requires modern transport" >&2
			exit 2
		}
		block_queues_expected=1
		scsi_transport_opt=
		scsi_queues_opt=
		scsi_packed_opt=
		[ "$SCSI_PACKED" = no ] || {
			echo "SCSI_PACKED=yes requires modern transport" >&2
			exit 2
		}
		scsi_queues_expected=1
		console_transport_opt=
		console_packed_opt=
		[ "$CONSOLE_PACKED" = no ] || {
			echo "CONSOLE_PACKED=yes requires modern transport" >&2
			exit 2
		}
		ninep_transport_opt=
		ninep_packed_opt=
		[ "$NINEP_PACKED" = no ] || {
			echo "NINEP_PACKED=yes requires modern transport" >&2
			exit 2
		}
		fs_packed_opt=
		[ "$run_fs_device" = no ] || {
			echo "virtio-fs is implemented as a modern-only device" >&2
			exit 2
		}
		[ "$FS_PACKED" = no ] || {
			echo "FS_PACKED=yes requires modern transport" >&2
			exit 2
		}
	fi
	if [ "$VSOCK_BACKEND" = kernel ]; then
		vsock_backend_opt=",backend=kernel"
	else
		vsock_backend_opt=",path=$sockdir"
	fi
	virtio_bdfs="0000:00:04.0"
	[ "$run_vsock" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:05.0"
	[ "$run_input_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:06.0"
	[ "$run_input_device" = no ] || [ "$INPUT_DEVICES" -eq 1 ] ||
	    virtio_bdfs="$virtio_bdfs 0000:00:12.0"
	[ "$run_rng_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:07.0"
	[ "$run_block_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:08.0"
	[ "$run_scsi_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:09.0"
	[ "$run_console_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:0a.0"
	[ "$run_9p_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:0b.0"
	[ "$run_fs_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:13.0"
	[ "$run_balloon_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:0c.0"
	[ "$run_rtc_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:0d.0"
	[ "$run_gpu_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:0e.0"
	[ "$run_mem_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:10.0"
	[ "$run_pmem_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:14.0"
	[ "$run_sound_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:11.0"
	virtio_endpoint_bdfs=$virtio_bdfs
	iommu_bdf=
	if [ "$VIRTIO_IOMMU" = yes ]; then
		iommu_bdf=0000:00:0f.0
		virtio_bdfs="$virtio_bdfs $iommu_bdf"
	fi
	mkdir -p "$sockdir"
	chmod 0700 "$sockdir"
	rm -f "$sockdir/sock"
	[ "$run_console_device" = no ] ||
	    rm -f "$console_socket" "$console_socket2"
	if [ "$run_9p_device" = yes ]; then
		mkdir -p -m 0700 "$ninep_share"
		chmod 0700 "$ninep_share"
		rm -f "$ninep_share/host-seed" \
		    "$ninep_share/guest-to-host" "$ninep_share/host-to-guest" \
		    "$ninep_share/escape" "$ninep_outside" "$ninep_escape_create"
		printf %s "$ninep_seed" > "$ninep_share/host-seed"
		printf '%s\n' "must-not-cross-9p-export" > "$ninep_outside"
		ln -s .. "$ninep_share/escape"
	fi
	if [ "$run_fs_device" = yes ]; then
		mkdir -p -m 0700 "$fs_share"
		chmod 0700 "$fs_share"
		rm -f "$fs_share/host-seed" "$fs_share/link" "$fs_socket"
		printf %s "$fs_seed" > "$fs_share/host-seed"
		ln -s host-seed "$fs_share/link"
		: > "$fs_log"
		"$VIRTIOFSD" -r "$fs_share" -s "$fs_socket" >"$fs_log" 2>&1 &
		virtiofsd_pid=$!
		i=0
		while [ ! -S "$fs_socket" ] &&
		    kill -0 "$virtiofsd_pid" 2>/dev/null &&
		    [ "$i" -lt 100 ]; do
			sleep .1
			i=$((i + 1))
		done
		[ -S "$fs_socket" ] || {
			cat "$fs_log" >&2
			echo "virtiofsd did not publish its backend socket" >&2
			exit 1
		}
	fi
	: > "$bhyve_log"
	: > "$nonvirtio_uart_log"
	rm -f "$nonvirtio_fbuf_socket"
	case "$NONVIRTIO_DEVICE" in
	ahci|nvme)
		truncate -s "${NONVIRTIO_IMAGE_MB}M" "$nonvirtio_image"
		chmod 0600 "$nonvirtio_image"
		;;
	esac
	if [ "$run_block_device" = yes ]; then
		truncate -s "${BLOCK_IMAGE_MB}M" "$block_image"
		chmod 0600 "$block_image"
	fi
	if [ "$run_pmem_device" = yes ]; then
		truncate -s "${PMEM_IMAGE_MB}M" "$pmem_image"
		chmod 0600 "$pmem_image"
	fi
	if [ "$run_input_device" = yes ]; then
		rm -f "$input_fifo" "$input_path_file" \
		    "$input_fifo2" "$input_path_file2"
		mkfifo -m 0600 "$input_fifo"
		"$tools/uinput-inject" "$input_fifo" "$input_name" > "$input_path_file" 2> "$input_log" &
		input_pid=$!
		i=0
		while [ ! -s "$input_path_file" ] && kill -0 "$input_pid" 2>/dev/null && [ "$i" -lt 10 ]; do
			sleep 1
			i=$((i + 1))
		done
		[ -s "$input_path_file" ] || { cat "$input_log" >&2; exit 1; }
		input_path=$(sed -n '1p' "$input_path_file")
		case "$input_path" in
		/dev/input/event*)
			input_unit=${input_path#/dev/input/event}
			case "$input_unit" in ''|*[!0-9]*) echo "unsafe uinput path: $input_path" >&2; exit 1;; esac
			;;
		*) echo "unsafe uinput path: $input_path" >&2; exit 1;;
		esac
		if [ "$INPUT_DEVICES" -eq 2 ]; then
			mkfifo -m 0600 "$input_fifo2"
			"$tools/uinput-inject" "$input_fifo2" "$input_name2" \
			    > "$input_path_file2" 2> "$input_log2" &
			input_pid2=$!
			i=0
			while [ ! -s "$input_path_file2" ] &&
			    kill -0 "$input_pid2" 2>/dev/null &&
			    [ "$i" -lt 10 ]; do
				sleep 1
				i=$((i + 1))
			done
			[ -s "$input_path_file2" ] ||
			    { cat "$input_log2" >&2; exit 1; }
			input_path2=$(sed -n '1p' "$input_path_file2")
			case "$input_path2" in
			/dev/input/event*)
				input_unit2=${input_path2#/dev/input/event}
				case "$input_unit2" in
				''|*[!0-9]*)
					echo "unsafe second uinput path: $input_path2" >&2
					exit 1
					;;
				esac
				;;
			*)
				echo "unsafe second uinput path: $input_path2" >&2
				exit 1
				;;
			esac
			[ "$input_path2" != "$input_path" ] || {
				echo "uinput providers resolved to the same event path" >&2
				exit 1
			}
		fi
	fi

	echo "== Alpine $transport: boot and test =="
	launch_vm
	provision_guest
	discover_guest_virtio_bdfs
	audit_guest_virtio_features
	if [ "$VERIFY_RING_ACTIVITY" = yes ] ||
	    [ "$VERIFY_GPU_BLOB_ACTIVITY" = yes ] ||
	    [ -n "$VERIFY_DEVICE_RING_NAME" ]; then
		[ "$VERIFY_GPU_BLOB_ACTIVITY" = no ] ||
		    virtio_gpu_blob_trace_require "$vm_pid"
		virtio_ring_trace_start "$vm_pid" "$ring_trace"
	fi
	run_network_smoke
	run_nonvirtio
	[ "$VIRTIO_IOMMU" = no ] || run_iommu
	if [ "$run_vsock" = yes ]; then
		wait_vsock_provider_barrier initial
		run_matrix
		run_vsock_soak
	fi
	[ "$run_rng_device" = no ] || run_rng
	[ "$run_balloon_device" = no ] || run_balloon
	[ "$run_rtc_device" = no ] || run_rtc
	[ "$run_gpu_device" = no ] || run_gpu
	[ "$run_mem_device" = no ] || run_mem
	[ "$run_pmem_device" = no ] || run_pmem
	[ "$run_sound_device" = no ] || run_sound
	[ "$run_input_device" = no ] || run_input
	[ "$run_block_device" = no ] || run_block
	[ "$run_scsi_device" = no ] || run_scsi
	[ "$run_scsi_device" = no ] || [ "$SCSI_EVENTS" = no ] ||
	    run_scsi_events
	[ "$run_console_device" = no ] || run_console
	[ "$run_9p_device" = no ] || run_9p
	[ "$run_fs_device" = no ] || run_fs
	prepare_active_fs_checkpoint
	verify_notification_data
	verify_no_msix
	if [ "$CHECKPOINT_TEST" != no ]; then
		wait_vsock_provider_barrier pre-checkpoint
		case "$NONVIRTIO_DEVICE" in
		tpm-crb|passthru) run_nonvirtio_checkpoint_rejection ;;
		*) run_checkpoint_roundtrip ;;
		esac
		wait_vsock_provider_barrier post-checkpoint
	fi
	if [ "$VIRTIO_RESET_SOAK_ITERATIONS" -gt 0 ]; then
		wait_vsock_provider_barrier pre-reset
		run_reset_soak
		wait_vsock_provider_barrier post-reset
	else
		if [ "$RESET_TEST" != no ]; then
			wait_vsock_provider_barrier pre-reset
			reset_devices
			wait_vsock_provider_barrier post-reset
		fi
	fi
	[ "$REBOOT_TEST" = no ] || reboot_guest
	if [ "$VERIFY_RING_ACTIVITY" = yes ]; then
		ring_layout=split
		[ "$NET_PACKED" = no ] || ring_layout=packed
		virtio_ring_trace_finish "$ring_trace" "$ring_layout" vtnet
		if [ "$NET_QUEUES" -gt 1 ]; then
			virtio_net_hash_trace_finish "$ring_trace" "$NET_QUEUES"
		fi
		[ "$VIRTIO_IOMMU" = no ] ||
		    virtio_iommu_trace_finish "$ring_trace" \
		    "$iommu_expected_endpoints"
	elif [ "$VERIFY_GPU_BLOB_ACTIVITY" = yes ] ||
	    [ -n "$VERIFY_DEVICE_RING_NAME" ]; then
		virtio_ring_trace_stop
	fi
	[ "$VERIFY_GPU_BLOB_ACTIVITY" = no ] ||
	    virtio_gpu_blob_trace_finish "$ring_trace"
	[ -z "$VERIFY_DEVICE_RING_NAME" ] ||
	    virtio_device_ring_trace_finish "$ring_trace" \
	    "$VERIFY_DEVICE_RING_LAYOUT" "$VERIFY_DEVICE_RING_NAME"

	cleanup_vm
done

echo "Alpine transport automation completed successfully"
