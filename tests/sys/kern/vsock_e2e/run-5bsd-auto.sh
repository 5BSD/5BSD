#!/bin/sh
# Clone an existing 5BSD test image and run the complete vsock matrix against
# opt-in modern and default (option omitted) legacy VirtIO PCI transports.
set -eu

# Release-ledger anchors emitted only by the associated checked command paths.
# VIRTIO_ACTIVATION_ASSERTION: active-pairs-and-per-vcpu-traffic
# VIRTIO_ACTIVATION_ASSERTION: rss-config-and-receive-hash-metadata
# VIRTIO_ACTIVATION_ASSERTION: hash-config-without-rss-and-receive-metadata
# VIRTIO_ACTIVATION_ASSERTION: bidirectional-stream-and-seqpacket
# VIRTIO_ACTIVATION_ASSERTION: desired-and-current-sysctls
# VIRTIO_ACTIVATION_ASSERTION: inflate-to-target
# VIRTIO_ACTIVATION_ASSERTION: packed-negotiation-and-network-traffic
# VIRTIO_ACTIVATION_ASSERTION: packed-block-root-io
# VIRTIO_ACTIVATION_ASSERTION: block-multiqueue-root-io
# VIRTIO_ACTIVATION_ASSERTION: write-zeroes-delete-and-readback
# VIRTIO_ACTIVATION_ASSERTION: readonly-read-and-write-rejection
# VIRTIO_ACTIVATION_ASSERTION: cache-mode-transition
# VIRTIO_ACTIVATION_ASSERTION: scsi-multiqueue-data-io
# VIRTIO_ACTIVATION_ASSERTION: report-luns-and-request-io
# VIRTIO_ACTIVATION_ASSERTION: packed-scsi-data
# VIRTIO_ACTIVATION_ASSERTION: scsi-hotplug-change-remove-without-manual-rescan
# VIRTIO_ACTIVATION_ASSERTION: packed-rng-data
# VIRTIO_ACTIVATION_ASSERTION: packed-vsock-bidirectional-data
# VIRTIO_ACTIVATION_ASSERTION: notification-data-doorbell-payload
# VIRTIO_ACTIVATION_ASSERTION: selective-rng-queue-reset
# VIRTIO_ACTIVATION_ASSERTION: packed-console-bidirectional-data
# VIRTIO_ACTIVATION_ASSERTION: target-memory-accounting
# VIRTIO_ACTIVATION_ASSERTION: target-reached
# VIRTIO_ACTIVATION_ASSERTION: deflate-on-lowmem-and-reinflate
# VIRTIO_ACTIVATION_ASSERTION: device-suspend-resume-and-data
# VIRTIO_ACTIVATION_ASSERTION: gpu-2d-command-sequence
# VIRTIO_ACTIVATION_ASSERTION: packed-gpu-control-queue
# VIRTIO_ACTIVATION_ASSERTION: rtc-config-capability-and-read
# VIRTIO_ACTIVATION_ASSERTION: packed-rtc-request-queue
# VIRTIO_ACTIVATION_ASSERTION: input-event-and-status-data
# VIRTIO_ACTIVATION_ASSERTION: packed-input-event-and-status-queues

here=$(cd "$(dirname "$0")" && pwd)
. "$here/virtio-ring-trace.sh"
IMAGE=${IMAGE:?set IMAGE to a 5BSD raw disk base image}
FIVEBSD_IMAGE_SHA256=${FIVEBSD_IMAGE_SHA256:?set FIVEBSD_IMAGE_SHA256 to the qualified base-image digest}
FIVEBSD_BUILD_ID=${FIVEBSD_BUILD_ID:?set FIVEBSD_BUILD_ID to the embedded current-build identifier}
BHYVE=${BHYVE:-}
BHYVELOAD=${BHYVELOAD:-$(command -v bhyveload 2>/dev/null || true)}
BHYVECTL=${BHYVECTL:-}
SRCTOP=${SRCTOP:-$(cd "$here/../../../.." && pwd)}
OBJROOT=${OBJROOT:-/usr/obj}
WORKDIR=${WORKDIR:-/tmp/bhyve-vsock-5bsd}
TRANSPORTS=${TRANSPORTS:-"modern legacy"}
CID=${CID:-3}
CONSOLE_PORT=${CONSOLE_PORT:-}
BULK_MB=${BULK_MB:-256}
KEEP_VM=${KEEP_VM:-no}
VM_FREE_GATES=${VM_FREE_GATES:-yes}
BALLOON_PACKED=${BALLOON_PACKED:-no}
FIVEBSD_BALLOON_STATS_INTERVAL=${FIVEBSD_BALLOON_STATS_INTERVAL:-0}
FIVEBSD_BALLOON_DEFLATE_ON_OOM=${FIVEBSD_BALLOON_DEFLATE_ON_OOM:-no}
FIVEBSD_BALLOON_PAGE_POISON=${FIVEBSD_BALLOON_PAGE_POISON:-no}
FIVEBSD_BLOCK_PACKED=${FIVEBSD_BLOCK_PACKED:-no}
FIVEBSD_BLOCK_QUEUES=${FIVEBSD_BLOCK_QUEUES:-1}
FIVEBSD_BLOCK_DISCARD=${FIVEBSD_BLOCK_DISCARD:-no}
FIVEBSD_BLOCK_WRITE_ZEROES=${FIVEBSD_BLOCK_WRITE_ZEROES:-no}
FIVEBSD_BLOCK_READONLY=${FIVEBSD_BLOCK_READONLY:-no}
FIVEBSD_BLOCK_WCE=${FIVEBSD_BLOCK_WCE:-no}
FIVEBSD_SCSI_QUEUES=${FIVEBSD_SCSI_QUEUES:-0}
FIVEBSD_SCSI_PACKED=${FIVEBSD_SCSI_PACKED:-no}
FIVEBSD_SCSI_EVENTS=${FIVEBSD_SCSI_EVENTS:-no}
FIVEBSD_RNG_PACKED=${FIVEBSD_RNG_PACKED:-no}
FIVEBSD_VSOCK_PACKED=${FIVEBSD_VSOCK_PACKED:-no}
FIVEBSD_NOTIFICATION_DATA=${FIVEBSD_NOTIFICATION_DATA:-no}
FIVEBSD_DEVICE_SUSPEND=${FIVEBSD_DEVICE_SUSPEND:-no}
FIVEBSD_RING_TRACE=${FIVEBSD_RING_TRACE:-no}
FIVEBSD_RNG_RESET_ITERATIONS=${FIVEBSD_RNG_RESET_ITERATIONS:-0}
FIVEBSD_CONSOLE_TEST=${FIVEBSD_CONSOLE_TEST:-no}
FIVEBSD_CONSOLE_PACKED=${FIVEBSD_CONSOLE_PACKED:-no}
FIVEBSD_CONSOLE_PORTS=${FIVEBSD_CONSOLE_PORTS:-1}
BALLOON_TARGET_MB=${BALLOON_TARGET_MB:-64}
FIVEBSD_NET_TEST=${FIVEBSD_NET_TEST:-no}
FIVEBSD_NET_QUEUES=${FIVEBSD_NET_QUEUES:-2}
FIVEBSD_NET_PACKED=${FIVEBSD_NET_PACKED:-no}
FIVEBSD_GPU_TEST=${FIVEBSD_GPU_TEST:-no}
FIVEBSD_GPU_PACKED=${FIVEBSD_GPU_PACKED:-no}
FIVEBSD_GPU_WIDTH=${FIVEBSD_GPU_WIDTH:-1024}
FIVEBSD_GPU_HEIGHT=${FIVEBSD_GPU_HEIGHT:-768}
FIVEBSD_RTC_TEST=${FIVEBSD_RTC_TEST:-no}
FIVEBSD_RTC_PACKED=${FIVEBSD_RTC_PACKED:-no}
FIVEBSD_INPUT_TEST=${FIVEBSD_INPUT_TEST:-no}
FIVEBSD_INPUT_PACKED=${FIVEBSD_INPUT_PACKED:-no}
FIVEBSD_INPUT_DEVICES=${FIVEBSD_INPUT_DEVICES:-1}
FIVEBSD_NINEP_TEST=${FIVEBSD_NINEP_TEST:-no}
FIVEBSD_NINEP_PACKED=${FIVEBSD_NINEP_PACKED:-no}
FIVEBSD_SOUND_TEST=${FIVEBSD_SOUND_TEST:-no}
FIVEBSD_SOUND_PACKED=${FIVEBSD_SOUND_PACKED:-no}
FIVEBSD_MEM_TEST=${FIVEBSD_MEM_TEST:-no}
FIVEBSD_PMEM_TEST=${FIVEBSD_PMEM_TEST:-no}
FIVEBSD_IOMMU_TEST=${FIVEBSD_IOMMU_TEST:-no}
FIVEBSD_CRYPTO_TEST=${FIVEBSD_CRYPTO_TEST:-no}
FIVEBSD_CHECKPOINT_TEST=${FIVEBSD_CHECKPOINT_TEST:-no}
if [ "$FIVEBSD_MEM_TEST" = yes ] || [ "$FIVEBSD_PMEM_TEST" = yes ] ||
    [ "$FIVEBSD_IOMMU_TEST" = yes ]; then
	echo "virtio-mem, virtio-pmem, and virtio-IOMMU are unsupported on the 5BSD qualification guest" >&2
	exit 2
fi
BRIDGE=${BRIDGE:-bridge0}
VIRTIO_DEBUG=${VIRTIO_DEBUG:-0}
NONVIRTIO_DEVICE=${NONVIRTIO_DEVICE:-none}
NONVIRTIO_CHECKPOINT=${NONVIRTIO_CHECKPOINT:-no}
NONVIRTIO_IMAGE_MB=${NONVIRTIO_IMAGE_MB:-128}
NONVIRTIO_HDA_PLAY=${NONVIRTIO_HDA_PLAY:-/dev/dsp0}
NONVIRTIO_HDA_RECORD=${NONVIRTIO_HDA_RECORD:-/dev/dsp1}
NONVIRTIO_TPM_TYPE=${NONVIRTIO_TPM_TYPE:-swtpm}
NONVIRTIO_TPM_PATH=${NONVIRTIO_TPM_PATH:-}
NONVIRTIO_PASSTHRU=${NONVIRTIO_PASSTHRU:-}
NONVIRTIO_PASSTHRU_GUEST_ASSERT=${NONVIRTIO_PASSTHRU_GUEST_ASSERT:-}
NONVIRTIO_PASSTHRU_FIVEBSD_ASSERT=${NONVIRTIO_PASSTHRU_FIVEBSD_ASSERT:-$NONVIRTIO_PASSTHRU_GUEST_ASSERT}
NONVIRTIO_FWCFG_NAME=opt/waspnest/checkpoint
NONVIRTIO_FWCFG_VALUE=WASPNEST-FWCFG-CURSOR-0123456789ABCDEF
# Destructive-fire gates.  The default lanes only bind/arm/attach; a dedicated
# fire case sets one of these to drive the emulated device all the way to its
# host action (bhyve keeps the guest alive: i6300esb action=notify, pvpanic
# action=none), which the runner then observes on the host log.
WATCHDOG_EXPECT_RESET=${WATCHDOG_EXPECT_RESET:-0}
PVPANIC_EXPECT_PANIC=${PVPANIC_EXPECT_PANIC:-no}
case "$NONVIRTIO_DEVICE" in
none|ahci|nvme|e82545|hda|xhci|fbuf|pci-uart|lpc-uart|tpm-crb|pvpanic|i6300esb|hostbridge|passthru|qemu-fwcfg) ;;
*) echo "unknown NONVIRTIO_DEVICE: $NONVIRTIO_DEVICE" >&2; exit 2 ;;
esac
validate_yes_no_early()
{
	case "$2" in yes|no) ;; *) echo "$1 must be yes or no" >&2; exit 2 ;; esac
}
validate_yes_no_early NONVIRTIO_CHECKPOINT "$NONVIRTIO_CHECKPOINT"
case "$WATCHDOG_EXPECT_RESET" in 0|1) ;; *) echo "WATCHDOG_EXPECT_RESET must be 0 or 1" >&2; exit 2 ;; esac
validate_yes_no_early PVPANIC_EXPECT_PANIC "$PVPANIC_EXPECT_PANIC"
# A destructive fire is confined to its own non-checkpoint case for its device.
[ "$WATCHDOG_EXPECT_RESET" != 1 ] || {
	[ "$NONVIRTIO_DEVICE" = i6300esb ] && [ "$NONVIRTIO_CHECKPOINT" = no ] || {
		echo "WATCHDOG_EXPECT_RESET=1 requires NONVIRTIO_DEVICE=i6300esb without checkpoint" >&2; exit 2
	}
}
[ "$PVPANIC_EXPECT_PANIC" != yes ] || {
	[ "$NONVIRTIO_DEVICE" = pvpanic ] && [ "$NONVIRTIO_CHECKPOINT" = no ] || {
		echo "PVPANIC_EXPECT_PANIC=yes requires NONVIRTIO_DEVICE=pvpanic without checkpoint" >&2; exit 2
	}
}
case "$NONVIRTIO_IMAGE_MB" in
''|*[!0-9]*|0) echo "NONVIRTIO_IMAGE_MB must be positive" >&2; exit 2 ;;
esac
case "$NONVIRTIO_TPM_TYPE" in
passthru|swtpm) ;; *) echo "invalid NONVIRTIO_TPM_TYPE" >&2; exit 2 ;;
esac
[ "$NONVIRTIO_DEVICE" != tpm-crb ] || [ -n "$NONVIRTIO_TPM_PATH" ] || {
	echo "tpm-crb requires NONVIRTIO_TPM_PATH" >&2; exit 2
}
[ "$NONVIRTIO_DEVICE" != passthru ] || {
	[ -n "$NONVIRTIO_PASSTHRU" ] && [ -n "$NONVIRTIO_PASSTHRU_FIVEBSD_ASSERT" ] || {
		echo "passthru requires NONVIRTIO_PASSTHRU and NONVIRTIO_PASSTHRU_FIVEBSD_ASSERT" >&2; exit 2
	}
}
case "$VIRTIO_DEBUG" in
''|*[!0-9]*) echo "VIRTIO_DEBUG must be a non-negative integer" >&2; exit 2 ;;
esac

validate_yes_no()
{
	case "$2" in
	yes|no) ;;
	*) echo "$1 must be yes or no" >&2; exit 2 ;;
	esac
}
validate_yes_no BALLOON_PACKED "$BALLOON_PACKED"
validate_yes_no FIVEBSD_BALLOON_DEFLATE_ON_OOM \
    "$FIVEBSD_BALLOON_DEFLATE_ON_OOM"
validate_yes_no FIVEBSD_BALLOON_PAGE_POISON \
    "$FIVEBSD_BALLOON_PAGE_POISON"
validate_yes_no FIVEBSD_BLOCK_PACKED "$FIVEBSD_BLOCK_PACKED"
validate_yes_no FIVEBSD_BLOCK_DISCARD "$FIVEBSD_BLOCK_DISCARD"
validate_yes_no FIVEBSD_BLOCK_WRITE_ZEROES "$FIVEBSD_BLOCK_WRITE_ZEROES"
validate_yes_no FIVEBSD_BLOCK_READONLY "$FIVEBSD_BLOCK_READONLY"
validate_yes_no FIVEBSD_BLOCK_WCE "$FIVEBSD_BLOCK_WCE"
validate_yes_no FIVEBSD_SCSI_PACKED "$FIVEBSD_SCSI_PACKED"
validate_yes_no FIVEBSD_SCSI_EVENTS "$FIVEBSD_SCSI_EVENTS"
validate_yes_no FIVEBSD_RNG_PACKED "$FIVEBSD_RNG_PACKED"
validate_yes_no FIVEBSD_VSOCK_PACKED "$FIVEBSD_VSOCK_PACKED"
validate_yes_no FIVEBSD_NOTIFICATION_DATA "$FIVEBSD_NOTIFICATION_DATA"
validate_yes_no FIVEBSD_DEVICE_SUSPEND "$FIVEBSD_DEVICE_SUSPEND"
validate_yes_no FIVEBSD_CHECKPOINT_TEST "$FIVEBSD_CHECKPOINT_TEST"
validate_yes_no FIVEBSD_RING_TRACE "$FIVEBSD_RING_TRACE"
validate_yes_no FIVEBSD_GPU_TEST "$FIVEBSD_GPU_TEST"
validate_yes_no FIVEBSD_GPU_PACKED "$FIVEBSD_GPU_PACKED"
validate_yes_no FIVEBSD_RTC_TEST "$FIVEBSD_RTC_TEST"
validate_yes_no FIVEBSD_RTC_PACKED "$FIVEBSD_RTC_PACKED"
validate_yes_no FIVEBSD_INPUT_TEST "$FIVEBSD_INPUT_TEST"
validate_yes_no FIVEBSD_INPUT_PACKED "$FIVEBSD_INPUT_PACKED"
validate_yes_no FIVEBSD_NINEP_TEST "$FIVEBSD_NINEP_TEST"
validate_yes_no FIVEBSD_NINEP_PACKED "$FIVEBSD_NINEP_PACKED"
case "$FIVEBSD_INPUT_DEVICES" in
1|2) ;;
*) echo "FIVEBSD_INPUT_DEVICES must be 1 or 2" >&2; exit 2 ;;
esac
[ "$FIVEBSD_INPUT_DEVICES" -eq 1 ] ||
    [ "$FIVEBSD_INPUT_TEST" = yes ] || {
	echo "FIVEBSD_INPUT_DEVICES=2 requires FIVEBSD_INPUT_TEST=yes" >&2
	exit 2
}
[ "$FIVEBSD_GPU_PACKED" = no ] ||
    [ "$FIVEBSD_GPU_TEST" = yes ] || {
	echo "FIVEBSD_GPU_PACKED=yes requires FIVEBSD_GPU_TEST=yes" >&2
	exit 2
}
[ "$FIVEBSD_RTC_PACKED" = no ] ||
    [ "$FIVEBSD_RTC_TEST" = yes ] || {
	echo "FIVEBSD_RTC_PACKED=yes requires FIVEBSD_RTC_TEST=yes" >&2
	exit 2
}
[ "$FIVEBSD_INPUT_PACKED" = no ] ||
    [ "$FIVEBSD_INPUT_TEST" = yes ] || {
	echo "FIVEBSD_INPUT_PACKED=yes requires FIVEBSD_INPUT_TEST=yes" >&2
	exit 2
}
[ "$FIVEBSD_NINEP_PACKED" = no ] ||
    [ "$FIVEBSD_NINEP_TEST" = yes ] || {
	echo "FIVEBSD_NINEP_PACKED=yes requires FIVEBSD_NINEP_TEST=yes" >&2
	exit 2
}
if [ "$FIVEBSD_DEVICE_SUSPEND" = yes ] &&
    [ "$TRANSPORTS" != modern ]; then
	echo "FIVEBSD_DEVICE_SUSPEND=yes requires TRANSPORTS=modern" >&2
	exit 2
fi
if [ "$FIVEBSD_RING_TRACE" = yes ] &&
    [ "$TRANSPORTS" != modern ]; then
	echo "FIVEBSD_RING_TRACE=yes requires TRANSPORTS=modern" >&2
	exit 2
fi
validate_yes_no FIVEBSD_CONSOLE_TEST "$FIVEBSD_CONSOLE_TEST"
validate_yes_no FIVEBSD_CONSOLE_PACKED "$FIVEBSD_CONSOLE_PACKED"
case "$FIVEBSD_CONSOLE_PORTS" in
1|2) ;;
*) echo "FIVEBSD_CONSOLE_PORTS must be 1 or 2" >&2; exit 2 ;;
esac
[ "$FIVEBSD_CONSOLE_PORTS" -eq 1 ] ||
    [ "$FIVEBSD_CONSOLE_TEST" = yes ] || {
	echo "FIVEBSD_CONSOLE_PORTS=2 requires FIVEBSD_CONSOLE_TEST=yes" >&2
	exit 2
}
[ "$FIVEBSD_CONSOLE_PACKED" = no ] ||
    [ "$FIVEBSD_CONSOLE_TEST" = yes ] || {
	echo "FIVEBSD_CONSOLE_PACKED=yes requires FIVEBSD_CONSOLE_TEST=yes" >&2
	exit 2
}
if [ "$BALLOON_PACKED" = yes ] ||
    [ "$FIVEBSD_BLOCK_PACKED" = yes ] ||
    [ "$FIVEBSD_SCSI_PACKED" = yes ] ||
    [ "$FIVEBSD_RNG_PACKED" = yes ] ||
    [ "$FIVEBSD_VSOCK_PACKED" = yes ] ||
    [ "$FIVEBSD_CONSOLE_PACKED" = yes ] ||
    [ "$FIVEBSD_GPU_PACKED" = yes ] ||
    [ "$FIVEBSD_RTC_PACKED" = yes ] ||
    [ "$FIVEBSD_INPUT_PACKED" = yes ] ||
    [ "$FIVEBSD_NINEP_PACKED" = yes ] ||
    [ "$FIVEBSD_BLOCK_WCE" = yes ] ||
    [ "$FIVEBSD_NOTIFICATION_DATA" = yes ] ||
    [ "$FIVEBSD_DEVICE_SUSPEND" = yes ]; then
	[ "$VIRTIO_DEBUG" -ge 2 ] || VIRTIO_DEBUG=2
fi
case "$FIVEBSD_GPU_WIDTH:$FIVEBSD_GPU_HEIGHT" in
*[!0-9:]*|:*|*:) echo "FIVEBSD GPU dimensions must be positive integers" >&2; exit 2 ;;
esac
[ "$FIVEBSD_GPU_WIDTH" -gt 0 ] && [ "$FIVEBSD_GPU_WIDTH" -le 16384 ] &&
    [ "$FIVEBSD_GPU_HEIGHT" -gt 0 ] &&
    [ "$FIVEBSD_GPU_HEIGHT" -le 16384 ] || {
	echo "FIVEBSD GPU dimensions must be between 1 and 16384" >&2
	exit 2
}
[ "$FIVEBSD_GPU_TEST" = no ] || [ "$TRANSPORTS" = modern ] || {
	echo "FIVEBSD_GPU_TEST=yes requires TRANSPORTS=modern" >&2
	exit 2
}
[ "$FIVEBSD_RTC_TEST" = no ] || [ "$TRANSPORTS" = modern ] || {
	echo "FIVEBSD_RTC_TEST=yes requires TRANSPORTS=modern" >&2
	exit 2
}
[ "$FIVEBSD_INPUT_TEST" = no ] || [ "$TRANSPORTS" = modern ] || {
	echo "FIVEBSD_INPUT_TEST=yes requires TRANSPORTS=modern" >&2
	exit 2
}
[ "$FIVEBSD_NINEP_TEST" = no ] || [ "$TRANSPORTS" = modern ] || {
	echo "FIVEBSD_NINEP_TEST=yes requires TRANSPORTS=modern" >&2
	exit 2
}
[ "$FIVEBSD_RTC_TEST" = no ] || [ "$VIRTIO_DEBUG" -ge 2 ] ||
    VIRTIO_DEBUG=2
[ "$FIVEBSD_GPU_TEST" = no ] || [ "$VIRTIO_DEBUG" -ge 2 ] ||
    VIRTIO_DEBUG=2
case "$FIVEBSD_RNG_RESET_ITERATIONS" in
''|*[!0-9]*)
	echo "FIVEBSD_RNG_RESET_ITERATIONS must be a non-negative integer" >&2
	exit 2
	;;
esac
[ "$FIVEBSD_RNG_RESET_ITERATIONS" -le 1000 ] || {
	echo "FIVEBSD_RNG_RESET_ITERATIONS must not exceed 1000" >&2
	exit 2
}
case "$FIVEBSD_NET_TEST" in
yes|no) ;;
*) echo "FIVEBSD_NET_TEST must be yes or no" >&2; exit 2 ;;
esac
case "$FIVEBSD_NET_PACKED" in
yes|no) ;;
*) echo "FIVEBSD_NET_PACKED must be yes or no" >&2; exit 2 ;;
esac
[ "$FIVEBSD_NET_PACKED" = no ] || [ "$VIRTIO_DEBUG" -ge 2 ] ||
    VIRTIO_DEBUG=2
case "$FIVEBSD_BLOCK_QUEUES" in
''|*[!0-9]*) echo "FIVEBSD_BLOCK_QUEUES must be an integer" >&2; exit 2 ;;
esac
[ "$FIVEBSD_BLOCK_QUEUES" -ge 1 ] &&
    [ "$FIVEBSD_BLOCK_QUEUES" -le 8 ] || {
	echo "FIVEBSD_BLOCK_QUEUES must be between 1 and 8" >&2
	exit 2
}
[ "$FIVEBSD_BLOCK_QUEUES" -eq 1 ] || [ "$VIRTIO_DEBUG" -ge 2 ] ||
    VIRTIO_DEBUG=2
case "$FIVEBSD_SCSI_QUEUES" in
''|*[!0-9]*) echo "FIVEBSD_SCSI_QUEUES must be an integer" >&2; exit 2 ;;
esac
[ "$FIVEBSD_SCSI_QUEUES" -ge 0 ] &&
    [ "$FIVEBSD_SCSI_QUEUES" -le 8 ] || {
	echo "FIVEBSD_SCSI_QUEUES must be between 0 and 8" >&2
	exit 2
}
[ "$FIVEBSD_SCSI_QUEUES" -le 1 ] || [ "$VIRTIO_DEBUG" -ge 2 ] ||
    VIRTIO_DEBUG=2
[ "$FIVEBSD_SCSI_PACKED" = no ] ||
    [ "$FIVEBSD_SCSI_QUEUES" -gt 0 ] || {
	echo "FIVEBSD_SCSI_PACKED=yes requires FIVEBSD_SCSI_QUEUES>0" >&2
	exit 2
}
[ "$FIVEBSD_SCSI_EVENTS" = no ] ||
    { [ "$TRANSPORTS" = modern ] &&
      [ "$FIVEBSD_SCSI_QUEUES" -gt 0 ]; } || {
	echo "FIVEBSD_SCSI_EVENTS=yes requires modern transport and a SCSI device" >&2
	exit 2
}
case "$FIVEBSD_NET_QUEUES" in
''|*[!0-9]*) echo "FIVEBSD_NET_QUEUES must be an integer" >&2; exit 2 ;;
esac
[ "$FIVEBSD_NET_QUEUES" -ge 1 ] &&
    [ "$FIVEBSD_NET_QUEUES" -le 8 ] || {
	echo "FIVEBSD_NET_QUEUES must be between 1 and 8" >&2
	exit 2
}
case "$BALLOON_TARGET_MB" in
''|*[!0-9]*) echo "BALLOON_TARGET_MB must be a positive integer" >&2; exit 2 ;;
esac
[ "$BALLOON_TARGET_MB" -gt 0 ] &&
    [ "$BALLOON_TARGET_MB" -le 2048 ] || {
	echo "BALLOON_TARGET_MB must fit the 2 GiB test guest" >&2
	exit 2
}
balloon_target_pages=$((BALLOON_TARGET_MB * 256))
case "$FIVEBSD_BALLOON_STATS_INTERVAL" in
''|*[!0-9]*)
	echo "FIVEBSD_BALLOON_STATS_INTERVAL must be a non-negative integer" >&2
	exit 2
	;;
esac
if [ "$FIVEBSD_BALLOON_STATS_INTERVAL" -ne 0 ]; then
	[ "$FIVEBSD_BALLOON_STATS_INTERVAL" -le 3600 ] || {
		echo "FIVEBSD_BALLOON_STATS_INTERVAL must not exceed 3600" >&2
		exit 2
	}
	[ "$TRANSPORTS" = modern ] || {
		echo "FIVEBSD_BALLOON_STATS_INTERVAL requires modern transport" >&2
		exit 2
	}
	[ "$VIRTIO_DEBUG" -ge 1 ] || VIRTIO_DEBUG=1
fi
if [ "$FIVEBSD_BALLOON_PAGE_POISON" = yes ]; then
	[ "$TRANSPORTS" = modern ] || {
		echo "FIVEBSD_BALLOON_PAGE_POISON requires modern transport" >&2
		exit 2
	}
	[ "$FIVEBSD_BALLOON_DEFLATE_ON_OOM" = yes ] || {
		echo "FIVEBSD_BALLOON_PAGE_POISON requires FIVEBSD_BALLOON_DEFLATE_ON_OOM=yes so the live test can deflate pages" >&2
		exit 2
	}
	[ "$VIRTIO_DEBUG" -ge 1 ] || VIRTIO_DEBUG=1
fi

if [ -z "$BHYVE" ]; then
	object_bhyve="$OBJROOT$SRCTOP/$(uname -p).$(uname -p)/usr.sbin/bhyve/bhyve"
	if [ -x "$object_bhyve" ]; then
		BHYVE=$object_bhyve
	else
		BHYVE=$(command -v bhyve 2>/dev/null || true)
	fi
fi
if [ -z "$BHYVECTL" ]; then
	object_bhyvectl="$OBJROOT$SRCTOP/$(uname -p).$(uname -p)/usr.sbin/bhyvectl/bhyvectl"
	if [ -x "$object_bhyvectl" ]; then
		BHYVECTL=$object_bhyvectl
	else
		BHYVECTL=$(command -v bhyvectl 2>/dev/null || true)
	fi
fi

[ "$(id -u)" -eq 0 ] || {
	echo "run-5bsd-auto.sh must run as root" >&2
	exit 1
}
[ -f "$IMAGE" ] || { echo "5BSD image not found: $IMAGE" >&2; exit 1; }
case "$FIVEBSD_IMAGE_SHA256" in
''|*[!0-9a-f]*) echo "FIVEBSD_IMAGE_SHA256 must be a lowercase SHA-256 digest" >&2; exit 2 ;;
esac
[ "${#FIVEBSD_IMAGE_SHA256}" -eq 64 ] || {
	echo "FIVEBSD_IMAGE_SHA256 must contain exactly 64 hexadecimal digits" >&2
	exit 2
}
case "$FIVEBSD_BUILD_ID" in
''|*[!A-Za-z0-9._-]*) echo "FIVEBSD_BUILD_ID contains unsafe characters" >&2; exit 2 ;;
esac
base_image_sha256=$(sha256 -q "$IMAGE")
[ "$base_image_sha256" = "$FIVEBSD_IMAGE_SHA256" ] || {
	echo "5BSD image digest mismatch: expected=$FIVEBSD_IMAGE_SHA256 actual=$base_image_sha256" >&2
	exit 1
}
[ -x "$BHYVE" ] || { echo "bhyve not found: $BHYVE" >&2; exit 1; }
[ -x "$BHYVELOAD" ] || { echo "bhyveload not found: $BHYVELOAD" >&2; exit 1; }
[ -x "$BHYVECTL" ] || { echo "bhyvectl not found: $BHYVECTL" >&2; exit 1; }
if [ "$NONVIRTIO_CHECKPOINT" = yes ] || [ "$FIVEBSD_CHECKPOINT_TEST" = yes ]; then
	"$BHYVE" -h 2>&1 | grep -q -- '-r: path to checkpoint file' || {
		echo "5BSD checkpoint tests require snapshot-enabled bhyve" >&2
		exit 1
	}
	"$BHYVECTL" --help 2>&1 | grep -q -- '--checkpoint=<filename>' || {
		echo "5BSD checkpoint tests require snapshot-enabled bhyvectl" >&2
		exit 1
	}
	sysctl -n kern.conftxt 2>/dev/null | grep -Eq '^options[[:space:]]+BHYVE_SNAPSHOT([[:space:]]|$)' || {
		echo "5BSD checkpoint tests require a BHYVE_SNAPSHOT kernel" >&2
		exit 1
	}
fi
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

# A raw image must never be attached writable to two guests at once.  Refuse
# instead of stopping a VM the caller may still be using.
if pgrep -f "bhyve.*virtio-blk,$IMAGE" >/dev/null 2>&1; then
	echo "another bhyve process is already using $IMAGE" >&2
	echo "stop that VM before running this writable-image test" >&2
	exit 1
fi

prepare_workdir "$WORKDIR"
if [ -f "$here/Makefile" ]; then
	case "$VM_FREE_GATES" in
	yes) make -C "$here" ;;
	no) ;;
	*) echo "VM_FREE_GATES must be yes or no" >&2; exit 2 ;;
	esac
	tools=${TOOLS:-$(make -C "$here" -V .OBJDIR)}
else
	tools=${TOOLS:-$here}
fi
for tool in unix-pipe vsh-connect vsh-connect-test-server uinput-inject \
    freebsd-input-check freebsd-tpm2-check freebsd-fwcfg-check wdfire \
    vtcryptocbc; do
	[ -x "$tools/$tool" ] || {
		echo "built helper not found: $tools/$tool" >&2
		exit 1
	}
done
[ -f "$here/freebsd-nonvirtio.sh" ] || {
	echo "5BSD non-VirtIO guest helper not found: $here/freebsd-nonvirtio.sh" >&2
	exit 1
}
if [ "$NONVIRTIO_DEVICE" = fbuf ] || [ "$NONVIRTIO_DEVICE" = xhci ]; then
	[ -x "$tools/gpu-rfb-check" ] || {
		echo "built helper not found: $tools/gpu-rfb-check" >&2; exit 1
	}
fi
[ "$VM_FREE_GATES" = no ] ||
    TOOLS="$tools" sh "$here/host-tools-selftest.sh"
kldload -n vmm

if [ -z "$CONSOLE_PORT" ]; then
	CONSOLE_PORT=4500
	while nc -z 127.0.0.1 "$CONSOLE_PORT" >/dev/null 2>&1; do
		CONSOLE_PORT=$((CONSOLE_PORT + 1))
		[ "$CONSOLE_PORT" -lt 4600 ] || {
			echo "no free TCP console port in 4500..4599" >&2
			exit 1
		}
	done
fi

vm_pid=
console_pid=
port_exchange_pid=
input_pid=
input2_pid=
vmname=
image_md=
image_mount=
tap=
scsi_lun_id=
scsi_event_lun_id=
cleanup_vm()
{
	if [ -n "$port_exchange_pid" ]; then
		pkill -TERM -P "$port_exchange_pid" 2>/dev/null || true
		kill "$port_exchange_pid" 2>/dev/null || true
		wait "$port_exchange_pid" 2>/dev/null || true
	fi
	port_exchange_pid=
	if [ -n "$input_pid" ]; then
		kill "$input_pid" 2>/dev/null || true
		wait "$input_pid" 2>/dev/null || true
	fi
	input_pid=
	if [ -n "$input2_pid" ]; then
		kill "$input2_pid" 2>/dev/null || true
		wait "$input2_pid" 2>/dev/null || true
	fi
	input2_pid=
	virtio_ring_trace_stop
	[ -z "$console_pid" ] || pkill -TERM -P "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || kill "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || wait "$console_pid" 2>/dev/null || true
	console_pid=
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
	if [ -n "$tap" ]; then
		ifconfig "$BRIDGE" deletem "$tap" >/dev/null 2>&1 || true
		ifconfig "$tap" destroy >/dev/null 2>&1 || true
		tap=
	fi
	[ -z "$vmname" ] || "$BHYVECTL" --vm="$vmname" --destroy \
	    >/dev/null 2>&1 || true
	if [ -n "$image_md" ]; then
		[ -z "$image_mount" ] ||
		    umount "$image_mount" >/dev/null 2>&1 || true
		mdconfig -d -u "$image_md" >/dev/null 2>&1 || true
		image_md=
	fi
	[ -z "$image_mount" ] || rmdir "$image_mount" >/dev/null 2>&1 || true
	image_mount=
}
cleanup_all()
{
	status=${1:-$?}
	trap - EXIT HUP INT TERM
	if [ "$KEEP_VM" = no ]; then
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
	fi
	exit "$status"
}
trap 'cleanup_all $?' EXIT
trap 'cleanup_all 129' HUP
trap 'cleanup_all 130' INT
trap 'cleanup_all 143' TERM

if [ "$FIVEBSD_SCSI_QUEUES" -gt 0 ]; then
	command -v ctladm >/dev/null 2>&1 || {
		echo "FIVEBSD_SCSI_QUEUES requires ctladm" >&2
		exit 1
	}
	kldload -n ctl
	scsi_size_bytes=$((64 * 1024 * 1024 + ($$ % 8192) * 512))
	scsi_create_log="$WORKDIR/scsi-create.log"
	ctladm create -b ramdisk -s "$scsi_size_bytes" \
	    -o "capacity=$scsi_size_bytes" >"$scsi_create_log"
	scsi_lun_id=$(awk '/^LUN ID:/ {print $NF}' "$scsi_create_log")
	case "$scsi_lun_id" in
	''|*[!0-9]*)
		echo "invalid CTL LUN ID: $scsi_lun_id" >&2
		exit 1
		;;
	esac
	[ "$scsi_lun_id" -le 16383 ] || {
		echo "CTL LUN ID exceeds virtio-scsi limit: $scsi_lun_id" >&2
		exit 1
	}
fi

start_console()
{
	: > "$console_input"
	: > "$console_log"
	i=0
	while ! sockstat -4 -l | grep -q ":${CONSOLE_PORT}[[:space:]]"; do
		kill -0 "$vm_pid" 2>/dev/null || {
			echo "bhyve exited before its console became ready:" >&2
			tail -n 30 "$bhyve_log" >&2
			return 1
		}
		[ "$i" -lt 30 ] || {
			echo "bhyve console did not listen" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	(tail -f "$console_input" |
	    nc 127.0.0.1 "$CONSOLE_PORT" > "$console_log" 2>&1) &
	console_pid=$!
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

guest_check()
{
	label=$1
	command=$2
	limit=${3:-15}
	output=
	if output=$(guest_cmd "$command" "$limit"); then
		echo "PASS  preflight_$label"
		return 0
	else
		status=$?
	fi
	echo "FAIL  preflight_$label (guest status $status)" >&2
	[ -z "$output" ] || printf '%s\n' "$output" >&2
	echo "recent guest console output:" >&2
	tail -n 40 "$console_log" >&2
	echo "recent bhyve output:" >&2
	tail -n 40 "$bhyve_log" >&2
	return "$status"
}

audit_5bsd_virtio_features()
{
	expected=4
	specs="vtblk.0=$FIVEBSD_BLOCK_PACKED virtio_vsock.0=$FIVEBSD_VSOCK_PACKED vtrnd.0=$FIVEBSD_RNG_PACKED vtballoon.0=$BALLOON_PACKED"
	if [ "$FIVEBSD_SCSI_QUEUES" -gt 0 ]; then
		expected=$((expected + 1)); specs="$specs vtscsi.0=$FIVEBSD_SCSI_PACKED"
	fi
	if [ "$FIVEBSD_CONSOLE_TEST" = yes ]; then
		expected=$((expected + 1)); specs="$specs vtcon.0=$FIVEBSD_CONSOLE_PACKED"
	fi
	if [ "$FIVEBSD_NET_TEST" = yes ]; then
		expected=$((expected + 1)); specs="$specs vtnet.0=$FIVEBSD_NET_PACKED"
	fi
	if [ "$FIVEBSD_GPU_TEST" = yes ]; then
		expected=$((expected + 1)); specs="$specs vtgpu.0=$FIVEBSD_GPU_PACKED"
	fi
	if [ "$FIVEBSD_RTC_TEST" = yes ]; then
		expected=$((expected + 1)); specs="$specs vtrtc.0=$FIVEBSD_RTC_PACKED"
	fi
	if [ "$FIVEBSD_INPUT_TEST" = yes ]; then
		i=0
		while [ "$i" -lt "$FIVEBSD_INPUT_DEVICES" ]; do
			expected=$((expected + 1)); specs="$specs vtinput.$i=$FIVEBSD_INPUT_PACKED"
			i=$((i + 1))
		done
	fi
	if [ "$FIVEBSD_NINEP_TEST" = yes ]; then
		expected=$((expected + 1)); specs="$specs virtio_p9fs.0=$FIVEBSD_NINEP_PACKED"
	fi
	if [ "$FIVEBSD_SOUND_TEST" = yes ]; then
		expected=$((expected + 1)); specs="$specs pcm.0=$FIVEBSD_SOUND_PACKED"
	fi
	guest_check virtio_feature_inventory \
	    "status=0
nodes=\$(sysctl -aN 2>/dev/null | grep -E '^dev\.vtpci\.[0-9]+\.negotiated_features$' || :)
set -- \$nodes
printf 'FEATURE-INVENTORY transport=%s expected=%s actual=%s nodes=%s\\n' '$transport' '$expected' \"\$#\" \"\$nodes\"
if [ \"\$#\" -ne '$expected' ]; then
	echo 'FEATURE-ERROR transport-node-count' >&2
	status=1
fi
for node in \$nodes; do
	if ! features=\$(sysctl -n \"\$node\" 2>&1); then
		printf 'FEATURE-ERROR node=%s negotiated-read=%s\\n' \"\$node\" \"\$features\" >&2
		status=1
		continue
	fi
	host_node=\${node%negotiated_features}host_features
	if ! host=\$(sysctl -n \"\$host_node\" 2>&1); then
		printf 'FEATURE-ERROR node=%s host-read=%s\\n' \"\$node\" \"\$host\" >&2
		status=1
		continue
	fi
	printf 'FEATURES node=%s host=%s negotiated=%s\\n' \"\$node\" \"\$host\" \"\$features\"
	if [ '$transport' = modern ]; then
		printf '%s\\n' \"\$features\" | grep -q Version1 || {
			printf 'FEATURE-ERROR node=%s missing=Version1\\n' \"\$node\" >&2
			status=1
		}
	elif printf '%s\\n' \"\$features\" | grep -q Version1; then
		printf 'FEATURE-ERROR node=%s unexpected=Version1\\n' \"\$node\" >&2
		status=1
	fi
done
for spec in $specs; do
	child=\${spec%=*}
	wanted=\${spec#*=}
	if ! parent=\$(sysctl -n \"dev.\$child.%parent\" 2>&1); then
		printf 'FEATURE-ERROR child=%s parent-read=%s\\n' \"\$child\" \"\$parent\" >&2
		status=1
		continue
	fi
	unit=\${parent##*[!0-9]}
	name=\${parent%\$unit}
	if [ -z \"\$unit\" ] || ! features=\$(sysctl -n \"dev.\$name.\$unit.negotiated_features\" 2>&1); then
		printf 'FEATURE-ERROR child=%s parent=%s negotiated-read=%s\\n' \"\$child\" \"\$parent\" \"\${features:-missing}\" >&2
		status=1
		continue
	fi
	printf 'FEATURE-MAP child=%s parent=%s packed=%s negotiated=%s\\n' \"\$child\" \"\$parent\" \"\$wanted\" \"\$features\"
	if [ \"\$wanted\" = yes ]; then
		printf '%s\\n' \"\$features\" | grep -q RingPacked || {
			printf 'FEATURE-ERROR child=%s missing=RingPacked\\n' \"\$child\" >&2
			status=1
		}
	elif printf '%s\\n' \"\$features\" | grep -q RingPacked; then
		printf 'FEATURE-ERROR child=%s unexpected=RingPacked\\n' \"\$child\" >&2
		status=1
	fi
done
exit \"\$status\"" \
	    45
}

nonvirtio_pci_identity()
{
	case "$NONVIRTIO_DEVICE" in
	ahci) echo 'vendor=0x8086 device=0x2821 class=0x010601' ;;
	nvme) echo 'vendor=0xfb5d device=0x0a0a class=0x010802' ;;
	e82545) echo 'vendor=0x8086 device=0x100f class=0x020000' ;;
	hda) echo 'vendor=0x8086 device=0x27d8 class=0x040300' ;;
	xhci) echo 'vendor=0x8086 device=0x1e31 class=0x0c0330' ;;
	fbuf) echo 'vendor=0xfb5d device=0x40fb class=0x030000' ;;
	pci-uart) echo 'vendor=0x131f device=0x2000 class=0x070002' ;;
	i6300esb) echo 'vendor=0x8086 device=0x25ab class=0x088000' ;;
	hostbridge) echo 'vendor=0x1275 device=0x1275 class=0x060000' ;;
	*) return 1 ;;
	esac
}

run_nonvirtio_5bsd()
{
	case "$NONVIRTIO_DEVICE" in
	none) return 0 ;;
	ahci|nvme|e82545|hda|xhci|fbuf|pci-uart|i6300esb|hostbridge)
		identity=$(nonvirtio_pci_identity)
		address=pci0:21:0
		[ "$NONVIRTIO_DEVICE" != hostbridge ] || address=pci0:0:0
		set -- $identity
		vendor=${1#vendor=}; device=${2#device=}; class=${3#class=}
		guest_check "nonvirtio_${NONVIRTIO_DEVICE}_pci" \
		    "pciconf -l '$address' | grep -Eqi 'vendor=$vendor device=$device class=$class'"
		;;
	esac
	case "$NONVIRTIO_DEVICE" in
	ahci)
		guest_check nonvirtio_ahci_io "set -eu; disk=\$(/tmp/freebsd-nonvirtio ahci-disk); marker=/tmp/ahci-marker; dd if=/dev/random of=\$marker bs=4096 count=1 2>/dev/null; dd if=\$marker of=/dev/\$disk bs=4096 oseek=256 2>/dev/null; sync; dd if=/dev/\$disk of=/tmp/ahci-read bs=4096 skip=256 count=1 2>/dev/null; cmp \$marker /tmp/ahci-read"
		;;
	nvme)
		guest_check nonvirtio_nvme_io "set -eu; controller=\$(/tmp/freebsd-nonvirtio nvme-controller); disk=\$(/tmp/freebsd-nonvirtio nvme-disk); nvmecontrol identify \$controller >/tmp/nvme-identify; grep -q WASPNESTNVME /tmp/nvme-identify; marker=/tmp/nvme-marker; dd if=/dev/random of=\$marker bs=4096 count=1 2>/dev/null; dd if=\$marker of=/dev/\$disk bs=4096 oseek=256 2>/dev/null; sync; dd if=/dev/\$disk of=/tmp/nvme-read bs=4096 skip=256 count=1 2>/dev/null; cmp \$marker /tmp/nvme-read"
		;;
	e82545)
		guest_check nonvirtio_e82545_io "set -eu; iface=\$(/tmp/freebsd-nonvirtio e82545-interface); ifconfig \$iface up; dhclient \$iface; address=\$(ifconfig \$iface inet | awk '/inet /{print \$2; exit}'); gateway=\$(route -n get default | awk '/gateway:/{print \$2; exit}'); test -n \"\$address\"; test -n \"\$gateway\"; route -n get \$gateway | awk -v iface=\$iface '/interface:/{found=(\$2 == iface)} END {exit !found}'; ping -S \$address -c 3 \$gateway; netstat -I \$iface -b | awk 'NR > 1 && \$8 + \$11 > 0 { ok=1 } END { exit !ok }'" 90
		;;
	hda)
		guest_check nonvirtio_hda_io "set -eu; dsp=\$(/tmp/freebsd-nonvirtio hda-pcm); timeout 5 dd if=/dev/zero of=/dev/\$dsp bs=4096 count=32 2>/dev/null; timeout 5 dd if=/dev/\$dsp of=/tmp/hda-capture bs=4096 count=4 2>/dev/null; test -s /tmp/hda-capture" 30
		;;
	xhci)
		guest_check nonvirtio_xhci_descriptor "set -eu; unit=\$(/tmp/freebsd-nonvirtio xhci-ugen); usbconfig -d \$unit dump_device_desc | grep -q ."
		guest_cmd 'set -eu; mouse=$(/tmp/freebsd-nonvirtio xhci-mouse); rm -f /tmp/xhci-live.event; dd if=/dev/$mouse of=/tmp/xhci-live.event bs=8 count=1 2>/dev/null & echo $! >/tmp/xhci-live.pid'
		"$tools/gpu-rfb-check" "$nonvirtio_fbuf_socket" 1024 768 --pointer 127 131 1
		guest_check nonvirtio_xhci_input 'set -eu; pid=$(cat /tmp/xhci-live.pid); i=0; while kill -0 $pid 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done; ! kill -0 $pid 2>/dev/null; test -s /tmp/xhci-live.event' 20
		;;
	fbuf)
		guest_check nonvirtio_fbuf_io "set -eu; base=\$(pciconf -lb pci0:21:0 | awk '/bar[[:space:]]+\\[14\\]/{for(i=1;i<=NF;i++) if(\$i==\"base\") {gsub(/,/,\"\",\$(i+1)); print \$(i+1); exit}}'); test -n \"\$base\"; printf '\\023\\127\\233\\000' | dd of=/dev/mem bs=1 oseek=\$((base + (1024 - 1) * 4)) conv=notrunc 2>/dev/null; printf '\\044\\150\\254\\000' | dd of=/dev/mem bs=1 oseek=\$((base + (768 - 1) * 1024 * 4)) conv=notrunc 2>/dev/null"
		"$tools/gpu-rfb-check" "$nonvirtio_fbuf_socket" 1024 768
		;;
	pci-uart)
		marker="PCI-UART-LIVE-$transport-$$"
		guest_check nonvirtio_pci_uart_io "set -eu; uart=\$(/tmp/freebsd-nonvirtio pci-uart); tty=/dev/cuau\${uart#uart}; test -c \"\$tty\"; stty -f \"\$tty\" 115200 raw -echo; printf '%s\\n' '$marker' > \"\$tty\""
		grep -q "$marker" "$nonvirtio_uart_log"
		;;
	lpc-uart)
		marker="LPC-UART-LIVE-$transport-$$"
		guest_check nonvirtio_lpc_uart_io "test -c /dev/cuau1; stty -f /dev/cuau1 115200 raw -echo; printf '%s\\n' '$marker' > /dev/cuau1"
		grep -q "$marker" "$nonvirtio_uart_log"
		;;
	tpm-crb)
		guest_check nonvirtio_tpm_crb "set -eu; kldstat -q -m tpm || kldload tpm; i=0; while [ ! -c /dev/tpm0 ] && [ \$i -lt 50 ]; do sleep 0.1; i=\$((i + 1)); done; test -c /dev/tpm0; /tmp/freebsd-tpm2-check /dev/tpm0" 60
		;;
	qemu-fwcfg)
		guest_check nonvirtio_qemu_fwcfg "/tmp/freebsd-fwcfg-check live '$NONVIRTIO_FWCFG_NAME' '$NONVIRTIO_FWCFG_VALUE'" 30
		;;
	hostbridge)
		guest_check nonvirtio_hostbridge_topology "test \"\$(pciconf -l | wc -l)\" -ge 4; devinfo -rv | grep -q 'Host to PCI bridge'"
		;;
	i6300esb)
		# Confirm the in-tree i6300esbwd(4) watchdog driver binds the emulated
		# 8086:25ab function and that the platform watchdog(4) node is present.
		# The kernel watchdog device (/dev/fido) drives the hardware through
		# i6300esbwd's watchdog_list handler.
		guest_check nonvirtio_i6300esb_watchdog "set -eu; kldstat -q -m ichwd || kldload ichwd; i=0; while ! pciconf -l pci0:0:21:0 2>/dev/null | grep -q '^i6300esbwd' && [ \$i -lt 50 ]; do sleep 0.1; i=\$((i + 1)); done; pciconf -l pci0:0:21:0 | grep -q '^i6300esbwd'; sysctl -n dev.i6300esbwd.0.%desc >/dev/null; test -c /dev/fido" 60
		# Arm and pat the watchdog through /dev/fido with the wdfire helper.
		# The default lane disarms without ever lapsing; the fire case (gated
		# by WATCHDOG_EXPECT_RESET) instead stops feeding so the two-stage
		# timer lapses and bhyve applies action=notify (guest survives).
		if [ "$WATCHDOG_EXPECT_RESET" = 1 ]; then
			guest_check nonvirtio_i6300esb_fire \
			    "env WATCHDOG_EXPECT_RESET=1 /tmp/wdfire /dev/fido | grep -q 'fired=expected'" 60
			i=0
			while [ "$i" -lt 60 ]; do
				grep -q 'i6300esb: watchdog expired, applying action "notify"' "$bhyve_log" && break
				sleep 1; i=$((i + 1))
			done
			grep -q 'i6300esb: watchdog expired, applying action "notify"' "$bhyve_log" || {
				echo "FAIL  host_i6300esb_watchdog_action" >&2; exit 1
			}
			echo "PASS  host_i6300esb_watchdog_action action=notify"
		else
			guest_check nonvirtio_i6300esb_arm_pat_disarm \
			    "/tmp/wdfire /dev/fido | grep -q 'armed=yes fired=no'" 30
		fi
		;;
	pvpanic)
		# Confirm the ACPI QEMU0001 pvpanic device is present and the guest
		# acpi_pvpanic(4) driver attached (module: pvpanic).  The default lane
		# is non-destructive; the fire case (gated by PVPANIC_EXPECT_PANIC)
		# forces a real guest panic so the driver writes the PANICKED byte and
		# bhyve (action=none) logs it without killing the VM.
		guest_check nonvirtio_pvpanic_acpi "set -eu; kldload pvpanic 2>/dev/null || kldstat -q -m acpi_pvpanic || true; i=0; while ! sysctl -n dev.acpi_pvpanic.0.%desc >/dev/null 2>&1 && [ \$i -lt 50 ]; do sleep 0.1; i=\$((i + 1)); done; sysctl -n dev.acpi_pvpanic.0.%desc | grep -q pvpanic; sysctl -n dev.acpi_pvpanic.0.%pnpinfo | grep -q QEMU0001" 60
		if [ "$PVPANIC_EXPECT_PANIC" = yes ]; then
			# Fire-and-forget: the panic reboots the guest, so the arming
			# command may not return cleanly.  Proceed to observe the host log.
			guest_cmd 'sysctl debug.debugger_on_panic=0 >/dev/null 2>&1 || true; sysctl debug.kdb.panic=1 >/dev/null 2>&1 || true' 10 || true
			i=0
			while [ "$i" -lt 60 ]; do
				grep -q 'pvpanic: guest reported event 0x01' "$bhyve_log" && break
				sleep 1; i=$((i + 1))
			done
			grep -q 'pvpanic: guest reported event 0x01' "$bhyve_log" || {
				echo "FAIL  host_pvpanic_panicked" >&2; exit 1
			}
			echo "PASS  host_pvpanic_panicked event=0x01"
			# The guest has panicked and is gone; the case is complete.  Exit
			# now so later guest-dependent steps do not stall on a dead VM.
			# The EXIT trap (cleanup_all) tears down the VM and image.
			echo "PASS nonvirtio-live guest=5bsd device=pvpanic (fire)"
			exit 0
		fi
		;;
	passthru) guest_check nonvirtio_passthru "$NONVIRTIO_PASSTHRU_FIVEBSD_ASSERT" 60 ;;
	esac
	echo "PASS nonvirtio-live guest=5bsd device=$NONVIRTIO_DEVICE"
}

wait_nonvirtio_manifest()
{
	manifest=$1
	old_contents=${2:-}
	i=0
	while [ "$i" -lt 180 ]; do
		if [ -f "$manifest" ] &&
		    [ "$(sed -n '1p' "$manifest")" = BHYVE-CHECKPOINT-MANIFEST-3 ]; then
			contents=$(cat "$manifest")
			if [ -z "$old_contents" ] || [ "$contents" != "$old_contents" ]; then
				valid=yes
				for key in data kern meta; do
					member=$(printf '%s\n' "$contents" | sed -n "s/^$key=//p")
					case "$member" in
					''|*/*|.|..) valid=no; break ;;
					esac
					[ -f "$(dirname "$manifest")/$member" ] || {
						valid=no
						break
					}
				done
				[ "$valid" = no ] || return 0
			fi
		fi
		sleep 1; i=$((i + 1))
	done
	echo "checkpoint manifest was not published: $manifest" >&2
	return 1
}

launch_nonvirtio_restore_5bsd()
{
	manifest=$1
	set -- "$BHYVE" -c 2 -m 2G -H -w -r "$manifest" \
	    -s "0,hostbridge$nonvirtio_hostbridge_opt" -s "3,virtio-blk,$guest_image$block_opt" \
	    -s "5,virtio-vsock,cid=$CID,path=$sockdir$vsock_opt" \
	    -s "6,virtio-rnd$rng_opt"
	[ "$FIVEBSD_NET_TEST" = no ] || set -- "$@" -s "4,virtio-net,$tap$net_opt"
	[ -z "$balloon_opt" ] || set -- "$@" -s "7,virtio-balloon$balloon_opt"
	[ "$FIVEBSD_SCSI_QUEUES" -eq 0 ] || set -- "$@" -s "8,virtio-scsi,/dev/cam/ctl$scsi_opt"
	if [ "$FIVEBSD_BLOCK_DISCARD" = yes ] || [ "$FIVEBSD_BLOCK_WRITE_ZEROES" = yes ]; then
		set -- "$@" -s "9,virtio-blk,$discard_image$block_opt"
	fi
	[ "$FIVEBSD_CONSOLE_TEST" = no ] || set -- "$@" -s "10,virtio-console,$console_ports_opt$console_opt"
	[ "$FIVEBSD_BLOCK_READONLY" = no ] || set -- "$@" -s "11,virtio-blk,$readonly_image,ro=true$block_opt"
	[ "$FIVEBSD_GPU_TEST" = no ] || set -- "$@" -s "12,virtio-gpu$gpu_opt"
	[ "$FIVEBSD_RTC_TEST" = no ] || set -- "$@" -s "13,virtio-rtc$rtc_opt"
	[ "$FIVEBSD_INPUT_TEST" = no ] || set -- "$@" -s "14,virtio-input,$input_path$input_opt"
	[ "$FIVEBSD_INPUT_DEVICES" -eq 1 ] || set -- "$@" -s "15,virtio-input,$input2_path$input_opt"
	[ "$FIVEBSD_NINEP_TEST" = no ] || set -- "$@" -s "16,virtio-9p,$ninep_tag=$ninep_share$ninep_opt"
	[ "$FIVEBSD_SOUND_TEST" = no ] || set -- "$@" -s "17,virtio-snd$snd_opt"
	[ "$FIVEBSD_MEM_TEST" = no ] || set -- "$@" -s "18,virtio-mem$mem_opt"
	[ "$FIVEBSD_PMEM_TEST" = no ] || set -- "$@" -s "19,virtio-pmem,path=$pmem_image$pmem_opt"
	[ "$FIVEBSD_IOMMU_TEST" = no ] || set -- "$@" -s "20,virtio-iommu$iommu_opt"
	[ "$FIVEBSD_CRYPTO_TEST" = no ] || set -- "$@" -s "23,virtio-crypto$crypto_opt"
	case "$NONVIRTIO_DEVICE" in
	ahci) set -- "$@" -s "21,ahci-hd,$nonvirtio_image,checkpoint_identity=waspnest-ahci" ;;
	nvme) set -- "$@" -s "21,nvme,$nonvirtio_image,ser=WASPNESTNVME,ioslots=64,maxq=8,qsz=64" ;;
	e82545) set -- "$@" -s "21,e1000,$tap" ;;
	hda) set -- "$@" -s "21,hda,play=$NONVIRTIO_HDA_PLAY,rec=$NONVIRTIO_HDA_RECORD" ;;
	xhci) set -- "$@" -s "21,xhci,tablet" \
	    -s "22,fbuf,rfb=unix:$nonvirtio_fbuf_socket,w=1024,h=768,vga=off" ;;
	fbuf) set -- "$@" -s "21,fbuf,rfb=unix:$nonvirtio_fbuf_socket,w=1024,h=768,vga=off" ;;
	pci-uart) set -- "$@" -s "21,uart,tcp=127.0.0.1:$nonvirtio_uart_port,log=$nonvirtio_uart_log" ;;
	i6300esb) set -- "$@" -s "21,i6300esb,action=notify,timeout=2" ;;
	none|hostbridge|lpc-uart|qemu-fwcfg|pvpanic) ;;
	*) echo "restore is not supported for $NONVIRTIO_DEVICE" >&2; return 2 ;;
	esac
	set -- "$@" -s 31,lpc -l "com1,tcp=127.0.0.1:$CONSOLE_PORT"
	[ "$NONVIRTIO_DEVICE" != lpc-uart ] || set -- "$@" \
	    -l "com2,tcp=127.0.0.1:$nonvirtio_uart_port,log=$nonvirtio_uart_log"
	[ "$NONVIRTIO_DEVICE" != qemu-fwcfg ] || set -- "$@" \
	    -l fwcfg,qemu -f "$NONVIRTIO_FWCFG_NAME,string=$NONVIRTIO_FWCFG_VALUE"
	[ "$NONVIRTIO_DEVICE" != pvpanic ] || set -- "$@" -l pvpanic,action=none
	set -- "$@" "$vmname"
	env BHYVE_VIRTIO_DEBUG="$VIRTIO_DEBUG" \
	    BHYVE_VTBLK_DEBUG="$VIRTIO_DEBUG" \
	    BHYVE_VTSCSI_DEBUG="$VIRTIO_DEBUG" \
	    "$@" >> "$bhyve_log" 2>&1 &
	vm_pid=$!
	start_console
}

start_fwcfg_cursor_5bsd()
{
	phase=$1
	guest_cmd "set -eu; rm -f /tmp/fwcfg.ready.$phase /tmp/fwcfg.go.$phase /tmp/fwcfg.result.$phase /tmp/nonvirtio-checkpoint.log; nohup /tmp/freebsd-fwcfg-check active '$NONVIRTIO_FWCFG_NAME' '$NONVIRTIO_FWCFG_VALUE' /tmp/fwcfg.ready.$phase /tmp/fwcfg.go.$phase /tmp/fwcfg.result.$phase >/tmp/nonvirtio-checkpoint.log 2>&1 & echo \$! >/tmp/nonvirtio-checkpoint.pid; i=0; while [ ! -s /tmp/fwcfg.ready.$phase ] && kill -0 \$(cat /tmp/nonvirtio-checkpoint.pid) 2>/dev/null && [ \$i -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done; test -s /tmp/fwcfg.ready.$phase; kill -0 \$(cat /tmp/nonvirtio-checkpoint.pid)" 30
}

start_nonvirtio_checkpoint_5bsd()
{
	nonvirtio_checkpoint_phase=0
	case "$NONVIRTIO_DEVICE" in
	ahci|nvme)
		resolve="$NONVIRTIO_DEVICE-disk"
		guest_cmd "set -eu; disk=\$(/tmp/freebsd-nonvirtio $resolve); rm -f /tmp/nonvirtio-checkpoint.count /tmp/nonvirtio-checkpoint.log; dd if=/dev/random of=/tmp/nonvirtio-checkpoint.marker bs=4096 count=1 2>/dev/null; dd if=/tmp/nonvirtio-checkpoint.marker of=/dev/\$disk bs=4096 oseek=384 2>/dev/null; sync; (exec 3<>/dev/\$disk; i=0; while :; do i=\$((i + 1)); dd if=/dev/zero bs=4096 oseek=\$((512 + i % 64)) count=1 >&3 2>/dev/null; echo \$i > /tmp/nonvirtio-checkpoint.count; sleep 0.05; done) >/tmp/nonvirtio-checkpoint.log 2>&1 & echo \$! > /tmp/nonvirtio-checkpoint.pid" 30
		;;
	e82545)
		guest_cmd 'set -eu; iface=$(/tmp/freebsd-nonvirtio e82545-interface); address=$(ifconfig $iface inet | awk '\''/inet /{print $2; exit}'\''); gateway=$(route -n get default | awk '\''/gateway:/{print $2; exit}'\''); test -n "$address"; test -n "$gateway"; route -n get $gateway | awk -v iface=$iface '\''/interface:/{found=($2 == iface)} END {exit !found}'\''; rm -f /tmp/nonvirtio-checkpoint.log; ping -S $address -i 0.1 $gateway >/tmp/nonvirtio-checkpoint.log 2>&1 & echo $! >/tmp/nonvirtio-checkpoint.pid; netstat -I $iface -b | awk '\''NR > 1 {n += $8 + $11} END {print n + 0}'\'' >/tmp/nonvirtio-checkpoint.count' 30
		;;
	hda)
		guest_cmd 'set -eu; dsp=$(/tmp/freebsd-nonvirtio hda-pcm); rm -f /tmp/nonvirtio-checkpoint.count /tmp/nonvirtio-checkpoint.log; (exec 3>/dev/$dsp; i=0; while :; do i=$((i + 1)); dd if=/dev/zero bs=4096 count=4 >&3 2>/dev/null; echo $i >/tmp/nonvirtio-checkpoint.count; sleep 0.05; done) >/tmp/nonvirtio-checkpoint.log 2>&1 & echo $! >/tmp/nonvirtio-checkpoint.pid' 30
		;;
	xhci)
		guest_cmd 'set -eu; mouse=$(/tmp/freebsd-nonvirtio xhci-mouse); rm -f /tmp/nonvirtio-checkpoint.count /tmp/nonvirtio-checkpoint.log /tmp/xhci-checkpoint.event.*; echo 0 >/tmp/nonvirtio-checkpoint.count; dd if=/dev/$mouse of=/tmp/xhci-checkpoint.event.1 bs=8 count=1 2>/tmp/nonvirtio-checkpoint.log & echo $! >/tmp/nonvirtio-checkpoint.pid' 30
		;;
	fbuf)
		guest_cmd 'set -eu; base=$(pciconf -lb pci0:21:0 | awk '\''/bar[[:space:]]+\[14\]/{for(i=1;i<=NF;i++) if($i=="base") {gsub(/,/,"",$(i+1)); print $(i+1); exit}}'\''); test -n "$base"; printf "\023\127\233\000" | dd of=/dev/mem bs=1 oseek=$((base + (1024 - 1) * 4)) conv=notrunc 2>/dev/null; printf "\165\232\277\344" | dd of=/dev/mem bs=1 oseek=$((base + (768 - 1) * 1024 * 4)) conv=notrunc 2>/dev/null; echo 1 >/tmp/nonvirtio-checkpoint.count; sleep 100000 & echo $! >/tmp/nonvirtio-checkpoint.pid' 30
		;;
	pci-uart)
		guest_cmd 'set -eu; uart=$(/tmp/freebsd-nonvirtio pci-uart); tty=/dev/cuau${uart#uart}; rm -f /tmp/nonvirtio-checkpoint.count /tmp/nonvirtio-checkpoint.log; (exec 3>$tty; i=0; while :; do i=$((i + 1)); printf "PCI-UART-CHECKPOINT-%s\n" "$i" >&3; echo $i >/tmp/nonvirtio-checkpoint.count; sleep 0.05; done) >/tmp/nonvirtio-checkpoint.log 2>&1 & echo $! >/tmp/nonvirtio-checkpoint.pid' 30
		;;
	lpc-uart)
		guest_cmd 'set -eu; tty=/dev/cuau1; test -c $tty; rm -f /tmp/nonvirtio-checkpoint.count /tmp/nonvirtio-checkpoint.log; (exec 3>$tty; i=0; while :; do i=$((i + 1)); printf "LPC-UART-CHECKPOINT-%s\n" "$i" >&3; echo $i >/tmp/nonvirtio-checkpoint.count; sleep 0.05; done) >/tmp/nonvirtio-checkpoint.log 2>&1 & echo $! >/tmp/nonvirtio-checkpoint.pid' 30
		;;
	hostbridge)
		guest_cmd 'set -eu; pciconf -l | sort >/tmp/nonvirtio-topology.expected; rm -f /tmp/nonvirtio-checkpoint.count /tmp/nonvirtio-checkpoint.log; (i=0; while :; do i=$((i + 1)); pciconf -l pci0:0:0 >/dev/null; echo $i >/tmp/nonvirtio-checkpoint.count; sleep 0.05; done) >/tmp/nonvirtio-checkpoint.log 2>&1 & echo $! >/tmp/nonvirtio-checkpoint.pid' 30
		;;
	i6300esb)
		guest_cmd 'set -eu; kldstat -q -m ichwd || kldload ichwd; rm -f /tmp/nonvirtio-checkpoint.count /tmp/nonvirtio-checkpoint.log; (i=0; while :; do i=$((i + 1)); pciconf -l pci0:0:21:0 | grep -q "^i6300esbwd"; echo $i >/tmp/nonvirtio-checkpoint.count; sleep 0.05; done) >/tmp/nonvirtio-checkpoint.log 2>&1 & echo $! >/tmp/nonvirtio-checkpoint.pid' 30
		;;
	pvpanic)
		guest_cmd 'set -eu; kldload pvpanic 2>/dev/null || kldstat -q -m acpi_pvpanic || true; i=0; while ! sysctl -n dev.acpi_pvpanic.0.%desc >/dev/null 2>&1 && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done; sysctl -n dev.acpi_pvpanic.0.%desc >/dev/null; rm -f /tmp/nonvirtio-checkpoint.count /tmp/nonvirtio-checkpoint.log; (i=0; while :; do i=$((i + 1)); sysctl -n dev.acpi_pvpanic.0.%desc >/dev/null; echo $i >/tmp/nonvirtio-checkpoint.count; sleep 0.05; done) >/tmp/nonvirtio-checkpoint.log 2>&1 & echo $! >/tmp/nonvirtio-checkpoint.pid' 30
		;;
	qemu-fwcfg)
		start_fwcfg_cursor_5bsd 1
		nonvirtio_count=0
		return 0
		;;
	*) return 1 ;;
	esac
	if [ "$NONVIRTIO_DEVICE" = xhci ]; then
		guest_cmd 'kill -0 $(cat /tmp/nonvirtio-checkpoint.pid)' 10
		nonvirtio_count=0
		return 0
	fi
	i=0
	while [ "$i" -lt 30 ]; do
		nonvirtio_count=$(guest_cmd 'cat /tmp/nonvirtio-checkpoint.count 2>/dev/null || echo 0' 10)
		[ "$nonvirtio_count" -gt 0 ] 2>/dev/null && return 0
		sleep 1; i=$((i + 1))
	done
	guest_cmd 'cat /tmp/nonvirtio-checkpoint.log' 10 >&2 || true
	return 1
}

verify_nonvirtio_checkpoint_5bsd()
{
	case "$NONVIRTIO_DEVICE" in
	qemu-fwcfg)
		phase=$((nonvirtio_checkpoint_phase + 1))
		guest_check nonvirtio_qemu_fwcfg_cursor "set -eu; touch /tmp/fwcfg.go.$phase; i=0; while [ ! -s /tmp/fwcfg.result.$phase ] && kill -0 \$(cat /tmp/nonvirtio-checkpoint.pid) 2>/dev/null && [ \$i -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done; cat /tmp/nonvirtio-checkpoint.log; test \"\$(cat /tmp/fwcfg.result.$phase)\" = pass; i=0; while kill -0 \$(cat /tmp/nonvirtio-checkpoint.pid) 2>/dev/null && [ \$i -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done; ! kill -0 \$(cat /tmp/nonvirtio-checkpoint.pid) 2>/dev/null" 30
		nonvirtio_checkpoint_phase=$phase
		nonvirtio_count=$phase
		if [ "$phase" -eq 1 ]; then
			start_fwcfg_cursor_5bsd 2
		fi
		echo "PASS active-checkpoint-state guest=5bsd device=qemu-fwcfg cursor-phase=$phase"
		return 0
		;;
	xhci)
		event=$((nonvirtio_checkpoint_phase + 1))
		"$tools/gpu-rfb-check" "$nonvirtio_fbuf_socket" 1024 768 \
		    --pointer $((200 + event)) $((220 + event)) 1
		guest_check nonvirtio_xhci_pending_transfer "set -eu; pid=\$(cat /tmp/nonvirtio-checkpoint.pid); i=0; while kill -0 \$pid 2>/dev/null && [ \$i -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done; ! kill -0 \$pid 2>/dev/null; test -s /tmp/xhci-checkpoint.event.$event; echo $event >/tmp/nonvirtio-checkpoint.count" 20
		nonvirtio_count=$event
		if [ "$nonvirtio_checkpoint_phase" -eq 0 ]; then
			guest_cmd 'mouse=$(/tmp/freebsd-nonvirtio xhci-mouse); dd if=/dev/$mouse of=/tmp/xhci-checkpoint.event.2 bs=8 count=1 2>>/tmp/nonvirtio-checkpoint.log & echo $! >/tmp/nonvirtio-checkpoint.pid' 15
		fi
		nonvirtio_checkpoint_phase=$((nonvirtio_checkpoint_phase + 1))
		echo "PASS active-checkpoint-state guest=5bsd device=xhci pending-transfer=$event"
		return 0
		;;
	fbuf)
		if [ "$nonvirtio_checkpoint_phase" -eq 0 ]; then
			"$tools/gpu-rfb-check" "$nonvirtio_fbuf_socket" 1024 768 759abfe4
			guest_cmd 'base=$(pciconf -lb pci0:21:0 | awk '\''/bar[[:space:]]+\[14\]/{for(i=1;i<=NF;i++) if($i=="base") {gsub(/,/,"",$(i+1)); print $(i+1); exit}}'\''); printf "\206\253\300\365" | dd of=/dev/mem bs=1 oseek=$((base + (768 - 1) * 1024 * 4)) conv=notrunc 2>/dev/null; echo 2 >/tmp/nonvirtio-checkpoint.count' 15
			nonvirtio_count=2
		else
			# This check happens before any restored guest command rewrites the BAR.
			"$tools/gpu-rfb-check" "$nonvirtio_fbuf_socket" 1024 768 86abc0f5
			nonvirtio_count=2
		fi
		nonvirtio_checkpoint_phase=$((nonvirtio_checkpoint_phase + 1))
		echo "PASS active-checkpoint-state guest=5bsd device=fbuf phase=$nonvirtio_checkpoint_phase"
		return 0
		;;
	esac
	case "$NONVIRTIO_DEVICE" in
	ahci|nvme)
		resolve="$NONVIRTIO_DEVICE-disk"
		guest_check "nonvirtio_${NONVIRTIO_DEVICE}_checkpoint_marker" "set -eu; disk=\$(/tmp/freebsd-nonvirtio $resolve); dd if=/dev/\$disk of=/tmp/nonvirtio-checkpoint.read bs=4096 skip=384 count=1 2>/dev/null; cmp /tmp/nonvirtio-checkpoint.marker /tmp/nonvirtio-checkpoint.read"
		;;
	e82545)
		guest_check nonvirtio_e82545_open_socket 'set -eu; kill -0 $(cat /tmp/nonvirtio-checkpoint.pid); iface=$(/tmp/freebsd-nonvirtio e82545-interface); route -n get default | awk -v iface=$iface '\''/interface:/{found=($2 == iface)} END {exit !found}'\''' 15
		before=$nonvirtio_count
		i=0
		while [ "$i" -lt 30 ]; do
			after=$(guest_cmd 'iface=$(/tmp/freebsd-nonvirtio e82545-interface); netstat -I $iface -b | awk '\''NR > 1 {n += $8 + $11} END {print n + 0}'\''' 10)
			[ "$after" -gt "$before" ] 2>/dev/null && break
			sleep 1; i=$((i + 1))
		done
		[ "$i" -lt 30 ] || return 1
		nonvirtio_count=$after
		echo "PASS active-checkpoint-state guest=5bsd device=e82545 bytes_before=$before bytes_after=$after"
		return 0
		;;
	hda)
		guest_check nonvirtio_hda_open_stream 'set -eu; dsp=$(/tmp/freebsd-nonvirtio hda-pcm); procstat -f $(cat /tmp/nonvirtio-checkpoint.pid) | grep -q "/dev/$dsp"'
		;;
	pci-uart)
		guest_check nonvirtio_pci_uart_open_descriptor 'set -eu; uart=$(/tmp/freebsd-nonvirtio pci-uart); procstat -f $(cat /tmp/nonvirtio-checkpoint.pid) | grep -q "/dev/cuau${uart#uart}"'
		;;
	lpc-uart)
		guest_check nonvirtio_lpc_uart_open_descriptor 'procstat -f $(cat /tmp/nonvirtio-checkpoint.pid) | grep -q /dev/cuau1'
		;;
	hostbridge)
		guest_check nonvirtio_hostbridge_exact_topology 'pciconf -l | sort | cmp - /tmp/nonvirtio-topology.expected'
		;;
	esac
	before=$nonvirtio_count
	i=0
	while [ "$i" -lt 30 ]; do
		after=$(guest_cmd 'cat /tmp/nonvirtio-checkpoint.count 2>/dev/null || echo 0' 10)
		[ "$after" -gt "$before" ] 2>/dev/null && break
		sleep 1; i=$((i + 1))
	done
	[ "$i" -lt 30 ] || return 1
	nonvirtio_count=$after
	echo "PASS active-checkpoint-state guest=5bsd device=$NONVIRTIO_DEVICE before=$before after=$after"
}

verify_nonvirtio_topology_rejection_5bsd()
{
	[ "$NONVIRTIO_DEVICE" = hostbridge ] || return 0
	nonvirtio_hostbridge_opt=',vendor=0x8086,devid=0x1237'
	log_line=$(( $(wc -l < "$bhyve_log") + 1 ))
	# Device backends, including the TCP console, can become visible before
	# checkpoint validation finishes.  The launcher's status is therefore not
	# the restore result; wait for bhyve and require a non-zero exit.
	if launch_nonvirtio_restore_5bsd "$nonvirtio_checkpoint"; then :; fi
	i=0
	while kill -0 "$vm_pid" 2>/dev/null && [ "$i" -lt 30 ]; do
		sleep 1; i=$((i + 1))
	done
	if kill -0 "$vm_pid" 2>/dev/null; then
		echo "changed hostbridge topology unexpectedly remained running" >&2
		kill "$vm_pid" 2>/dev/null || true
		wait "$vm_pid" 2>/dev/null || true
		restore_status=0
	else
		if wait "$vm_pid" 2>/dev/null; then
			restore_status=0
		else
			restore_status=$?
		fi
	fi
	vm_pid=
	[ -z "$console_pid" ] || pkill -TERM -P "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || kill "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || wait "$console_pid" 2>/dev/null || true
	console_pid=
	"$BHYVECTL" --vm="$vmname" --destroy >/dev/null 2>&1 || true
	nonvirtio_hostbridge_opt=
	[ "$restore_status" -ne 0 ] || return 1
	sed -n "${log_line},\$p" "$bhyve_log" | \
	    grep -Eqi 'incompatible|Failed to restore|topology'
	echo "PASS incompatible checkpoint restore rejected contract=hostbridge-topology guest=5bsd"
}

run_nonvirtio_checkpoint_5bsd()
{
	rm -f "$nonvirtio_checkpoint" "$nonvirtio_checkpoint".*
	case "$NONVIRTIO_DEVICE" in
	tpm-crb|passthru)
		if "$BHYVECTL" --vm="$vmname" --checkpoint="$nonvirtio_checkpoint" \
		    >"$nonvirtio_checkpoint.stdout" 2>"$nonvirtio_checkpoint.stderr"; then
			echo "$NONVIRTIO_DEVICE unexpectedly accepted checkpoint" >&2; return 1
		fi
		grep -Eqi 'not supported|unsupported|cannot snapshot' \
		    "$nonvirtio_checkpoint.stdout" "$nonvirtio_checkpoint.stderr" "$bhyve_log"
		kill -0 "$vm_pid"
		[ ! -e "$nonvirtio_checkpoint" ] || {
			echo "rejected checkpoint published a manifest" >&2; return 1
		}
		run_nonvirtio_5bsd
		echo "PASS checkpoint-rejected guest=5bsd device=$NONVIRTIO_DEVICE"
		return 0
		;;
	esac
	start_nonvirtio_checkpoint_5bsd
	"$BHYVECTL" --vm="$vmname" --checkpoint="$nonvirtio_checkpoint"
	wait_nonvirtio_manifest "$nonvirtio_checkpoint"
	first_manifest=$(cat "$nonvirtio_checkpoint")
	verify_nonvirtio_checkpoint_5bsd
	"$BHYVECTL" --vm="$vmname" --suspend="$nonvirtio_checkpoint"
	i=0
	while kill -0 "$vm_pid" 2>/dev/null && [ "$i" -lt 180 ]; do sleep 1; i=$((i + 1)); done
	[ "$i" -lt 180 ] || return 1
	if wait "$vm_pid" 2>/dev/null; then :; else
		status=$?
		echo "suspended bhyve exited unsuccessfully: $status" >&2
		return 1
	fi
	vm_pid=
	[ -z "$console_pid" ] || pkill -TERM -P "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || kill "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || wait "$console_pid" 2>/dev/null || true
	console_pid=
	wait_nonvirtio_manifest "$nonvirtio_checkpoint" "$first_manifest"
	verify_nonvirtio_topology_rejection_5bsd
	launch_nonvirtio_restore_5bsd "$nonvirtio_checkpoint"
	guest_cmd 'test -s /tmp/nonvirtio-checkpoint.pid' 60
	verify_nonvirtio_checkpoint_5bsd
	guest_cmd 'pid=$(cat /tmp/nonvirtio-checkpoint.pid); kill $pid 2>/dev/null || true; i=0; while kill -0 $pid 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done; ! kill -0 $pid 2>/dev/null' 15
	run_nonvirtio_5bsd
	echo "PASS checkpoint-restore guest=5bsd device=$NONVIRTIO_DEVICE"
}

virtio_checkpoint_probe_5bsd()
{
	probe='set -eu; dd if=/dev/vtbd0 of=/dev/null bs=4096 count=1 2>/dev/null; dd if=/dev/random of=/dev/null bs=32 count=1 2>/dev/null; test "$(sysctl -n kern.vsock.guest_cid)" = '"$CID"
	[ -z "$balloon_opt" ] || probe="$probe; sysctl -n dev.vtballoon.0.current >/dev/null"
	if [ "$FIVEBSD_NET_TEST" = yes ]; then
		probe="$probe; iface=\$(ifconfig -l | tr ' ' '\\n' | grep '^vtnet' | head -n 1); test -n \"\$iface\"; gateway=\$(route -n get default | awk '/gateway:/{print \$2; exit}'); ping -c 1 -W 2 \"\$gateway\" >/dev/null"
	fi
	[ "$FIVEBSD_SCSI_QUEUES" -eq 0 ] ||
	    probe="$probe; camcontrol devlist | grep -q '<BHYVE '"
	[ "$FIVEBSD_CONSOLE_TEST" = no ] ||
	    probe="$probe; sysctl -aN | grep -q '^dev.vtcon.0.'"
	[ "$FIVEBSD_GPU_TEST" = no ] ||
	    probe="$probe; sysctl -aN | grep -q '^dev.vtgpu.0.'"
	[ "$FIVEBSD_RTC_TEST" = no ] ||
	    probe="$probe; sysctl -aN | grep -q '^dev.vtrtc.0.'"
	[ "$FIVEBSD_INPUT_TEST" = no ] ||
	    probe="$probe; sysctl -aN | grep -q '^dev.vtinput.0.'"
	if [ "$FIVEBSD_NINEP_TEST" = yes ]; then
		probe="$probe; mkdir -p /mnt/bhyve-checkpoint-9p; mount -t p9fs '$ninep_tag' /mnt/bhyve-checkpoint-9p; test \"\$(cat /mnt/bhyve-checkpoint-9p/host-seed)\" = '$ninep_seed'; umount /mnt/bhyve-checkpoint-9p"
	fi
	[ "$FIVEBSD_SOUND_TEST" = no ] ||
	    probe="$probe; sysctl -aN | grep -q '^dev.vtsnd.0.'"
	printf '%s' "$probe"
}

verify_virtio_checkpoint_worker_5bsd()
{
	before=$1
	i=0
	while [ "$i" -lt 30 ]; do
		after=$(guest_cmd 'cat /tmp/virtio-checkpoint.count 2>/dev/null || echo 0' 10)
		[ "$after" -gt "$before" ] 2>/dev/null && break
		sleep 1
		i=$((i + 1))
	done
	[ "$i" -lt 30 ] || {
		guest_cmd 'cat /tmp/virtio-checkpoint.log' 10 >&2 || true
		return 1
	}
	guest_cmd 'kill -0 $(cat /tmp/virtio-checkpoint.pid)' 10
	virtio_checkpoint_count=$after
	echo "PASS active-checkpoint-progress guest=5bsd before=$before after=$after"
}

run_virtio_checkpoint_5bsd()
{
	[ "$FIVEBSD_CHECKPOINT_TEST" = yes ] || return 0
	checkpoint="$rundir/virtio.checkpoint"
	rm -f "$checkpoint" "$checkpoint".*
	probe=$(virtio_checkpoint_probe_5bsd)
	guest_cmd "set -eu; printf '%s' '5bsd-checkpoint-$transport-$$' >/tmp/virtio-checkpoint.marker; rm -f /tmp/virtio-checkpoint.count /tmp/virtio-checkpoint.log; (i=0; while :; do i=\$((i + 1)); $probe; echo \$i >/tmp/virtio-checkpoint.count; sleep 0.05; done) >/tmp/virtio-checkpoint.log 2>&1 & echo \$! >/tmp/virtio-checkpoint.pid" 30
	virtio_checkpoint_count=0
	verify_virtio_checkpoint_worker_5bsd "$virtio_checkpoint_count"
	"$BHYVECTL" --vm="$vmname" --checkpoint="$checkpoint"
	wait_nonvirtio_manifest "$checkpoint"
	first_manifest=$(cat "$checkpoint")
	verify_virtio_checkpoint_worker_5bsd "$virtio_checkpoint_count"
	"$BHYVECTL" --vm="$vmname" --suspend="$checkpoint"
	i=0
	while kill -0 "$vm_pid" 2>/dev/null && [ "$i" -lt 180 ]; do
		sleep 1
		i=$((i + 1))
	done
	[ "$i" -lt 180 ] || return 1
	if wait "$vm_pid" 2>/dev/null; then :; else
		status=$?
		echo "suspended bhyve exited unsuccessfully: $status" >&2
		return 1
	fi
	vm_pid=
	[ -z "$console_pid" ] || pkill -TERM -P "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || kill "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || wait "$console_pid" 2>/dev/null || true
	console_pid=
	wait_nonvirtio_manifest "$checkpoint" "$first_manifest"
	launch_nonvirtio_restore_5bsd "$checkpoint"
	wait_for_guest
	guest_check fivebsd_restored_build \
	    "set -u; system=\$(uname -s); product=\$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null || :); embedded=\$(cat /etc/waspnest-build-id 2>/dev/null || :); actual=\$(cd /boot/kernel && find -s . -type f -exec sha256 -r {} \\; | sha256 -q) || actual=; printf '5BSD-RESTORE system=%s product=%s embedded=%s actual=%s\\n' \"\$system\" \"\$product\" \"\$embedded\" \"\$actual\"; test \"\$system\" = 5BSD; test \"\$product\" = 5bsd; test \"\$embedded\" = '$FIVEBSD_BUILD_ID'; test \"\$actual\" = '$FIVEBSD_BUILD_ID'; test \"\$(cat /tmp/virtio-checkpoint.marker)\" = '5bsd-checkpoint-$transport-$$'" \
	    60
	verify_virtio_checkpoint_worker_5bsd "$virtio_checkpoint_count"
	guest_cmd 'pid=$(cat /tmp/virtio-checkpoint.pid); kill $pid; i=0; while kill -0 $pid 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done; ! kill -0 $pid 2>/dev/null' 15
	echo "PASS checkpoint-restore guest=5bsd transport=$transport manifest=$checkpoint"
}

run_5bsd_console_exchange()
{
	label=$1
	port_name=$2
	port_socket=$3
	exchange_log=$4
	guest_token="guest-console-$label-$transport-$$"
	host_token="host-console-$label-$transport-$$"

	i=0
	while [ ! -S "$port_socket" ] && [ "$i" -lt 20 ]; do
		sleep 1
		i=$((i + 1))
	done
	[ -S "$port_socket" ] || {
		echo "FAIL  host_console_socket port=$label" >&2
		return 1
	}
	: >"$exchange_log"
	( { i=0
	    until grep -q "^$guest_token\$" "$exchange_log" 2>/dev/null; do
		    [ "$i" -lt 20 ] || exit 1
		    sleep 1
		    i=$((i + 1))
	    done
	    printf '%s\n' "$host_token"
	  } | timeout 30 "$tools/unix-pipe" "$port_socket" \
	    >"$exchange_log" ) &
	port_exchange_pid=$!
	guest_check "console_bidirectional_$label" \
	    "port='/dev/vtcon/$port_name'; test -c \"\$port\"; exec 3<>\"\$port\"; printf '%s\\n' '$guest_token' >&3; IFS= read -r token <&3; test \"\$token\" = '$host_token'" \
	    30
	wait "$port_exchange_pid"
	port_exchange_pid=
	grep -q "^$guest_token\$" "$exchange_log"
	echo "PASS  host_console_bidirectional port=$label"
}

host_device_lifecycle_check()
{
	device=$1

	grep -q "^${device}: device suspend complete\$" "$bhyve_log" || {
		echo "FAIL  host_device_suspend device=$device" >&2
		exit 1
	}
	grep -q "^${device}: device resume complete\$" "$bhyve_log" || {
		echo "FAIL  host_device_resume device=$device" >&2
		exit 1
	}
	echo "PASS  host_device_suspend_resume device=$device"
}

start_ring_trace()
{
	virtio_ring_trace_start "$vm_pid" "$ring_trace"
}

finish_ring_trace()
{
	layout=${1:-split}
	device=${2:-}

	virtio_ring_trace_finish "$ring_trace" "$layout" "$device"
}

wait_for_guest()
{
	login_sent=no
	i=0
	while [ "$i" -lt 120 ]; do
		if [ "$login_sent" = no ] && grep -q 'login:' "$console_log" 2>/dev/null; then
			printf 'root\r' >> "$console_input"
			login_sent=yes
			sleep 2
		fi
		if grep -Eq '(^|[[:space:]])root@[^[:space:]]+.*#[[:space:]]*$' \
		    "$console_log" 2>/dev/null &&
		    guest_cmd 'echo guest-ready' 8 2>/dev/null |
		    grep -q '^guest-ready$'; then
			return 0
		fi
		sleep 1
		i=$((i + 1))
	done
	echo "5BSD guest did not reach a usable root console" >&2
	tail -n 30 "$console_log" >&2
	return 1
}

prepare_guest_image()
{
	base=$1
	copy=$2
	fsck_log=$3

	echo "Creating sparse per-attempt guest image"
	dd if="$base" of="$copy" bs=4m conv=sparse status=none
	image_md=$(mdconfig -a -t vnode -f "$copy")
	ufs_partition=$(gpart show -p "$image_md" |
	    awk '$4 == "freebsd-ufs" { print "/dev/" $3; exit }')
	if [ -z "$ufs_partition" ]; then
		echo "no FreeBSD UFS partition found in $base" >&2
		return 1
	fi
	# Repair only the disposable copy.  The base image remains immutable.
	if ! fsck_ufs -fy "$ufs_partition" >"$fsck_log" 2>&1; then
		echo "fsck failed for cloned guest image:" >&2
		tail -n 40 "$fsck_log" >&2
		return 1
	fi
	if [ "$FIVEBSD_INPUT_TEST" = yes ] || [ "$FIVEBSD_CRYPTO_TEST" = yes ] ||
	    [ "$NONVIRTIO_DEVICE" != none ]; then
		image_mount="$copy.mount"
		mkdir -m 0700 "$image_mount"
		mount -t ufs "$ufs_partition" "$image_mount"
		if [ "$FIVEBSD_INPUT_TEST" = yes ]; then
			install -m 0555 "$tools/freebsd-input-check" \
			    "$image_mount/tmp/freebsd-input-check"
		fi
		if [ "$FIVEBSD_CRYPTO_TEST" = yes ]; then
			install -m 0555 "$tools/vtcryptocbc" \
			    "$image_mount/tmp/vtcryptocbc"
		fi
		if [ "$NONVIRTIO_DEVICE" != none ]; then
			install -m 0555 "$here/freebsd-nonvirtio.sh" \
			    "$image_mount/tmp/freebsd-nonvirtio"
		fi
		if [ "$NONVIRTIO_DEVICE" = tpm-crb ]; then
			install -m 0555 "$tools/freebsd-tpm2-check" \
			    "$image_mount/tmp/freebsd-tpm2-check"
		fi
		if [ "$NONVIRTIO_DEVICE" = qemu-fwcfg ]; then
			install -m 0555 "$tools/freebsd-fwcfg-check" \
			    "$image_mount/tmp/freebsd-fwcfg-check"
		fi
		if [ "$NONVIRTIO_DEVICE" = i6300esb ]; then
			install -m 0555 "$tools/wdfire" \
			    "$image_mount/tmp/wdfire"
		fi
		sync
		umount "$image_mount"
		rmdir "$image_mount"
		image_mount=
	fi
	mdconfig -d -u "$image_md"
	image_md=
}

shutdown_guest()
{
	# Prefer a clean UFS unmount.  A wedged or panicked guest is bounded by
	# cleanup_vm(), which escalates from TERM to KILL after five seconds.
	guest_cmd 'shutdown -p now' 8 >/dev/null 2>&1 || true
	i=0
	while kill -0 "$vm_pid" 2>/dev/null && [ "$i" -lt 60 ]; do
		sleep 1
		i=$((i + 1))
	done
}

for transport in $TRANSPORTS; do
	case "$transport" in
	modern)
		transport_opt=,transport=modern
		block_id=1042
		vsock_id=1053
		rng_id=1044
		balloon_id=1045
		scsi_id=1048
		block_opt="$transport_opt,queues=$FIVEBSD_BLOCK_QUEUES"
		rng_opt=$transport_opt
		vsock_opt=$transport_opt
		console_opt=",transport=modern"
		gpu_opt=",transport=modern,width=$FIVEBSD_GPU_WIDTH,height=$FIVEBSD_GPU_HEIGHT"
		rtc_opt=",transport=modern,alarm=true"
		input_opt=",transport=modern"
		ninep_opt=",transport=modern"
		balloon_opt=",target=${BALLOON_TARGET_MB}M"
		net_opt=",transport=modern,queues=$FIVEBSD_NET_QUEUES"
		scsi_opt=",transport=modern,queues=$FIVEBSD_SCSI_QUEUES"
		[ "$FIVEBSD_NET_PACKED" = no ] ||
		    net_opt="$net_opt,packed=true"
		[ "$VIRTIO_DEBUG" = 0 ] ||
		    net_opt="$net_opt,debug=$VIRTIO_DEBUG"
		[ "$BALLOON_PACKED" = no ] ||
		    balloon_opt="$balloon_opt,packed=true"
		[ "$FIVEBSD_BALLOON_STATS_INTERVAL" -eq 0 ] ||
		    balloon_opt="$balloon_opt,stats_interval=$FIVEBSD_BALLOON_STATS_INTERVAL"
		[ "$FIVEBSD_BALLOON_DEFLATE_ON_OOM" = no ] ||
		    balloon_opt="$balloon_opt,deflate_on_oom=true"
		[ "$FIVEBSD_BALLOON_PAGE_POISON" = no ] ||
		    balloon_opt="$balloon_opt,page_poison=true"
		[ "$FIVEBSD_BLOCK_PACKED" = no ] ||
		    block_opt="$block_opt,packed=true"
		[ "$FIVEBSD_SCSI_PACKED" = no ] ||
		    scsi_opt="$scsi_opt,packed=true"
		[ "$FIVEBSD_RNG_PACKED" = no ] ||
		    rng_opt="$rng_opt,packed=true"
		[ "$FIVEBSD_VSOCK_PACKED" = no ] ||
		    vsock_opt="$vsock_opt,packed=true"
		[ "$FIVEBSD_CONSOLE_PACKED" = no ] ||
		    console_opt="$console_opt,packed=true"
		[ "$FIVEBSD_GPU_PACKED" = no ] ||
		    gpu_opt="$gpu_opt,packed=true"
		[ "$FIVEBSD_RTC_PACKED" = no ] ||
		    rtc_opt="$rtc_opt,packed=true"
		[ "$FIVEBSD_INPUT_PACKED" = no ] ||
		    input_opt="$input_opt,packed=true"
		[ "$FIVEBSD_NINEP_PACKED" = no ] ||
		    ninep_opt="$ninep_opt,packed=true"
		snd_opt=",transport=modern"
		mem_opt=",transport=modern,size=256M,requested=128M"
		pmem_opt=",transport=modern"
		iommu_opt=",transport=modern"
		crypto_opt=",transport=modern"
		[ "$FIVEBSD_SOUND_PACKED" = no ] ||
		    snd_opt="$snd_opt,packed=true"
		;;
	legacy)
		# Deliberately omit transport=legacy: this validates compatibility
		# for every existing command line which has no transport option.
		transport_opt=
		block_id=1001
		vsock_id=1013
		rng_id=1005
		scsi_id=1008
		block_opt=
		rng_opt=
		vsock_opt=
		console_opt=
		gpu_opt=
		rtc_opt=
		input_opt=
		ninep_opt=
		balloon_opt=
		net_opt=
		scsi_opt=
		snd_opt=
		mem_opt=
		pmem_opt=
		iommu_opt=
		crypto_opt=
		[ "$BALLOON_PACKED" = no ] || {
			echo "BALLOON_PACKED=yes requires modern transport" >&2
			exit 2
		}
		[ "$FIVEBSD_NET_PACKED" = no ] || {
			echo "FIVEBSD_NET_PACKED=yes requires modern transport" >&2
			exit 2
		}
		[ "$FIVEBSD_BLOCK_PACKED" = no ] &&
		    [ "$FIVEBSD_SCSI_PACKED" = no ] &&
		    [ "$FIVEBSD_RNG_PACKED" = no ] &&
		    [ "$FIVEBSD_VSOCK_PACKED" = no ] &&
		    [ "$FIVEBSD_CONSOLE_TEST" = no ] &&
		    [ "$FIVEBSD_CONSOLE_PACKED" = no ] &&
		    [ "$FIVEBSD_GPU_TEST" = no ] &&
		    [ "$FIVEBSD_GPU_PACKED" = no ] &&
		    [ "$FIVEBSD_RTC_TEST" = no ] &&
		    [ "$FIVEBSD_RTC_PACKED" = no ] &&
		    [ "$FIVEBSD_INPUT_TEST" = no ] &&
		    [ "$FIVEBSD_INPUT_PACKED" = no ] &&
		    [ "$FIVEBSD_NINEP_TEST" = no ] &&
		    [ "$FIVEBSD_NINEP_PACKED" = no ] &&
		    [ "$FIVEBSD_SOUND_TEST" = no ] &&
		    [ "$FIVEBSD_SOUND_PACKED" = no ] &&
		    [ "$FIVEBSD_MEM_TEST" = no ] &&
		    [ "$FIVEBSD_PMEM_TEST" = no ] &&
		    [ "$FIVEBSD_IOMMU_TEST" = no ] &&
		    [ "$FIVEBSD_CRYPTO_TEST" = no ] &&
		    [ "$FIVEBSD_NOTIFICATION_DATA" = no ] || {
			echo "packed and notification-data options require modern transport" >&2
			exit 2
		}
		[ "$FIVEBSD_RNG_RESET_ITERATIONS" -eq 0 ] || {
			echo "FIVEBSD_RNG_RESET_ITERATIONS requires modern transport" >&2
			exit 2
		}
		[ "$FIVEBSD_BLOCK_QUEUES" -eq 1 ] || {
			echo "FIVEBSD_BLOCK_QUEUES>1 requires modern transport" >&2
			exit 2
		}
		[ "$FIVEBSD_BLOCK_DISCARD" = no ] || {
			echo "FIVEBSD_BLOCK_DISCARD=yes requires modern transport" >&2
			exit 2
		}
		[ "$FIVEBSD_BLOCK_WRITE_ZEROES" = no ] || {
			echo "FIVEBSD_BLOCK_WRITE_ZEROES=yes requires modern transport" >&2
			exit 2
		}
		[ "$FIVEBSD_BLOCK_READONLY" = no ] || {
			echo "FIVEBSD_BLOCK_READONLY=yes requires modern transport" >&2
			exit 2
		}
		[ "$FIVEBSD_BLOCK_WCE" = no ] || {
			echo "FIVEBSD_BLOCK_WCE=yes requires modern transport" >&2
			exit 2
		}
		[ "$FIVEBSD_SCSI_QUEUES" -le 1 ] || {
			echo "FIVEBSD_SCSI_QUEUES>1 requires modern transport" >&2
			exit 2
		}
		;;
	*)
		echo "invalid transport: $transport" >&2
		exit 2
		;;
	esac

	vmname="vsock-5bsd-${transport}-$$"
	rundir="$WORKDIR/$transport.$$"
	sockdir="$rundir/sockets"
	console_input="$rundir/console.in"
	console_log="$rundir/console.log"
	bhyve_log="$rundir/bhyve.log"
	port_exchange_log="$rundir/virtio-console-exchange.log"
	console_name="bhyve-5bsd-console-$transport-$$"
	console_socket="$rundir/virtio-console.sock"
	port_exchange_log2="$rundir/virtio-console-exchange2.log"
	console_name2="bhyve-5bsd-console2-$transport-$$"
	console_socket2="$rundir/virtio-console2.sock"
	console_ports_opt="$console_name=$console_socket,console-port=0"
	[ "$FIVEBSD_CONSOLE_PORTS" -eq 1 ] ||
	    console_ports_opt="$console_ports_opt,$console_name2=$console_socket2"
	ring_trace="$rundir/virtio-ring.trace"
	input_fifo="$rundir/input.fifo"
	input_path_file="$rundir/input.path"
	input_log="$rundir/input.log"
	input_name="bhyve-5bsd-input-$transport-$$"
	input2_fifo="$rundir/input2.fifo"
	input2_path_file="$rundir/input2.path"
	input2_log="$rundir/input2.log"
	input2_name="bhyve-5bsd-input2-$transport-$$"
	ninep_share="$rundir/9p-share"
	ninep_tag="bhyve-5bsd-9p-$transport-$$"
	ninep_seed="host-seed-$transport-$$"
	ninep_outside="$rundir/9p-outside"
	ninep_outside_name=$(basename "$ninep_outside")
	ninep_escape_create="$rundir/9p-escape-created"
	ninep_escape_create_name=$(basename "$ninep_escape_create")
	discard_image="$rundir/block-discard.img"
	readonly_image="$rundir/block-readonly.img"
	pmem_image="$rundir/pmem-backing.img"
	readonly_digest=
	guest_image="$rundir/guest.img"
	nonvirtio_image="$rundir/nonvirtio.img"
	nonvirtio_fbuf_socket="$rundir/nonvirtio-vnc.sock"
	nonvirtio_uart_log="$rundir/nonvirtio-uart.log"
	nonvirtio_uart_port=$((CONSOLE_PORT + 1))
	nonvirtio_hostbridge_opt=
	nonvirtio_checkpoint="$rundir/nonvirtio.checkpoint"
	fsck_log="$rundir/fsck.log"
	mkdir -p -m 0700 "$sockdir"
	if [ "$FIVEBSD_NINEP_TEST" = yes ]; then
		mkdir -m 0700 "$ninep_share"
		printf %s "$ninep_seed" >"$ninep_share/host-seed"
		printf '%s\n' "must-not-cross-9p-export" >"$ninep_outside"
		ln -s .. "$ninep_share/escape"
	fi
	: > "$bhyve_log"
	: > "$nonvirtio_uart_log"
	case "$NONVIRTIO_DEVICE" in
	ahci|nvme) truncate -s "${NONVIRTIO_IMAGE_MB}M" "$nonvirtio_image" ;;
	esac

	echo "== 5BSD $transport: boot and test =="
	prepare_guest_image "$IMAGE" "$guest_image" "$fsck_log"
	if [ "$FIVEBSD_BLOCK_DISCARD" = yes ] ||
	    [ "$FIVEBSD_BLOCK_WRITE_ZEROES" = yes ]; then
		truncate -s 64M "$discard_image"
	fi
	if [ "$FIVEBSD_BLOCK_READONLY" = yes ]; then
		dd if=/dev/random of="$readonly_image" bs=1m count=8 \
		    > /dev/null 2>&1
		readonly_digest=$(sha256 -q "$readonly_image")
	fi
	if [ "$FIVEBSD_PMEM_TEST" = yes ]; then
		# virtio-pmem needs an exclusive durable file backing the shared
		# memory region the guest driver maps and flushes.
		truncate -s "${PMEM_IMAGE_MB:-64}M" "$pmem_image"
	fi
	if [ "$FIVEBSD_NET_TEST" = yes ] || [ "$NONVIRTIO_DEVICE" = e82545 ]; then
		[ "$transport" = modern ] || {
			echo "network device tests require modern transport" >&2
			exit 2
		}
		ifconfig "$BRIDGE" >/dev/null 2>&1 || {
			echo "5BSD network test requires bridge $BRIDGE" >&2
			exit 1
		}
		tap=$(ifconfig tap create)
		ifconfig "$tap" up
		ifconfig "$BRIDGE" addm "$tap"
	fi
	if [ "$FIVEBSD_INPUT_TEST" = yes ]; then
		kldload -n uinput
		rm -f "$input_fifo" "$input_path_file"
		mkfifo -m 0600 "$input_fifo"
		"$tools/uinput-inject" "$input_fifo" "$input_name" \
		    >"$input_path_file" 2>"$input_log" &
		input_pid=$!
		i=0
		while [ ! -s "$input_path_file" ] &&
		    kill -0 "$input_pid" 2>/dev/null && [ "$i" -lt 10 ]; do
			sleep 1
			i=$((i + 1))
		done
		[ -s "$input_path_file" ] ||
		    { cat "$input_log" >&2; exit 1; }
		input_path=$(sed -n '1p' "$input_path_file")
		case "$input_path" in
		/dev/input/event*)
			input_unit=${input_path#/dev/input/event}
			case "$input_unit" in
			''|*[!0-9]*)
				echo "unsafe uinput path: $input_path" >&2
				exit 1
				;;
			esac
			;;
		*)
			echo "unsafe uinput path: $input_path" >&2
			exit 1
			;;
		esac
		if [ "$FIVEBSD_INPUT_DEVICES" -eq 2 ]; then
			rm -f "$input2_fifo" "$input2_path_file"
			mkfifo -m 0600 "$input2_fifo"
			"$tools/uinput-inject" "$input2_fifo" "$input2_name" \
			    >"$input2_path_file" 2>"$input2_log" &
			input2_pid=$!
			i=0
			while [ ! -s "$input2_path_file" ] &&
			    kill -0 "$input2_pid" 2>/dev/null &&
			    [ "$i" -lt 10 ]; do
				sleep 1
				i=$((i + 1))
			done
			[ -s "$input2_path_file" ] ||
			    { cat "$input2_log" >&2; exit 1; }
			input2_path=$(sed -n '1p' "$input2_path_file")
			case "$input2_path" in
			/dev/input/event*)
				input2_unit=${input2_path#/dev/input/event}
				case "$input2_unit" in
				''|*[!0-9]*)
					echo "unsafe uinput path: $input2_path" >&2
					exit 1
					;;
				esac
				;;
			*)
				echo "unsafe uinput path: $input2_path" >&2
				exit 1
				;;
			esac
		fi
	fi
	"$BHYVELOAD" -c /dev/null -m 2G -d "$guest_image" "$vmname" \
	    >> "$bhyve_log" 2>&1
	set -- "$BHYVE" -c 2 -m 2G -H -w \
	    -s "0,hostbridge$nonvirtio_hostbridge_opt" \
	    -s "3,virtio-blk,$guest_image$block_opt" \
	    -s "5,virtio-vsock,cid=$CID,path=$sockdir$vsock_opt" \
	    -s "6,virtio-rnd$rng_opt"
	[ "$FIVEBSD_NET_TEST" = no ] || set -- "$@" \
	    -s "4,virtio-net,$tap$net_opt"
	[ -z "$balloon_opt" ] || set -- "$@" \
	    -s "7,virtio-balloon$balloon_opt"
	[ "$FIVEBSD_SCSI_QUEUES" -eq 0 ] || set -- "$@" \
	    -s "8,virtio-scsi,/dev/cam/ctl$scsi_opt"
	if [ "$FIVEBSD_BLOCK_DISCARD" = yes ] ||
	    [ "$FIVEBSD_BLOCK_WRITE_ZEROES" = yes ]; then
		set -- "$@" -s "9,virtio-blk,$discard_image$block_opt"
	fi
	[ "$FIVEBSD_CONSOLE_TEST" = no ] || set -- "$@" \
	    -s "10,virtio-console,$console_ports_opt$console_opt"
	[ "$FIVEBSD_BLOCK_READONLY" = no ] || set -- "$@" \
	    -s "11,virtio-blk,$readonly_image,ro=true$block_opt"
	[ "$FIVEBSD_GPU_TEST" = no ] || set -- "$@" \
	    -s "12,virtio-gpu$gpu_opt"
	[ "$FIVEBSD_RTC_TEST" = no ] || set -- "$@" \
	    -s "13,virtio-rtc$rtc_opt"
	[ "$FIVEBSD_INPUT_TEST" = no ] || set -- "$@" \
	    -s "14,virtio-input,$input_path$input_opt"
	[ "$FIVEBSD_INPUT_DEVICES" -eq 1 ] || set -- "$@" \
	    -s "15,virtio-input,$input2_path$input_opt"
	[ "$FIVEBSD_NINEP_TEST" = no ] || set -- "$@" \
	    -s "16,virtio-9p,$ninep_tag=$ninep_share$ninep_opt"
	[ "$FIVEBSD_SOUND_TEST" = no ] || set -- "$@" \
	    -s "17,virtio-snd$snd_opt"
	[ "$FIVEBSD_MEM_TEST" = no ] || set -- "$@" \
	    -s "18,virtio-mem$mem_opt"
	[ "$FIVEBSD_PMEM_TEST" = no ] || set -- "$@" \
	    -s "19,virtio-pmem,path=$pmem_image$pmem_opt"
	[ "$FIVEBSD_IOMMU_TEST" = no ] || set -- "$@" \
	    -s "20,virtio-iommu$iommu_opt"
	[ "$FIVEBSD_CRYPTO_TEST" = no ] || set -- "$@" \
	    -s "23,virtio-crypto$crypto_opt"
	case "$NONVIRTIO_DEVICE" in
	none|lpc-uart|tpm-crb|hostbridge|qemu-fwcfg|pvpanic) ;;
	ahci) set -- "$@" -s "21,ahci-hd,$nonvirtio_image,checkpoint_identity=waspnest-ahci" ;;
	nvme) set -- "$@" -s "21,nvme,$nonvirtio_image,ser=WASPNESTNVME,ioslots=64,maxq=8,qsz=64" ;;
	e82545) set -- "$@" -s "21,e1000,$tap" ;;
	hda) set -- "$@" -s "21,hda,play=$NONVIRTIO_HDA_PLAY,rec=$NONVIRTIO_HDA_RECORD" ;;
	xhci) set -- "$@" -s "21,xhci,tablet" \
	    -s "22,fbuf,rfb=unix:$nonvirtio_fbuf_socket,w=1024,h=768,vga=off" ;;
	fbuf) set -- "$@" -s "21,fbuf,rfb=unix:$nonvirtio_fbuf_socket,w=1024,h=768,vga=off" ;;
	pci-uart) set -- "$@" -s "21,uart,tcp=127.0.0.1:$nonvirtio_uart_port,log=$nonvirtio_uart_log" ;;
	i6300esb) set -- "$@" -s "21,i6300esb,action=notify,timeout=2" ;;
	passthru) set -- "$@" -S -s "21,passthru,$NONVIRTIO_PASSTHRU" ;;
	esac
	set -- "$@" -s 31,lpc -l "com1,tcp=127.0.0.1:$CONSOLE_PORT"
	[ "$NONVIRTIO_DEVICE" != lpc-uart ] || set -- "$@" \
	    -l "com2,tcp=127.0.0.1:$nonvirtio_uart_port,log=$nonvirtio_uart_log"
	[ "$NONVIRTIO_DEVICE" != tpm-crb ] || set -- "$@" \
	    -l "tpm,$NONVIRTIO_TPM_TYPE,$NONVIRTIO_TPM_PATH,version=2.0"
	[ "$NONVIRTIO_DEVICE" != qemu-fwcfg ] || set -- "$@" \
	    -l fwcfg,qemu -f "$NONVIRTIO_FWCFG_NAME,string=$NONVIRTIO_FWCFG_VALUE"
	[ "$NONVIRTIO_DEVICE" != pvpanic ] || set -- "$@" -l pvpanic,action=none
	set -- "$@" "$vmname"
	env BHYVE_VIRTIO_DEBUG="$VIRTIO_DEBUG" \
	    BHYVE_VTBLK_DEBUG="$VIRTIO_DEBUG" \
	    BHYVE_VTSCSI_DEBUG="$VIRTIO_DEBUG" \
	    "$@" >> "$bhyve_log" 2>&1 &
	vm_pid=$!
	start_console
	wait_for_guest
	guest_check fivebsd_current_build \
	    "set -u; system=\$(uname -s); product=\$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null || :); embedded=\$(cat /etc/waspnest-build-id 2>/dev/null || :); actual=\$(cd /boot/kernel && find -s . -type f -exec sha256 -r {} \\; | sha256 -q) || actual=; printf '5BSD-BUILD system=%s product=%s kernel=%s machine=%s embedded=%s actual=%s\\n' \"\$system\" \"\$product\" \"\$(uname -K)\" \"\$(uname -m)\" \"\$embedded\" \"\$actual\"; test \"\$system\" = 5BSD; test \"\$product\" = 5bsd; test \"\$embedded\" = '$FIVEBSD_BUILD_ID'; test \"\$actual\" = '$FIVEBSD_BUILD_ID'" \
	    60
	if [ "$FIVEBSD_RING_TRACE" = yes ]; then
		start_ring_trace
		guest_check ring_features_negotiated \
		    "set -eu; parent=\$(sysctl -n dev.vtblk.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; features=\$(sysctl -n \"dev.\$name.\$unit.negotiated_features\"); printf '%s\\n' \"\$features\" | grep -q RingIndirectDesc; printf '%s\\n' \"\$features\" | grep -q RingEventIdx"
	fi

	guest_check cid \
	    "test \"\$(sysctl -n kern.vsock.guest_cid)\" = $CID"
	guest_check vsock_pci \
	    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x${vsock_id}([[:space:]]|$)'"
	guest_check block_pci \
	    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x${block_id}([[:space:]]|$)'"
	guest_check rng_pci \
	    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x${rng_id}([[:space:]]|$)'"
	if [ "$FIVEBSD_GPU_TEST" = yes ]; then
		guest_check gpu_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x1050([[:space:]]|$)'"
		guest_check gpu_driver_and_commands \
		    "kldload virtio_gpu 2>/dev/null || kldstat -q -m virtio_gpu; devinfo -rv | grep -q 'vtgpu0'"
		gpu_notifies=$(grep -Ec \
		    '^vtgpu: modern notify q=0([[:space:]]|$)' "$bhyve_log" ||
		    true)
		[ "$gpu_notifies" -ge 6 ] || {
			echo "FAIL  host_gpu_2d_commands count=$gpu_notifies expected>=6" >&2
			exit 1
		}
		echo "PASS  host_gpu_2d_commands count=$gpu_notifies"
		if [ "$FIVEBSD_GPU_PACKED" = yes ]; then
			guest_check gpu_packed_negotiated \
			    "parent=\$(sysctl -n dev.vtgpu.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q RingPacked"
			grep -Eq \
			    '^vtgpu: modern queue enable q=0 .*enabled=1 .*layout=packed' \
			    "$bhyve_log" || {
				echo "FAIL  host_gpu_packed_layout" >&2
				exit 1
			}
			echo "PASS  host_gpu_packed_control"
		fi
	fi
	if [ "$FIVEBSD_RTC_TEST" = yes ]; then
		guest_check rtc_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x1051([[:space:]]|$)'"
		guest_check rtc_driver_and_read \
		    "kldload virtio_rtc 2>/dev/null || kldstat -q -m virtio_rtc; devinfo -rv | grep -q 'vtrtc0'"
		guest_check rtc_alarm_notification \
		    "set -eu; before=\$(sysctl -n dev.vtrtc.0.alarm_count); now=\$(date +%s); deadline=\$(((now + 4) * 1000000000)); sysctl dev.vtrtc.0.alarm_time_ns=\$deadline >/dev/null; i=0; while { [ \"\$(sysctl -n dev.vtrtc.0.alarm_count)\" -le \"\$before\" ] || [ \"\$(sysctl -n dev.vtrtc.0.alarm_observed_time_ns)\" -lt \"\$deadline\" ]; } && [ \"\$i\" -lt 15 ]; do sleep 1; i=\$((i + 1)); done; after=\$(sysctl -n dev.vtrtc.0.alarm_count); observed=\$(sysctl -n dev.vtrtc.0.alarm_observed_time_ns); sysctl dev.vtrtc.0.alarm_time_ns=0 >/dev/null; test \"\$after\" -gt \"\$before\"; test \"\$observed\" -ge \"\$deadline\"" \
		    25
		rtc_notifies=$(grep -Ec \
		    '^vtrtc: modern notify q=0([[:space:]]|$)' "$bhyve_log" ||
		    true)
		[ "$rtc_notifies" -ge 5 ] || {
			echo "FAIL  host_rtc_requests count=$rtc_notifies expected>=5" >&2
			exit 1
		}
		echo "PASS  host_rtc_requests config,capability,read,alarm count=$rtc_notifies"
		grep -Eq \
		    '^vtrtc: modern queue enable q=1 .*enabled=1' \
		    "$bhyve_log" || {
			echo "FAIL  host_rtc_alarm_queue" >&2
			exit 1
		}
		grep -Eq '^vtrtc: modern notify q=1([[:space:]]|$)' \
		    "$bhyve_log" || {
			echo "FAIL  host_rtc_alarm_buffer" >&2
			exit 1
		}
		echo "PASS  host_rtc_alarm_queue"
		if [ "$FIVEBSD_RTC_PACKED" = yes ]; then
			guest_check rtc_packed_negotiated \
			    "parent=\$(sysctl -n dev.vtrtc.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q RingPacked"
			grep -Eq \
			    '^vtrtc: modern queue enable q=0 .*enabled=1 .*layout=packed' \
			    "$bhyve_log" || {
				echo "FAIL  host_rtc_packed_layout" >&2
				exit 1
			}
			grep -Eq \
			    '^vtrtc: modern queue enable q=1 .*enabled=1 .*layout=packed' \
			    "$bhyve_log" || {
				echo "FAIL  host_rtc_packed_alarm_layout" >&2
				exit 1
			}
			echo "PASS  host_rtc_packed_request_and_alarm"
		fi
	fi
	if [ "$FIVEBSD_INPUT_TEST" = yes ]; then
		guest_check input_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x1052([[:space:]]|$)'"
		guest_check input_driver \
		    "kldload virtio_input 2>/dev/null || kldstat -q -m virtio_input; devinfo -rv | grep -q 'vtinput0'"
		guest_check input_in_order_negotiated \
		    "set -eu; i=0; while [ \"\$i\" -lt '$FIVEBSD_INPUT_DEVICES' ]; do parent=\$(sysctl -n dev.vtinput.\$i.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q InOrder; i=\$((i + 1)); done"
		guest_check input_helper_selftest \
		    "/tmp/freebsd-input-check --self-test | grep -q '^SELFTEST PASS\$'"
		guest_check input_ready \
		    "rm -f /tmp/freebsd-input-check.out /tmp/freebsd-input-check.pid; nohup /tmp/freebsd-input-check '$input_name' >/tmp/freebsd-input-check.out 2>&1 & echo \$! >/tmp/freebsd-input-check.pid; i=0; while ! grep -q '^READY\$' /tmp/freebsd-input-check.out 2>/dev/null && [ \"\$i\" -lt 20 ]; do sleep 1; i=\$((i + 1)); done; grep -q '^READY\$' /tmp/freebsd-input-check.out" \
		    30
		printf 'tap\n' >"$input_fifo"
		guest_check input_event_and_status \
		    "i=0; while ! grep -q '^PASS\$' /tmp/freebsd-input-check.out 2>/dev/null && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; cat /tmp/freebsd-input-check.out; grep -q '^PASS\$' /tmp/freebsd-input-check.out" \
		    40
		i=0
		while ! grep -q '^PASS tap=' "$input_log" 2>/dev/null &&
		    kill -0 "$input_pid" 2>/dev/null && [ "$i" -lt 20 ]; do
			sleep 1
			i=$((i + 1))
		done
		grep -q '^PASS tap=' "$input_log" || {
			echo "FAIL  host_input_status" >&2
			cat "$input_log" >&2
			exit 1
		}
		echo "PASS  host_input_event_and_status"
		if [ "$FIVEBSD_INPUT_DEVICES" -eq 2 ]; then
			guest_check input_second_driver \
			    "devinfo -rv | grep -q 'vtinput1'"
			guest_check input_second_ready \
			    "rm -f /tmp/freebsd-input-check2.out /tmp/freebsd-input-check2.pid; nohup /tmp/freebsd-input-check '$input2_name' >/tmp/freebsd-input-check2.out 2>&1 & echo \$! >/tmp/freebsd-input-check2.pid; i=0; while ! grep -q '^READY\$' /tmp/freebsd-input-check2.out 2>/dev/null && [ \"\$i\" -lt 20 ]; do sleep 1; i=\$((i + 1)); done; grep -q '^READY\$' /tmp/freebsd-input-check2.out" \
			    30
			printf 'tap\n' >"$input2_fifo"
			guest_check input_second_event_and_status \
			    "i=0; while ! grep -q '^PASS\$' /tmp/freebsd-input-check2.out 2>/dev/null && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; cat /tmp/freebsd-input-check2.out; grep -q '^PASS\$' /tmp/freebsd-input-check2.out" \
			    40
			i=0
			while ! grep -q '^PASS tap=' "$input2_log" 2>/dev/null &&
			    kill -0 "$input2_pid" 2>/dev/null &&
			    [ "$i" -lt 20 ]; do
				sleep 1
				i=$((i + 1))
			done
			grep -q '^PASS tap=' "$input2_log" || {
				echo "FAIL  host_input_second_status" >&2
				cat "$input2_log" >&2
				exit 1
			}
			echo "PASS  host_input_second_event_and_status"
		fi
		if [ "$FIVEBSD_INPUT_PACKED" = yes ]; then
			guest_check input_packed_negotiated \
			    "set -eu; i=0; while [ \"\$i\" -lt '$FIVEBSD_INPUT_DEVICES' ]; do parent=\$(sysctl -n dev.vtinput.\$i.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q RingPacked; i=\$((i + 1)); done"
			[ "$(grep -Ec \
			    '^vtinput: modern queue enable q=0 .*enabled=1 .*layout=packed' \
			    "$bhyve_log" || true)" -ge "$FIVEBSD_INPUT_DEVICES" ] || {
				echo "FAIL  host_input_packed_event_layout" >&2
				exit 1
			}
			[ "$(grep -Ec \
			    '^vtinput: modern queue enable q=1 .*enabled=1 .*layout=packed' \
			    "$bhyve_log" || true)" -ge "$FIVEBSD_INPUT_DEVICES" ] || {
				echo "FAIL  host_input_packed_status_layout" >&2
				exit 1
			}
			[ "$(grep -Ec '^vtinput: modern notify q=1([[:space:]]|$)' \
			    "$bhyve_log" || true)" -ge "$FIVEBSD_INPUT_DEVICES" ] || {
				echo "FAIL  host_input_packed_status" >&2
				exit 1
			}
			echo "PASS  host_input_packed_event_and_status"
		fi
	fi
	if [ "$FIVEBSD_NINEP_TEST" = yes ]; then
		ninep_guest_token="guest-9p-$transport-$$"
		ninep_host_token="host-9p-$transport-$$"
		copy_guest_file "$here/run-freebsd-p9-rebind.sh" \
		    /tmp/run-freebsd-p9-rebind.sh
		guest_check ninep_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x1049([[:space:]]|$)'"
		guest_check ninep_driver \
		    "kldload p9fs 2>/dev/null || kldstat -q -m p9fs; kldload virtio_p9fs 2>/dev/null || kldstat -q -m virtio_p9fs; devinfo -rv | grep -q 'virtio_p9fs0'"
		guest_check ninep_bidirectional \
		    "set -eu; mkdir -p /mnt/bhyve-9p; mount -t p9fs '$ninep_tag' /mnt/bhyve-9p; trap 'umount /mnt/bhyve-9p' EXIT; test \"\$(cat /mnt/bhyve-9p/host-seed)\" = '$ninep_seed'; test \"\$(readlink /mnt/bhyve-9p/escape)\" = '..'; if cat '/mnt/bhyve-9p/escape/$ninep_outside_name' >/tmp/9p-escape-read 2>/dev/null; then echo '9P export escape read unexpectedly succeeded' >&2; exit 1; fi; if printf compromised >'/mnt/bhyve-9p/escape/$ninep_outside_name' 2>/tmp/9p-escape-write; then echo '9P export escape write unexpectedly succeeded' >&2; exit 1; fi; if printf created >'/mnt/bhyve-9p/escape/$ninep_escape_create_name' 2>/tmp/9p-escape-create; then echo '9P export escape create unexpectedly succeeded' >&2; exit 1; fi; printf %s '$ninep_guest_token' >/mnt/bhyve-9p/guest-to-host; sync" \
		    45
		[ "$(cat "$ninep_share/guest-to-host")" =
		    "$ninep_guest_token" ] || {
			echo "FAIL  host_ninep_guest_write" >&2
			exit 1
		}
		[ "$(cat "$ninep_outside")" = "must-not-cross-9p-export" ] &&
		    [ ! -e "$ninep_escape_create" ] || {
			echo "FAIL  host_ninep_export_confinement" >&2
			exit 1
		}
		echo "PASS  host_ninep_export_confinement"
		printf %s "$ninep_host_token" >"$ninep_share/host-to-guest"
		guest_check ninep_host_write \
		    "set -eu; mount -t p9fs '$ninep_tag' /mnt/bhyve-9p; trap 'umount /mnt/bhyve-9p' EXIT; test \"\$(cat /mnt/bhyve-9p/host-to-guest)\" = '$ninep_host_token'" \
		    45
		echo "PASS  host_ninep_bidirectional"
		guest_check ninep_mount_ownership_and_rebind \
		    "ITERATIONS=2 sh /tmp/run-freebsd-p9-rebind.sh '$ninep_tag' '$ninep_seed'" \
		    90
		if [ "$FIVEBSD_NINEP_PACKED" = yes ]; then
			guest_check ninep_packed_negotiated \
			    "parent=\$(sysctl -n dev.virtio_p9fs.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q RingPacked"
			grep -Eq \
			    '^vt9p: modern queue enable q=0 .*enabled=1 .*layout=packed' \
			    "$bhyve_log" || {
				echo "FAIL  host_ninep_packed_layout" >&2
				exit 1
			}
			grep -Eq '^vt9p: modern notify q=0([[:space:]]|$)' \
			    "$bhyve_log" || {
				echo "FAIL  host_ninep_packed_notify" >&2
				exit 1
			}
			echo "PASS  host_ninep_packed_requests"
		fi
	fi
	if [ "$FIVEBSD_SOUND_TEST" = yes ]; then
		# virtio-snd device id 25 -> modern PCI device 0x1059.  The guest
		# driver attaches as a pcm(4) child; a bounded /dev/dsp playback
		# drives control-queue negotiation and PCM (TX) traffic.
		guest_check snd_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x1059([[:space:]]|$)'"
		guest_check snd_driver_and_playback \
		    "kldload virtio_snd 2>/dev/null || kldstat -q -m virtio_snd; cat /dev/sndstat 2>/dev/null | grep -qi 'virtio'; timeout 15 dd if=/dev/zero of=/dev/dsp bs=4096 count=16 2>/dev/null" \
		    30
		grep -Eq '^vtsnd: modern queue enable q=[0-9]+ .*enabled=1' \
		    "$bhyve_log" || {
			echo "FAIL  host_snd_queue_enable" >&2
			exit 1
		}
		grep -Eq '^vtsnd: modern notify q=[0-9]+' "$bhyve_log" || {
			echo "FAIL  host_snd_control_and_pcm_notify" >&2
			exit 1
		}
		echo "PASS  host_snd_control_and_playback"
		if [ "$FIVEBSD_SOUND_PACKED" = yes ]; then
			guest_check snd_packed_negotiated \
			    "parent=\$(sysctl -n dev.pcm.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q RingPacked"
			grep -Eq \
			    '^vtsnd: modern queue enable q=0 .*enabled=1 .*layout=packed' \
			    "$bhyve_log" || {
				echo "FAIL  host_snd_packed_layout" >&2
				exit 1
			}
			echo "PASS  host_snd_packed_control"
		fi
	fi
	if [ "$FIVEBSD_MEM_TEST" = yes ]; then
		# virtio-mem device id 24 -> modern PCI device 0x1058.  The guest
		# driver reconciles toward the device requested_size by issuing PLUG
		# requests on the request queue; it deliberately stops at the plug
		# protocol (no runtime memory onlining on this kernel).
		guest_check mem_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x1058([[:space:]]|$)'"
		guest_check mem_driver \
		    "kldload virtio_mem 2>/dev/null || kldstat -q -m virtio_mem; devinfo -rv | grep -q 'vtmem0'"
		grep -Eq '^vtmem: modern queue enable q=0 .*enabled=1' \
		    "$bhyve_log" || {
			echo "FAIL  host_mem_queue_enable" >&2
			exit 1
		}
		grep -Eq '^vtmem: modern notify q=0' "$bhyve_log" || {
			echo "FAIL  host_mem_plug_request" >&2
			exit 1
		}
		echo "PASS  host_mem_plug_protocol"
	fi
	if [ "$FIVEBSD_PMEM_TEST" = yes ]; then
		# virtio-pmem device id 27 -> modern PCI device 0x105b.  The guest
		# driver negotiates the shared-memory region and publishes an nvdimm
		# SPA over its request queue.
		guest_check pmem_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x105b([[:space:]]|$)'"
		guest_check pmem_driver \
		    "kldload virtio_pmem 2>/dev/null || kldstat -q -m virtio_pmem; devinfo -rv | grep -q 'vtpmem0'"
		grep -Eq '^vtpmem: modern queue enable q=[0-9]+ .*enabled=1' \
		    "$bhyve_log" || {
			echo "FAIL  host_pmem_queue_enable" >&2
			exit 1
		}
		echo "PASS  host_pmem_shared_memory_region"
	fi
	if [ "$FIVEBSD_IOMMU_TEST" = yes ]; then
		# virtio-iommu device id 23 -> modern PCI device 0x1057.  The guest
		# driver parses config and publishes its request/event queues; the
		# ATTACH/MAP translation cycle needs a downstream endpoint fabric and
		# stays a documented boundary here.
		guest_check iommu_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x1057([[:space:]]|$)'"
		guest_check iommu_driver \
		    "kldload virtio_iommu 2>/dev/null || kldstat -q -m virtio_iommu; devinfo -rv | grep -q 'vtiommu0'"
		grep -Eq '^vtiommu: modern queue enable q=[0-9]+ .*enabled=1' \
		    "$bhyve_log" || {
			echo "FAIL  host_iommu_queue_enable" >&2
			exit 1
		}
		echo "PASS  host_iommu_config_and_queue_publication"
	fi
	if [ "$FIVEBSD_CRYPTO_TEST" = yes ]; then
		# virtio-crypto device id 20 -> modern PCI device 0x1054.  The 5BSD
		# guest driver (sys/dev/virtio/crypto) attaches as vtcrypto0 and
		# registers a CRYPTOCAP_F_HARDWARE provider with opencrypto(9); the
		# vtcryptocbc helper resolves that provider by crid through
		# /dev/crypto and drives an AES-CBC round-trip through the device.
		guest_check crypto_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x1054([[:space:]]|$)'"
		guest_check crypto_driver \
		    "kldload virtio_crypto 2>/dev/null || kldstat -q -m virtio_crypto; devinfo -rv | grep -q 'vtcrypto0'"
		# Queue enable is published when the driver brings its data and
		# control virtqueues up at attach.
		grep -Eq '^vtcrypto: modern queue enable q=0 .*enabled=1' \
		    "$bhyve_log" || {
			echo "FAIL  host_crypto_queue_enable" >&2
			exit 1
		}
		echo "PASS  host_crypto_queue_publication"
		# opencrypto registration: CIOCFINDDEV must resolve the vtcrypto
		# provider to a crid.  cryptodev(4) exposes /dev/crypto.
		guest_check crypto_opencrypto_registration \
		    "kldload cryptodev 2>/dev/null || kldstat -q -m cryptodev; /tmp/vtcryptocbc find | grep -q 'registered=yes'" \
		    30
		# Functional AES-CBC round-trip pinned to the vtcrypto crid.  This
		# submits a session request on the control queue and cipher work on
		# a data queue, which is what drives the host-visible notifies below.
		guest_check crypto_cbc_roundtrip \
		    "/tmp/vtcryptocbc | grep -q 'roundtrip=ok'" \
		    30
		grep -Eq '^vtcrypto: modern notify q=[0-9]+' "$bhyve_log" || {
			echo "FAIL  host_crypto_data_or_control_notify" >&2
			exit 1
		}
		echo "PASS  host_crypto_request_notify"
	fi
	audit_5bsd_virtio_features
	guest_check vsock_driver \
	    "devinfo -rv | grep -q 'virtio_vsock0'"
	guest_check block_driver \
	    "devinfo -rv | grep -q 'vtblk0'"
	guest_check block_root_io \
	    "rootdev=\$(mount -p | awk '\$2 == \"/\" { print \$1; exit }'); test \"\${rootdev#/dev/vtbd0}\" != \"\$rootdev\"; marker=/tmp/virtio-block-root-\$\$; dd if=/dev/zero of=\"\$marker\" bs=4096 count=8 conv=fsync 2>/dev/null; test \"\$(stat -f %z \"\$marker\")\" = 32768; rm -f \"\$marker\""
	if [ "$FIVEBSD_NOTIFICATION_DATA" = yes ]; then
		guest_check notification_features_negotiated \
		    "features=\$(sysctl -a 2>/dev/null | awk -F': ' '/\\.negotiated_features:/{print \$2}'); printf '%s\\n' \"\$features\" | grep -q 'NotificationData'; printf '%s\\n' \"\$features\" | grep -q 'NotifConfigData'"
		grep -Eq \
		    '^vtblk: modern notify q=[0-9]+ next_avail=[1-9][0-9]* ' \
		    "$bhyve_log" || {
			echo "FAIL  host_notification_data" >&2
			exit 1
		}
		echo "PASS  host_notification_data device=vtblk payload=queue+available-index"
	fi
	if [ "$FIVEBSD_BLOCK_QUEUES" -gt 1 ]; then
		guest_check "block_mq_active_${FIVEBSD_BLOCK_QUEUES}" \
		    "test \"\$(sysctl -n dev.vtblk.0.num_queues)\" = '$FIVEBSD_BLOCK_QUEUES'"
		guest_check block_mq_root_io \
		    "set -eu; pids=; cpu=0; while [ \"\$cpu\" -lt '$FIVEBSD_BLOCK_QUEUES' ]; do cpuset -l \"\$cpu\" dd if=/dev/zero of=\"/tmp/virtio-block-mq-\$cpu\" bs=64k count=32 conv=fsync >/dev/null 2>&1 & pids=\"\$pids \$!\"; cpu=\$((cpu + 1)); done; for pid in \$pids; do wait \"\$pid\"; done; sync; cpu=0; while [ \"\$cpu\" -lt '$FIVEBSD_BLOCK_QUEUES' ]; do test \"\$(stat -f %z \"/tmp/virtio-block-mq-\$cpu\")\" = 2097152; rm -f \"/tmp/virtio-block-mq-\$cpu\"; cpu=\$((cpu + 1)); done" 45
		queue=0
		while [ "$queue" -lt "$FIVEBSD_BLOCK_QUEUES" ]; do
			grep -Eq "vtblk: modern notify q=$queue([[:space:]]|$)" \
			    "$bhyve_log" || {
				echo "FAIL  host_block_mq_data queue=$queue" >&2
				exit 1
			}
			grep -Eq "virtio-block: q=$queue completed status=0" \
			    "$bhyve_log" || {
				echo "FAIL  host_block_mq_completion queue=$queue" >&2
				exit 1
			}
			queue=$((queue + 1))
		done
		echo "PASS  host_block_mq_data queues=$FIVEBSD_BLOCK_QUEUES"
	fi
	if [ "$FIVEBSD_BLOCK_DISCARD" = yes ]; then
		guest_check block_discard_data \
		    "set -eu; dev=; i=0; while [ -z \"\$dev\" ] && [ \"\$i\" -lt 30 ]; do for candidate in /dev/vtbd[1-9]*; do [ -c \"\$candidate\" ] || continue; [ \"\$(diskinfo \"\$candidate\" | awk '{print \$3}')\" = 67108864 ] || continue; dev=\$candidate; break; done; [ -n \"\$dev\" ] || { sleep 1; i=\$((i + 1)); }; done; [ -n \"\$dev\" ]; unit=\${dev#/dev/vtbd}; parent=\$(sysctl -n \"dev.vtblk.\$unit.%parent\"); punit=\${parent##*[!0-9]}; pname=\${parent%\$punit}; test -n \"\$punit\"; sysctl -n \"dev.\$pname.\$punit.negotiated_features\" | grep -q 'Discard'; dd if=/dev/random of=/tmp/discard-payload bs=1m count=4 >/dev/null 2>&1; dd if=/dev/zero of=/tmp/discard-zero bs=1m count=4 >/dev/null 2>&1; dd if=/dev/random of=/tmp/discard-left bs=512 count=1 >/dev/null 2>&1; dd if=/dev/random of=/tmp/discard-right bs=512 count=1 >/dev/null 2>&1; dd if=/tmp/discard-left of=\"\$dev\" bs=512 count=1 oseek=1024 conv=sync >/dev/null 2>&1; dd if=/tmp/discard-payload of=\"\$dev\" bs=1m count=4 oseek=1 conv=sync >/dev/null 2>&1; dd if=/tmp/discard-right of=\"\$dev\" bs=512 count=1 oseek=10240 conv=sync >/dev/null 2>&1; dd if=\"\$dev\" of=/tmp/discard-before bs=1m count=4 iseek=1 >/dev/null 2>&1; cmp /tmp/discard-payload /tmp/discard-before; trim -fq -o 1m -l 4m \"\$dev\"; dd if=\"\$dev\" of=/tmp/discard-after bs=1m count=4 iseek=1 >/dev/null 2>&1; cmp /tmp/discard-after /tmp/discard-zero; dd if=\"\$dev\" of=/tmp/discard-left-after bs=512 count=1 iseek=1024 >/dev/null 2>&1; dd if=\"\$dev\" of=/tmp/discard-right-after bs=512 count=1 iseek=10240 >/dev/null 2>&1; cmp /tmp/discard-left /tmp/discard-left-after; cmp /tmp/discard-right /tmp/discard-right-after" \
		    60
		grep -Eq '^virtio-block: q=[0-9]+ type=11 ' "$bhyve_log" || {
			echo "FAIL  host_block_discard_request" >&2
			exit 1
		}
		echo "PASS  host_block_discard_request type=11"
	fi
	if [ "$FIVEBSD_BLOCK_WRITE_ZEROES" = yes ]; then
		guest_check block_write_zeroes_data \
		    "set -eu; dev=; i=0; while [ -z \"\$dev\" ] && [ \"\$i\" -lt 30 ]; do for candidate in /dev/vtbd[1-9]*; do [ -c \"\$candidate\" ] || continue; [ \"\$(diskinfo \"\$candidate\" | awk '{print \$3}')\" = 67108864 ] || continue; dev=\$candidate; break; done; [ -n \"\$dev\" ] || { sleep 1; i=\$((i + 1)); }; done; [ -n \"\$dev\" ]; unit=\${dev#/dev/vtbd}; parent=\$(sysctl -n \"dev.vtblk.\$unit.%parent\"); punit=\${parent##*[!0-9]}; pname=\${parent%\$punit}; test -n \"\$punit\"; sysctl -n \"dev.\$pname.\$punit.negotiated_features\" | grep -q 'WriteZeros'; policy=\"dev.vtblk.\$unit.write_zeroes_delete\"; test \"\$(sysctl -n \"\$policy\")\" = 0; trap 'sysctl \"\$policy\"=0 >/dev/null' EXIT HUP INT TERM; sysctl \"\$policy\"=1 >/dev/null; test \"\$(sysctl -n \"\$policy\")\" = 1; dd if=/dev/random of=/tmp/write-zeroes-payload bs=1m count=4 >/dev/null 2>&1; dd if=/dev/zero of=/tmp/write-zeroes-zero bs=1m count=4 >/dev/null 2>&1; dd if=/dev/random of=/tmp/write-zeroes-left bs=512 count=1 >/dev/null 2>&1; dd if=/dev/random of=/tmp/write-zeroes-right bs=512 count=1 >/dev/null 2>&1; dd if=/tmp/write-zeroes-left of=\"\$dev\" bs=512 count=1 oseek=1024 conv=sync >/dev/null 2>&1; dd if=/tmp/write-zeroes-payload of=\"\$dev\" bs=1m count=4 oseek=1 conv=sync >/dev/null 2>&1; dd if=/tmp/write-zeroes-right of=\"\$dev\" bs=512 count=1 oseek=10240 conv=sync >/dev/null 2>&1; dd if=\"\$dev\" of=/tmp/write-zeroes-before bs=1m count=4 iseek=1 >/dev/null 2>&1; cmp /tmp/write-zeroes-payload /tmp/write-zeroes-before; trim -fq -o 1m -l 4m \"\$dev\"; dd if=\"\$dev\" of=/tmp/write-zeroes-after bs=1m count=4 iseek=1 >/dev/null 2>&1; cmp /tmp/write-zeroes-after /tmp/write-zeroes-zero; dd if=\"\$dev\" of=/tmp/write-zeroes-left-after bs=512 count=1 iseek=1024 >/dev/null 2>&1; dd if=\"\$dev\" of=/tmp/write-zeroes-right-after bs=512 count=1 iseek=10240 >/dev/null 2>&1; cmp /tmp/write-zeroes-left /tmp/write-zeroes-left-after; cmp /tmp/write-zeroes-right /tmp/write-zeroes-right-after; sysctl \"\$policy\"=0 >/dev/null; trap - EXIT HUP INT TERM" \
		    60
		grep -Eq '^virtio-block: q=[0-9]+ type=13 ' "$bhyve_log" || {
			echo "FAIL  host_block_write_zeroes_request" >&2
			exit 1
		}
		echo "PASS  host_block_write_zeroes_request type=13"
	fi
	if [ "$FIVEBSD_BLOCK_READONLY" = yes ]; then
		guest_check block_readonly_data \
		    "set -eu; dev=; i=0; while [ -z \"\$dev\" ] && [ \"\$i\" -lt 30 ]; do for candidate in /dev/vtbd[1-9]*; do [ -c \"\$candidate\" ] || continue; [ \"\$(diskinfo \"\$candidate\" | awk '{print \$3}')\" = 8388608 ] || continue; dev=\$candidate; break; done; [ -n \"\$dev\" ] || { sleep 1; i=\$((i + 1)); }; done; [ -n \"\$dev\" ]; unit=\${dev#/dev/vtbd}; parent=\$(sysctl -n \"dev.vtblk.\$unit.%parent\"); punit=\${parent##*[!0-9]}; pname=\${parent%\$punit}; test -n \"\$punit\"; sysctl -n \"dev.\$pname.\$punit.negotiated_features\" | grep -q 'ReadOnly'; test \"\$(sha256 -q \"\$dev\")\" = '$readonly_digest'; if dd if=/dev/zero of=\"\$dev\" bs=512 count=1 conv=notrunc >/tmp/readonly-write.out 2>&1; then echo 'read-only write unexpectedly succeeded' >&2; exit 1; fi; test \"\$(sha256 -q \"\$dev\")\" = '$readonly_digest'" \
		    60
		echo "PASS  host_block_readonly bytes=8388608"
	fi
	if [ "$FIVEBSD_BLOCK_WCE" = yes ]; then
		guest_check block_wce_transition \
		    "set -eu; parent=\$(sysctl -n dev.vtblk.0.%parent); punit=\${parent##*[!0-9]}; pname=\${parent%\$punit}; test -n \"\$punit\"; sysctl -n \"dev.\$pname.\$punit.negotiated_features\" | grep -q 'ConfigWCE'; original=\$(sysctl -n dev.vtblk.0.writecache_mode); trap 'sysctl dev.vtblk.0.writecache_mode=\"\$original\" >/dev/null' EXIT HUP INT TERM; sysctl dev.vtblk.0.writecache_mode=0 >/dev/null; test \"\$(sysctl -n dev.vtblk.0.writecache_mode)\" = 0; dd if=/dev/zero of=/tmp/virtio-wce-writethrough bs=64k count=8 conv=fsync >/dev/null 2>&1; sysctl dev.vtblk.0.writecache_mode=1 >/dev/null; test \"\$(sysctl -n dev.vtblk.0.writecache_mode)\" = 1; dd if=/dev/zero of=/tmp/virtio-wce-writeback bs=64k count=8 conv=fsync >/dev/null 2>&1; sysctl dev.vtblk.0.writecache_mode=\"\$original\" >/dev/null; trap - EXIT HUP INT TERM; rm -f /tmp/virtio-wce-writethrough /tmp/virtio-wce-writeback" \
		    60
		grep -q '^vtblk: cache mode changed to writethrough$' \
		    "$bhyve_log" || {
			echo "FAIL  host_block_wce_writethrough" >&2
			exit 1
		}
		grep -q '^vtblk: cache mode changed to writeback$' \
		    "$bhyve_log" || {
			echo "FAIL  host_block_wce_writeback" >&2
			exit 1
		}
		echo "PASS  host_block_wce_transition modes=0,1"
	fi
	if [ "$FIVEBSD_SCSI_QUEUES" -gt 0 ]; then
		guest_check scsi_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x${scsi_id}([[:space:]]|$)'"
		guest_check scsi_driver \
		    "devinfo -rv | grep -q 'vtscsi0'"
		guest_check "scsi_mq_active_${FIVEBSD_SCSI_QUEUES}" \
		    "test \"\$(sysctl -n dev.vtscsi.0.num_queues)\" = '$FIVEBSD_SCSI_QUEUES'"
		guest_check scsi_mq_data_io \
		    "set -eu; i=0; while [ \"\$i\" -lt 30 ]; do disk=\$(camcontrol devlist | sed -n 's/.*\\(da[0-9][0-9]*\\).*/\\1/p' | head -n 1); [ -n \"\$disk\" ] && break; sleep 1; i=\$((i + 1)); done; test -n \"\${disk:-}\"; dev=/dev/\$disk; pids=; q=0; while [ \"\$q\" -lt '$FIVEBSD_SCSI_QUEUES' ]; do dd if=/dev/random of=\"/tmp/scsi-src-\$q\" bs=64k count=16 >/dev/null 2>&1; cpuset -l \"\$q\" dd if=\"/tmp/scsi-src-\$q\" of=\"\$dev\" bs=64k count=16 oseek=\$((q * 32)) conv=fsync >/dev/null 2>&1 & pids=\"\$pids \$!\"; q=\$((q + 1)); done; for pid in \$pids; do wait \"\$pid\"; done; q=0; while [ \"\$q\" -lt '$FIVEBSD_SCSI_QUEUES' ]; do dd if=\"\$dev\" of=\"/tmp/scsi-dst-\$q\" bs=64k count=16 iseek=\$((q * 32)) >/dev/null 2>&1; cmp \"/tmp/scsi-src-\$q\" \"/tmp/scsi-dst-\$q\"; rm -f \"/tmp/scsi-src-\$q\" \"/tmp/scsi-dst-\$q\"; q=\$((q + 1)); done" 60
		grep -Eq '^virtio-scsi: submit opcode=0xa0 ' "$bhyve_log" || {
			echo "FAIL  host_scsi_report_luns" >&2
			exit 1
		}
		grep -Eq "^virtio-scsi: \\(0:0:${scsi_lun_id}/0\\): (READ|WRITE)\\(10\\)" \
		    "$bhyve_log" || {
			echo "FAIL  host_scsi_lun_identity lun=$scsi_lun_id" >&2
			exit 1
		}
		echo "PASS  host_scsi_report_luns lun=$scsi_lun_id"
		queue=0
		while [ "$queue" -lt "$FIVEBSD_SCSI_QUEUES" ]; do
			host_queue=$((queue + 2))
			grep -Eq "vtscsi: modern notify q=$host_queue([[:space:]]|$)" \
			    "$bhyve_log" || {
				echo "FAIL  host_scsi_mq_data queue=$queue" >&2
				exit 1
			}
			grep -Eq "virtio-scsi: q=$host_queue request .* completed, response 0" \
			    "$bhyve_log" || {
				echo "FAIL  host_scsi_mq_completion queue=$queue" >&2
				exit 1
			}
			queue=$((queue + 1))
		done
		echo "PASS  host_scsi_mq_data queues=$FIVEBSD_SCSI_QUEUES"
		if [ "$FIVEBSD_SCSI_EVENTS" = yes ]; then
			scsi_event_size=$((scsi_size_bytes + 32 * 1024 * 1024))
			scsi_event_changed_size=$((scsi_event_size + 16 * 1024 * 1024))
			scsi_event_create_log="$WORKDIR/$transport.scsi-event-create.log"
			guest_check scsi_events_negotiated \
			    "set -eu; parent=\$(sysctl -n dev.vtscsi.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; features=\$(sysctl -n \"dev.\$name.\$unit.negotiated_features\"); printf '%s\\n' \"\$features\" | grep -q Hotplug; printf '%s\\n' \"\$features\" | grep -q ChangeEvent"
			# No camcontrol rescan is permitted below.  The event queue is
			# the only mechanism which may reveal these transitions.
			ctladm create -b ramdisk -s "$scsi_event_size" \
			    -o "capacity=$scsi_event_size" >"$scsi_event_create_log"
			scsi_event_lun_id=$(awk '/^LUN ID:/ {print $NF}' \
			    "$scsi_event_create_log")
			case "$scsi_event_lun_id" in
			''|*[!0-9]*)
				echo "invalid CTL event-test LUN ID: $scsi_event_lun_id" >&2
				exit 1
				;;
			esac
			[ "$scsi_event_lun_id" -le 16383 ] || {
				echo "CTL event-test LUN ID exceeds virtio-scsi limit" >&2
				exit 1
			}
			guest_check scsi_event_add \
			    "set -eu; i=0; dev=; while [ \"\$i\" -lt 45 ]; do for candidate in /dev/da[0-9]*; do [ -c \"\$candidate\" ] || continue; [ \"\$(diskinfo \"\$candidate\" | awk '{print \$3}')\" = '$scsi_event_size' ] || continue; dev=\$candidate; break; done; [ -n \"\$dev\" ] && break; sleep 1; i=\$((i + 1)); done; test -n \"\$dev\"; printf '%s\\n' \"\$dev\" >/tmp/virtio-scsi-event-dev" \
			    55
			ctladm modify -b ramdisk -l "$scsi_event_lun_id" \
			    -s "$scsi_event_changed_size" >/dev/null
			guest_check scsi_event_change \
			    "set -eu; dev=\$(cat /tmp/virtio-scsi-event-dev); i=0; while [ \"\$i\" -lt 45 ] && [ \"\$(diskinfo \"\$dev\" | awk '{print \$3}')\" != '$scsi_event_changed_size' ]; do sleep 1; i=\$((i + 1)); done; test \"\$(diskinfo \"\$dev\" | awk '{print \$3}')\" = '$scsi_event_changed_size'" \
			    55
			ctladm remove -b ramdisk -l "$scsi_event_lun_id" >/dev/null
			scsi_event_lun_id=
			guest_check scsi_event_remove \
			    "set -eu; dev=\$(cat /tmp/virtio-scsi-event-dev); i=0; while [ \"\$i\" -lt 45 ] && [ -c \"\$dev\" ]; do sleep 1; i=\$((i + 1)); done; test ! -c \"\$dev\"; rm -f /tmp/virtio-scsi-event-dev" \
			    55
			echo "PASS  host_scsi_events add,change,remove"
		fi
		if [ "$FIVEBSD_DEVICE_SUSPEND" = yes ]; then
			guest_check device_suspend_scsi \
			    "set -eu; parent=\$(sysctl -n dev.vtscsi.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q Suspend; devctl suspend \"\$parent\"; devctl resume \"\$parent\"; camcontrol devlist | grep -q 'da[0-9]'" \
			    30
			host_device_lifecycle_check vtscsi
		fi
		if [ "$FIVEBSD_SCSI_PACKED" = yes ]; then
			grep -Eq '^vtscsi: modern queue enable q=[2-9][0-9]* .*enabled=1 .*layout=packed' \
			    "$bhyve_log" || {
				echo "FAIL  host_scsi_packed_layout" >&2
				exit 1
			}
			grep -Eq '^vtscsi: modern notify q=[2-9][0-9]*([[:space:]]|$)' \
			    "$bhyve_log" || {
				echo "FAIL  host_scsi_packed_io" >&2
				exit 1
			}
			grep -Eq '^virtio-scsi: q=[2-9][0-9]* request .* completed, response 0' \
			    "$bhyve_log" || {
				echo "FAIL  host_scsi_packed_completion" >&2
				exit 1
			}
			echo "PASS  host_scsi_packed_layout_and_data"
		fi
	fi
	guest_check rng_driver \
	    "devinfo -rv | grep -q 'vtrnd0'"
	guest_check rng_read \
	    "timeout 10 dd if=/dev/random of=/dev/null bs=32 count=1 2>/dev/null" 15
	if [ "$FIVEBSD_DEVICE_SUSPEND" = yes ]; then
		guest_check device_suspend_rng \
		    "set -eu; parent=\$(sysctl -n dev.vtrnd.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q Suspend; devctl suspend \"\$parent\"; devctl resume \"\$parent\"; timeout 10 dd if=/dev/random of=/dev/null bs=32 count=1 2>/dev/null" \
		    30
		guest_check device_suspend_block \
		    "set -eu; parent=\$(sysctl -n dev.vtblk.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q Suspend; devctl suspend \"\$parent\"; devctl resume \"\$parent\"; marker=/tmp/virtio-block-suspend-\$\$; dd if=/dev/zero of=\"\$marker\" bs=4096 count=8 conv=fsync 2>/dev/null; test \"\$(stat -f %z \"\$marker\")\" = 32768; rm -f \"\$marker\"" \
		    30
		guest_check device_suspend_vsock \
		    "set -eu; parent=\$(sysctl -n dev.virtio_vsock.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q Suspend; cid=\$(sysctl -n kern.vsock.guest_cid); devctl suspend \"\$parent\"; devctl resume \"\$parent\"; test \"\$(sysctl -n kern.vsock.guest_cid)\" = \"\$cid\"" \
		    30
		host_device_lifecycle_check vtrnd
		host_device_lifecycle_check vtblk
		host_device_lifecycle_check vtvsock
	fi
	if [ "$FIVEBSD_RNG_RESET_ITERATIONS" -gt 0 ]; then
		copy_guest_file "$here/run-freebsd-vtrnd-reset.sh" \
		    /tmp/run-freebsd-vtrnd-reset.sh
		reset_timeout=$((FIVEBSD_RNG_RESET_ITERATIONS * 5 + 60))
		[ "$reset_timeout" -le 600 ] || reset_timeout=600
		guest_check rng_selective_queue_reset \
		    "ITERATIONS='$FIVEBSD_RNG_RESET_ITERATIONS' sh /tmp/run-freebsd-vtrnd-reset.sh" \
		    "$reset_timeout"
	fi
	if [ "$FIVEBSD_CONSOLE_TEST" = yes ]; then
		guest_check console_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x1043([[:space:]]|$)'"
		guest_check console_driver \
		    "devinfo -rv | grep -Eq 'vtcon[0-9]+'"
		guest_check console_port_count \
		    "set -- /dev/vtcon/$console_name /dev/vtcon/$console_name2; test -c \"\$1\"; if [ '$FIVEBSD_CONSOLE_PORTS' -eq 2 ]; then test -c \"\$2\"; else test ! -e \"\$2\"; fi"
		guest_check console_in_order_negotiated \
		    "set -eu; parent=\$(sysctl -n dev.vtcon.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q InOrder"
		run_5bsd_console_exchange port0 "$console_name" \
		    "$console_socket" "$port_exchange_log"
		[ "$FIVEBSD_CONSOLE_PORTS" -eq 1 ] ||
		    run_5bsd_console_exchange port1 "$console_name2" \
		    "$console_socket2" "$port_exchange_log2"
		if [ "$FIVEBSD_DEVICE_SUSPEND" = yes ]; then
			guest_check device_suspend_console \
			    "set -eu; parent=\$(sysctl -n dev.vtcon.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q Suspend; devctl suspend \"\$parent\"; devctl resume \"\$parent\"; set -- /dev/vport*p*; test -c \"\$1\"" \
			    30
			host_device_lifecycle_check vtcon
		fi
		if [ "$FIVEBSD_CONSOLE_PACKED" = yes ]; then
			q=0
			last_q=$((FIVEBSD_CONSOLE_PORTS * 2 + 1))
			while [ "$q" -le "$last_q" ]; do
				grep -Eq "^vtcon: modern queue enable q=$q .*enabled=1 .*layout=packed" \
				    "$bhyve_log" || {
					echo "FAIL  host_console_packed_layout queue=$q" >&2
					exit 1
				}
				q=$((q + 1))
			done
			port_id=0
			while [ "$port_id" -lt "$FIVEBSD_CONSOLE_PORTS" ]; do
				if [ "$port_id" -eq 0 ]; then
					in_q=0
				else
					in_q=$((port_id * 2 + 2))
				fi
				out_q=$((in_q + 1))
				for q in "$in_q" "$out_q"; do
					grep -Eq "^vtcon: modern notify q=$q([[:space:]]|$)" \
					    "$bhyve_log" || {
						echo "FAIL  host_console_packed_io port=$port_id queue=$q" >&2
						exit 1
					}
				done
				port_id=$((port_id + 1))
			done
		fi
		echo "PASS  host_console_complete ports=$FIVEBSD_CONSOLE_PORTS packed=$FIVEBSD_CONSOLE_PACKED"
	fi
	if [ "$FIVEBSD_BLOCK_PACKED" = yes ]; then
		grep -Eq '^vtblk: modern queue enable q=[0-9]+ .*enabled=1 .*layout=packed' \
		    "$bhyve_log" || {
			echo "FAIL  host_block_packed_layout" >&2
			exit 1
		}
		grep -Eq '^vtblk: modern notify q=[0-9]+' "$bhyve_log" || {
			echo "FAIL  host_block_packed_io" >&2
			exit 1
		}
		echo "PASS  host_block_packed_layout_and_io"
	fi
	if [ "$FIVEBSD_RNG_PACKED" = yes ]; then
		grep -Eq '^vtrnd: modern queue enable q=[0-9]+ .*enabled=1 .*layout=packed' \
		    "$bhyve_log" || {
			echo "FAIL  host_rng_packed_layout" >&2
			exit 1
		}
		grep -Eq '^vtrnd: modern notify q=[0-9]+' "$bhyve_log" || {
			echo "FAIL  host_rng_packed_io" >&2
			exit 1
		}
		echo "PASS  host_rng_packed_layout_and_io"
	fi
	if [ "$FIVEBSD_NET_TEST" = yes ]; then
		guest_check net_driver \
		    "devinfo -rv | grep -q 'vtnet0'"
		guest_check "net_mq_active_${FIVEBSD_NET_QUEUES}" \
		    "test \"\$(sysctl -n dev.vtnet.0.max_vq_pairs)\" = '$FIVEBSD_NET_QUEUES'; test \"\$(sysctl -n dev.vtnet.0.act_vq_pairs)\" = '$FIVEBSD_NET_QUEUES'"
		if [ "$FIVEBSD_NET_QUEUES" -gt 1 ]; then
			guest_check net_rss_negotiated \
			    "parent=\$(sysctl -n dev.vtnet.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; features=\$(sysctl -n \"dev.\$name.\$unit.negotiated_features\"); printf '%s\\n' \"\$features\" | grep -q RSS; printf '%s\\n' \"\$features\" | grep -q HashReport"
			net_hash_command=1
		else
			guest_check net_hash_without_rss_negotiated \
			    "parent=\$(sysctl -n dev.vtnet.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; features=\$(sysctl -n \"dev.\$name.\$unit.negotiated_features\"); printf '%s\\n' \"\$features\" | grep -q HashReport; ! printf '%s\\n' \"\$features\" | grep -q RSS"
			net_hash_command=2
		fi
		guest_check net_data \
		    "ifconfig vtnet0 up; timeout 30 dhclient vtnet0; gateway=\$(route -n get default | awk '/gateway:/{print \$2; exit}'); test -n \"\$gateway\"; ping -c 3 \"\$gateway\"" 45
		guest_check net_mq_data \
		    "set -eu; gateway=\$(route -n get default | awk '/gateway:/{print \$2; exit}'); pids=; cpu=0; while [ \"\$cpu\" -lt '$FIVEBSD_NET_QUEUES' ]; do cpuset -l \"\$cpu\" ping -c 4 \"\$gateway\" >\"/tmp/net-mq-\$cpu.log\" 2>&1 & pids=\"\$pids \$!\"; cpu=\$((cpu + 1)); done; for pid in \$pids; do wait \"\$pid\"; done" 45
		guest_check net_hash_metadata \
		    "set -eu; total=0; invalid=0; q=0; while [ \"\$q\" -lt '$FIVEBSD_NET_QUEUES' ]; do total=\$((total + \$(sysctl -n dev.vtnet.0.rxq\$q.hash))); invalid=\$((invalid + \$(sysctl -n dev.vtnet.0.rxq\$q.hash_invalid))); q=\$((q + 1)); done; test \"\$total\" -gt 0; test \"\$invalid\" -eq 0"
		if [ "$FIVEBSD_DEVICE_SUSPEND" = yes ]; then
			guest_check device_suspend_net \
			    "set -eu; parent=\$(sysctl -n dev.vtnet.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q Suspend; gateway=\$(route -n get default | awk '/gateway:/{print \$2; exit}'); devctl suspend \"\$parent\"; devctl resume \"\$parent\"; ping -c 3 \"\$gateway\"" \
			    30
			host_device_lifecycle_check vtnet
		fi
		if [ "$VIRTIO_DEBUG" -ge 2 ] &&
		    grep -Eq "control chain .*valid=1 class=4 command=$net_hash_command" \
		    "$bhyve_log"; then
			echo "PASS  host_net_hash_control command=$net_hash_command"
		elif [ "$VIRTIO_DEBUG" -ge 2 ]; then
			echo "FAIL  host_net_hash_control command=$net_hash_command" >&2
			exit 1
		fi
		if [ "$VIRTIO_DEBUG" -ge 2 ]; then
			pair=0
			while [ "$pair" -lt "$FIVEBSD_NET_QUEUES" ]; do
				txq=$((pair * 2 + 1))
				grep -Eq "vtnet: modern notify q=$txq([[:space:]]|$)" \
				    "$bhyve_log" || {
					echo "FAIL  host_net_mq_data queue=$txq" >&2
					exit 1
				}
				pair=$((pair + 1))
			done
			echo "PASS  host_net_mq_data queues=$FIVEBSD_NET_QUEUES"
		fi
		if [ "$FIVEBSD_NET_PACKED" = yes ]; then
			grep -Eq '^vtnet: modern queue enable q=[0-9]+ .*enabled=1 .*layout=packed' \
			    "$bhyve_log" || {
				echo "FAIL  host_net_packed_layout" >&2
				exit 1
			}
			echo "PASS  host_net_packed_layout"
		fi
	fi
	if [ "$transport" = modern ]; then
		guest_check balloon_pci \
		    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x${balloon_id}([[:space:]]|$)'"
		guest_check balloon_driver \
		    "devinfo -rv | grep -q 'vtballoon0'"
		guest_check balloon_target \
		    "i=0; while [ \"\$(sysctl -n dev.vtballoon.0.current)\" != '$balloon_target_pages' ] && [ \"\$i\" -lt 60 ]; do sleep 1; i=\$((i + 1)); done; test \"\$(sysctl -n dev.vtballoon.0.desired)\" = '$balloon_target_pages'; test \"\$(sysctl -n dev.vtballoon.0.current)\" = '$balloon_target_pages'" 70
		if [ "$FIVEBSD_BALLOON_STATS_INTERVAL" -ne 0 ]; then
			guest_check balloon_statistics_negotiated \
			    "parent=\$(sysctl -n dev.vtballoon.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q StatsVq"
			i=0
			while { ! grep -Eq 'vtballoon: statistics sample entries=3 .*present=0x31' \
			    "$bhyve_log" ||
			    ! grep -Eq 'vtballoon: statistics refresh entries=3 present=0x31' \
			    "$bhyve_log"; } && [ "$i" -lt 15 ]; do
				sleep 1
				i=$((i + 1))
			done
			grep -Eq 'vtballoon: statistics sample entries=3 .*present=0x31' \
			    "$bhyve_log" &&
			    grep -Eq 'vtballoon: statistics refresh entries=3 present=0x31' \
			    "$bhyve_log" || {
				echo "FAIL  host_balloon_statistics_refresh" >&2
				exit 1
			}
			echo "PASS  host_balloon_statistics_refresh tags=SWAP_IN,MEMFREE,MEMTOT"
		fi
		if [ "$FIVEBSD_BALLOON_DEFLATE_ON_OOM" = yes ]; then
			guest_check balloon_deflate_on_oom_negotiated \
			    "parent=\$(sysctl -n dev.vtballoon.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q DeflateOnOOM"
			guest_check balloon_deflate_on_lowmem \
			    "set -eu; before=\$(sysctl -n dev.vtballoon.0.current); test \"\$before\" -gt 0; sysctl debug.vm_lowmem=2 >/dev/null; i=0; while [ \"\$(sysctl -n dev.vtballoon.0.current)\" -ge \"\$before\" ] && [ \"\$i\" -lt 100 ]; do sleep 0.05; i=\$((i + 1)); done; low=\$(sysctl -n dev.vtballoon.0.current); test \"\$low\" -lt \"\$before\"; desired=\$(sysctl -n dev.vtballoon.0.desired); i=0; while [ \"\$(sysctl -n dev.vtballoon.0.current)\" != \"\$desired\" ] && [ \"\$i\" -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done; test \"\$(sysctl -n dev.vtballoon.0.current)\" = \"\$desired\""
			grep -Eq 'vtballoon: deflate request seen=[1-9][0-9]* accepted=[1-9][0-9]* rejected=0 error=0' \
			    "$bhyve_log" || {
				echo "FAIL  host_balloon_lowmem_deflate" >&2
				exit 1
			}
			echo "PASS  host_balloon_lowmem_deflate"
		fi
		if [ "$FIVEBSD_BALLOON_PAGE_POISON" = yes ]; then
			guest_check balloon_page_poison_negotiated \
			    "parent=\$(sysctl -n dev.vtballoon.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q PagePoison"
			guest_check balloon_page_poison_deflate \
			    "set -eu; desired=\$(sysctl -n dev.vtballoon.0.desired); before_current=\$(sysctl -n dev.vtballoon.0.current); before_poisoned=\$(sysctl -n dev.vtballoon.0.poisoned); test \"\$before_current\" -gt 0; sysctl debug.vm_lowmem=2 >/dev/null; i=0; while [ \"\$(sysctl -n dev.vtballoon.0.current)\" -ge \"\$before_current\" ] && [ \"\$i\" -lt 100 ]; do sleep 0.05; i=\$((i + 1)); done; low=\$(sysctl -n dev.vtballoon.0.current); after_poisoned=\$(sysctl -n dev.vtballoon.0.poisoned); test \"\$low\" -lt \"\$before_current\"; test \"\$after_poisoned\" -gt \"\$before_poisoned\"; i=0; while [ \"\$(sysctl -n dev.vtballoon.0.current)\" != \"\$desired\" ] && [ \"\$i\" -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done; test \"\$(sysctl -n dev.vtballoon.0.current)\" = \"\$desired\"" \
			    30
			grep -Eq 'vtballoon: poison value=0([[:space:]]|$)' \
			    "$bhyve_log" || {
				echo "FAIL  host_balloon_page_poison_config" >&2
				exit 1
			}
			echo "PASS  host_balloon_page_poison_config"
		fi
		if [ "$FIVEBSD_DEVICE_SUSPEND" = yes ]; then
			guest_check device_suspend_balloon \
			    "set -eu; parent=\$(sysctl -n dev.vtballoon.0.%parent); unit=\${parent##*[!0-9]}; name=\${parent%\$unit}; test -n \"\$unit\"; sysctl -n \"dev.\$name.\$unit.negotiated_features\" | grep -q Suspend; desired=\$(sysctl -n dev.vtballoon.0.desired); devctl suspend \"\$parent\"; devctl resume \"\$parent\"; i=0; while [ \"\$(sysctl -n dev.vtballoon.0.current)\" != \"\$desired\" ] && [ \"\$i\" -lt 30 ]; do sleep 1; i=\$((i + 1)); done; test \"\$(sysctl -n dev.vtballoon.0.current)\" = \"\$desired\"" \
			    45
			host_device_lifecycle_check vtballoon
		fi
		if [ "$BALLOON_PACKED" = yes ]; then
			grep -Eq '^vtballoon: modern queue enable q=[0-9]+ .*enabled=1 .*layout=packed' \
			    "$bhyve_log" || {
				echo "FAIL  host_balloon_packed_layout" >&2
				exit 1
			}
			echo "PASS  host_balloon_packed_layout"
		fi
	fi

	run_nonvirtio_5bsd
	[ "$NONVIRTIO_CHECKPOINT" = no ] || run_nonvirtio_checkpoint_5bsd

	mkdir -p -m 0700 "$rundir/data"
	DIR=$sockdir BULK_MB=$BULK_MB \
	    TOOLS="$tools" \
	    WORK="$rundir/data" \
	    VCMD="env CONSOLE_LOG=$console_log CONSOLE_INPUT=$console_input sh $here/acmd-console.sh" \
	    sh "$here/run.sh"
	if [ "$FIVEBSD_VSOCK_PACKED" = yes ]; then
		grep -Eq '^vtvsock: modern queue enable q=[0-9]+ .*enabled=1 .*layout=packed' \
		    "$bhyve_log" || {
			echo "FAIL  host_vsock_packed_layout" >&2
			exit 1
		}
		grep -Eq '^vtvsock: modern notify q=[01]([[:space:]]|$)' \
		    "$bhyve_log" || {
			echo "FAIL  host_vsock_packed_io" >&2
			exit 1
		}
		echo "PASS  host_vsock_packed_layout_and_io"
	fi
	if [ "$FIVEBSD_RING_TRACE" = yes ]; then
		if [ "$FIVEBSD_NET_TEST" = yes ]; then
			net_layout=split
			[ "$FIVEBSD_NET_PACKED" = no ] || net_layout=packed
			finish_ring_trace "$net_layout" vtnet
			virtio_net_hash_trace_finish "$ring_trace" \
			    "$FIVEBSD_NET_QUEUES"
		else
			finish_ring_trace
		fi
	fi
	run_virtio_checkpoint_5bsd
	shutdown_guest
	cleanup_vm
	rm -f "$guest_image"
done

[ "$(sha256 -q "$IMAGE")" = "$base_image_sha256" ] || {
	echo "qualified 5BSD base image changed during execution" >&2
	exit 1
}

echo "5BSD transport automation completed successfully: $TRANSPORTS"
