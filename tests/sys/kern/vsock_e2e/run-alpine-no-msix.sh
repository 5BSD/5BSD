#!/bin/sh
# Acceptance test for bhyve's shared VirtIO interrupt path.  The guest uses
# Alpine's upstream legacy drivers while bhyve -W removes MSI-X, forcing the
# one-vector MSI/INTx fallback exercised by virtio.c.
set -eu

here=$(cd "$(dirname "$0")" && pwd)

ISO=${ISO:?set ISO to an Alpine virt ISO}
TRANSPORTS=${TRANSPORTS:-legacy}
DEVICES=${DEVICES:-"vsock rng block"}
WORKDIR=${WORKDIR:-${TMPDIR:-/tmp}/bhyve-virtio-no-msix}
RESET_TEST=${RESET_TEST:-yes}
REBOOT_TEST=${REBOOT_TEST:-yes}
BLOCK_TEST_MB=${BLOCK_TEST_MB:-256}
BLOCK_IMAGE_MB=${BLOCK_IMAGE_MB:-1024}

exec env ISO="$ISO" TRANSPORTS="$TRANSPORTS" DEVICES="$DEVICES" \
    WORKDIR="$WORKDIR" VIRTIO_MSIX=no RESET_TEST="$RESET_TEST" \
    REBOOT_TEST="$REBOOT_TEST" BLOCK_TEST_MB="$BLOCK_TEST_MB" \
    BLOCK_IMAGE_MB="$BLOCK_IMAGE_MB" \
    sh "$here/run-alpine-auto.sh"
