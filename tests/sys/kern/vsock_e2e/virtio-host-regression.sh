#!/bin/sh
# Complete VM-free release gate for the bhyve VirtIO lab.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kern_tests=$(CDPATH= cd -- "$here/.." && pwd)
workdir=${WORKDIR:-/tmp/virtio-host-regression}

mkdir -p "$workdir"

echo "=== VirtIO device, transport, and requirements sanitizer harnesses ==="
sh "$kern_tests/vsock_device_harness/run.sh"

echo "=== Host helper controls ==="
sh "$here/host-tools-selftest.sh"

echo "=== VirtIO, vsock, and AF_VSOCK isolation ATF suites ==="
results="$workdir/vsock-results.txt"
sh "$kern_tests/run_vsock_tests.sh" "$results"

echo "VM-free VirtIO release gate completed successfully"
