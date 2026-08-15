#!/bin/sh
# Complete VM-free release gate for the bhyve VirtIO lab.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kern_tests=$(CDPATH= cd -- "$here/.." && pwd)
tree_root=$(CDPATH= cd -- "$here/../../../.." && pwd)
workdir=${WORKDIR:-/tmp/virtio-host-regression}

mkdir -p "$workdir"

echo "=== VirtIO device, transport, and requirements sanitizer harnesses ==="
harness_result="$workdir/device-harness.result"
RESULT_FILE="$harness_result" sh "$kern_tests/vsock_device_harness/run.sh"
[ "$(cat "$harness_result")" = 'PASS device harness all tests passed' ] || {
	echo "device harness did not publish a successful completion record" >&2
	exit 1
}
if [ -n "${VIRTIO_REFERENCE_ARTIFACT_DIR:-}" ]; then
	echo "=== Authenticated local reference corpus ==="
	sh "$kern_tests/vsock_device_harness/validate-virtio-reference-corpus.sh" \
	    "$kern_tests/vsock_device_harness/virtio-reference-corpus.tsv" \
	    "$VIRTIO_REFERENCE_ARTIFACT_DIR"
fi

echo "=== Host helper controls ==="
sh "$here/host-tools-selftest.sh"

echo "=== bhyve snapshot build-mode integration ==="
sh "$kern_tests/vsock_device_harness/validate-bhyve-build-modes.sh" \
    "$tree_root"

echo "=== Intel nested-VMX architectural state ABI ==="
vmx_test_dir=$tree_root/tests/sys/vmm
vmx_requirements=$vmx_test_dir/validate-vmx-nested-requirements.sh
[ -x "$vmx_requirements" ] || {
	echo "validate-vmx-nested-requirements.sh is unavailable" >&2
	exit 1
}
sh "$vmx_requirements"
sh "$vmx_test_dir/vmx-nested-live-coverage-selftest.sh"
vmx_model=$vmx_test_dir/run-vmx-nested-model.sh
[ -x "$vmx_model" ] || {
	echo "run-vmx-nested-model.sh is unavailable" >&2
	exit 1
}
if [ -d "$tree_root/sys" ]; then
	model_srctop=$tree_root
else
	model_srctop=${SRCTOP:-/usr/src}
fi
SANITIZERS=${NESTED_SANITIZERS:-address,undefined} \
    SRCTOP=$model_srctop sh "$vmx_model"

echo "=== VirtIO, vsock, and AF_VSOCK isolation ATF suites ==="
if [ "$(id -u)" -ne 0 ] &&
    [ "${RUN_PRIVILEGED_ATF:-auto}" != yes ]; then
	echo "DEFER privileged kernel/MAC ATF suites (root required)"
	echo "VM-free VirtIO rootless release gate completed successfully"
	exit 0
fi
results="$workdir/vsock-results.txt"
sh "$kern_tests/run_vsock_tests.sh" "$results"

echo "VM-free VirtIO release gate completed successfully"
