#!/bin/sh
# Complete VM-free release gate for the bhyve VirtIO lab.
set -eu

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kern_tests=$(CDPATH= cd -- "$here/.." && pwd)
tree_root=$(CDPATH= cd -- "$here/../../../.." && pwd)
if [ -n "${WORKDIR:-}" ]; then
	workdir=$WORKDIR
	case "$workdir" in
	/*) ;;
	*) echo "WORKDIR must be an absolute path" >&2; exit 1 ;;
	esac
	if [ -e "$workdir" ]; then
		[ -d "$workdir" ] && [ ! -L "$workdir" ] || {
			echo "WORKDIR must be a real directory: $workdir" >&2
			exit 1
		}
		set -- $(stat -f '%u %Lp' "$workdir")
		[ "$1" -eq "$(id -u)" ] && [ "$2" = 700 ] || {
			echo "WORKDIR must be owned by the caller with mode 0700: $workdir" >&2
			exit 1
		}
	else
		mkdir -m 0700 "$workdir"
	fi
else
	workdir=$(mktemp -d /tmp/virtio-host-regression.XXXXXX)
fi

if [ -d "$tree_root/sys" ]; then
	source_root=$tree_root
else
	source_root=${SRCTOP:-/usr/src}
fi
[ -d "$source_root/sys" ] || {
	echo "matching source tree is unavailable: $source_root" >&2
	exit 1
}

echo "host-regression artifacts: $workdir"

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
    "$source_root"

echo "=== KVM-selftests parity inventory and validator falsification ==="
vmm_test_dir=$tree_root/tests/sys/vmm
sh "$vmm_test_dir/validate-kvm-parity-requirements.sh" \
    "$vmm_test_dir/kvm-parity-requirements.tsv" "$source_root"
SRCTOP=$source_root sh "$vmm_test_dir/kvm-parity-selftest.sh"
sh "$vmm_test_dir/vmm-kvm-parity-stress-selftest.sh"

echo "=== Intel nested-VMX architectural state ABI ==="
case $(uname -m) in
amd64)
	vmx_test_dir=$vmm_test_dir
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
	SANITIZERS=${NESTED_SANITIZERS:-address,undefined} \
	    SRCTOP=$source_root sh "$vmx_model"
	;;
*)
	echo "SKIP nested VMX model: Intel amd64-only"
	;;
esac

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
