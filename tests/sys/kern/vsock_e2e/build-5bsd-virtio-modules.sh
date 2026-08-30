#!/bin/sh
#
# Compile every in-tree 5BSD VirtIO guest module used by the live matrix.
# This is deliberately VM-free: it catches guest-driver API and warning
# regressions before an immutable test image is booted.

set -eu

src=${SRCTOP:-/usr/src}
jobs=${MAKE_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 1)}
module_set=${FIVEBSD_MODULE_SET:-supported}

case "$jobs" in
''|*[!0-9]*)
	echo "5BSD VirtIO module build: MAKE_JOBS must be numeric" >&2
	exit 2
	;;
esac
[ "$jobs" -gt 0 ] || {
	echo "5BSD VirtIO module build: MAKE_JOBS must be positive" >&2
	exit 2
}

work=$(mktemp -d /tmp/virtio-5bsd-modules.XXXXXX)
cleanup()
{
	status=${1:-$?}
	trap - EXIT HUP INT TERM
	rm -rf "$work"
	exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
obj=$work/obj
log=$work/build.log

build_module_tree()
{
	directory=$1

	if ! env MAKEOBJDIRPREFIX="$obj" make -C "$src/$directory" \
	    -j"$jobs" >> "$log" 2>&1; then
		echo "5BSD VirtIO module build failed: $directory" >&2
		tail -n 120 "$log" >&2
		exit 1
	fi
}

case "$module_set" in
supported)
	directories='
sys/modules/virtio/virtio
sys/modules/virtio/pci
sys/modules/virtio/network
sys/modules/virtio/block
sys/modules/virtio/scsi
sys/modules/virtio/balloon
sys/modules/virtio/random
sys/modules/virtio/console
sys/modules/virtio/gpu
sys/modules/virtio/input
sys/modules/virtio/p9fs
sys/modules/virtio/rtc
sys/modules/virtio/vsock
sys/modules/virtio/sound
sys/modules/virtio/crypto
sys/modules/vsock
sys/modules/p9fs
'
	modules='
virtio.ko
virtio_pci.ko
if_vtnet.ko
virtio_blk.ko
virtio_scsi.ko
virtio_balloon.ko
virtio_random.ko
virtio_console.ko
virtio_gpu.ko
virtio_input.ko
virtio_p9fs.ko
virtio_rtc.ko
virtio_vsock.ko
virtio_snd.ko
virtio_crypto.ko
vsock.ko
p9fs.ko
'
	;;
prototype)
	directories='
sys/modules/virtio/fs
sys/modules/virtio/mem
sys/modules/virtio/iommu
'
	modules='
virtio_fs.ko
virtio_mem.ko
virtio_iommu.ko
'
	# PMEM consumes the amd64-only nvdimm provider.
	case "$(uname -m)" in
	amd64|x86_64)
		directories="$directories
sys/modules/virtio/pmem"
		modules="$modules
virtio_pmem.ko"
		;;
	esac
	;;
*)
	echo "5BSD VirtIO module build: FIVEBSD_MODULE_SET must be supported or prototype" >&2
	exit 2
	;;
esac

for directory in $directories; do
	build_module_tree "$directory"
done

count=0
for module in $modules; do
	paths=$(find "$obj" -type f -name "$module" -print)
	[ "$(printf '%s\n' "$paths" | sed '/^$/d' | wc -l | tr -d ' ')" -eq 1 ] || {
		echo "5BSD VirtIO module build did not produce exactly one $module" >&2
		exit 1
	}
	[ -s "$paths" ] || {
		echo "5BSD VirtIO module build produced no $module" >&2
		exit 1
	}
	count=$((count + 1))
done

echo "PASS 5BSD VirtIO module-set=$module_set modules=$count architecture=$(uname -m)"
