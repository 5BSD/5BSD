#!/bin/sh
#
# Exercise the rebuilt FreeBSD VirtIO 9P transport's mount ownership and
# detach/attach reconstruction contract.  Run inside a disposable bhyve guest.

set -eu

tag=${1-}
seed=${2-}
iterations=${ITERATIONS:-1}
mountpoint=${MOUNTPOINT:-/mnt/bhyve-9p-rebind}
device=
mounted=no
detached=no
completed=no

cleanup()
{
	status=$?
	set +e
	if [ "$mounted" = yes ]; then
		umount "$mountpoint" >/dev/null 2>&1
	fi
	if [ "$detached" = yes ] && [ -n "$device" ]; then
		devctl attach "$device" >/dev/null 2>&1
	fi
	if [ "$completed" = yes ]; then
		rmdir "$mountpoint" >/dev/null 2>&1
	fi
	return "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

[ "$(id -u)" -eq 0 ] || {
	echo "must be run as root" >&2
	exit 1
}
[ "$(sysctl -n kern.vm_guest)" = "bhyve" ] || {
	echo "must be run inside a disposable bhyve guest" >&2
	exit 1
}
[ -n "$tag" ] || {
	echo "usage: $0 mount-tag expected-seed" >&2
	exit 1
}
case "$tag" in
*/*|*'
'*)
	echo "mount tag must not contain a slash or newline" >&2
	exit 1
	;;
esac
case "$iterations" in
*[!0-9]*|'')
	echo "ITERATIONS must be a positive integer" >&2
	exit 1
	;;
esac
[ "$iterations" -gt 0 ] || {
	echo "ITERATIONS must be a positive integer" >&2
	exit 1
}

device=$(devinfo | sed -n \
    's/.*\(virtio_p9fs[0-9][0-9]*\).*/\1/p' | head -n 1)
[ -n "$device" ] || {
	echo "no attached VirtIO 9P transport found" >&2
	exit 1
}
devinfo -p "$device" | grep -q 'virtio_pci' || {
	echo "$device is not attached through virtio_pci" >&2
	exit 1
}
mkdir -p "$mountpoint"

i=1
while [ "$i" -le "$iterations" ]; do
	mount -t p9fs "$tag" "$mountpoint"
	mounted=yes
	test "$(cat "$mountpoint/host-seed")" = "$seed"

	# A mounted p9fs owns the transport.  Detaching it must fail rather
	# than invalidate live fids or leave the mount backed by freed state.
	if devctl detach "$device" >/tmp/p9-rebind-detach.out 2>&1; then
		detached=yes
		echo "iteration $i: detach succeeded while p9fs was mounted" >&2
		exit 1
	fi
	devinfo -p "$device" | grep -q 'virtio_pci'
	test "$(cat "$mountpoint/host-seed")" = "$seed"

	umount "$mountpoint"
	mounted=no
	devctl detach "$device"
	detached=yes
	if devinfo -p "$device" >/dev/null 2>&1; then
		echo "iteration $i: 9P transport survived successful detach" >&2
		exit 1
	fi

	devctl attach "$device"
	detached=no
	j=0
	while ! devinfo -p "$device" 2>/dev/null | grep -q 'virtio_pci'; do
		j=$((j + 1))
		[ "$j" -lt 20 ] || {
			echo "iteration $i: 9P transport did not reattach" >&2
			exit 1
		}
		sleep 1
	done

	mount -t p9fs "$tag" "$mountpoint"
	mounted=yes
	test "$(cat "$mountpoint/host-seed")" = "$seed"
	umount "$mountpoint"
	mounted=no
	i=$((i + 1))
done

rm -f /tmp/p9-rebind-detach.out
completed=yes
echo "PASS p9fs ownership and rebind iterations=$iterations device=$device"
