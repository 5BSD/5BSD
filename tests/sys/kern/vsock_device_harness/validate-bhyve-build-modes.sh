#!/bin/sh
# Verify that the bhyve/libvmmapi interface builds consistently with the
# optional snapshot facility both absent and present.  Fresh object roots prove
# each mode in isolation; a second no->yes->no pass reuses one root so that a
# stale object compiled with the opposite CPP mode cannot hide a link error.
set -eu

src=${1:-${SRCTOP:-/usr/src}}
jobs=${VIRTIO_BUILD_JOBS:-2}

case "$jobs" in
''|*[!0-9]*)
	echo "VIRTIO_BUILD_JOBS must be a positive integer" >&2
	exit 2
	;;
0)
	echo "VIRTIO_BUILD_JOBS must be a positive integer" >&2
	exit 2
	;;
esac

if [ ! -f "$src/usr.sbin/bhyve/Makefile" ] ||
    [ ! -f "$src/lib/libvmmapi/Makefile" ]; then
	echo "not a bhyve source tree: $src" >&2
	exit 2
fi

objroot=$(mktemp -d /tmp/bhyve-build-modes.XXXXXX)
cleanup()
{
	status=${1:-$?}
	trap - EXIT HUP INT TERM
	rm -rf -- "$objroot"
	exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

for snapshot in no yes; do
	echo "bhyve build mode: MK_BHYVE_SNAPSHOT=$snapshot"
	log="$objroot/$snapshot.log"
	if ! MAKEOBJDIRPREFIX="$objroot/$snapshot" \
	    make -C "$src/lib/libvmmapi" -j"$jobs" \
	    MK_BHYVE_SNAPSHOT="$snapshot" >"$log" 2>&1 ||
	    ! MAKEOBJDIRPREFIX="$objroot/$snapshot" \
	    make -C "$src/usr.sbin/bhyve" -j"$jobs" \
	    MK_BHYVE_SNAPSHOT="$snapshot" >>"$log" 2>&1; then
		echo "bhyve build mode failed: MK_BHYVE_SNAPSHOT=$snapshot" >&2
		tail -n 120 "$log" >&2
		exit 1
	fi
done

# The normal source-tree object directory is often reused by developers and
# package builds.  A fresh directory per mode proves each configuration in
# isolation, but cannot detect stale objects compiled with the opposite
# preprocessor mode.  Exercise both transitions in one private object tree.
toggle="$objroot/toggle"
for snapshot in no yes no; do
	echo "bhyve build mode transition: MK_BHYVE_SNAPSHOT=$snapshot"
	log="$objroot/toggle-$snapshot.log"
	if ! MAKEOBJDIRPREFIX="$toggle" \
	    make -C "$src/lib/libvmmapi" -j"$jobs" \
	    MK_BHYVE_SNAPSHOT="$snapshot" >"$log" 2>&1 ||
	    ! MAKEOBJDIRPREFIX="$toggle" \
	    make -C "$src/usr.sbin/bhyve" -j"$jobs" \
	    MK_BHYVE_SNAPSHOT="$snapshot" >>"$log" 2>&1; then
		echo "bhyve build mode transition failed: MK_BHYVE_SNAPSHOT=$snapshot" >&2
		tail -n 120 "$log" >&2
		exit 1
	fi
done

echo "PASS bhyve build modes: isolated and reused snapshot=no,yes"
