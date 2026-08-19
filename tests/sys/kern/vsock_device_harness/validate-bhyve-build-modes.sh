#!/bin/sh
# Verify that the bhyve/bhyvectl/libvmmapi interface builds consistently with
# the optional snapshot facility both absent and present.  Fresh object roots
# prove each mode in isolation; a second no->yes->no pass reuses one root so
# that a stale object compiled with the opposite CPP mode cannot survive.
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
	[ ! -f "$src/usr.sbin/bhyvectl/Makefile" ] ||
	[ ! -f "$src/lib/libvmmapi/Makefile" ]; then
	echo "not a bhyve source tree: $src" >&2
	exit 2
fi

if [ "$(uname -p)" = amd64 ]; then
	default_mode=$(make -C "$src/usr.sbin/bhyve" -V MK_BHYVE_SNAPSHOT)
	[ "$default_mode" = yes ] || {
		echo "amd64 bhyve must enable snapshot support by default" >&2
		exit 1
	}
fi

verify_mode()
{
	root=$1
	expected=$2
	bhyve_obj=$(MAKEOBJDIRPREFIX="$root" make -C "$src/usr.sbin/bhyve" \
	    MK_BHYVE_SNAPSHOT="$expected" -V .OBJDIR)
	bhyvectl_obj=$(MAKEOBJDIRPREFIX="$root" make -C "$src/usr.sbin/bhyvectl" \
	    MK_BHYVE_SNAPSHOT="$expected" -V .OBJDIR)

	if "$bhyve_obj/bhyve" -h 2>&1 |
	    grep -q -- '-r: path to checkpoint file'; then
		bhyve_mode=yes
	else
		bhyve_mode=no
	fi
	if "$bhyvectl_obj/bhyvectl" --help 2>&1 |
	    grep -q -- '--checkpoint=<filename>'; then
		bhyvectl_mode=yes
	else
		bhyvectl_mode=no
	fi
	if [ "$bhyve_mode" != "$expected" ] ||
	    [ "$bhyvectl_mode" != "$expected" ]; then
		echo "snapshot tool mode mismatch: expected=$expected bhyve=$bhyve_mode bhyvectl=$bhyvectl_mode" >&2
		exit 1
	fi
}

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
	    MK_BHYVE_SNAPSHOT="$snapshot" >>"$log" 2>&1 ||
	    ! MAKEOBJDIRPREFIX="$objroot/$snapshot" \
	    make -C "$src/usr.sbin/bhyvectl" -j"$jobs" \
	    MK_BHYVE_SNAPSHOT="$snapshot" >>"$log" 2>&1; then
		echo "bhyve build mode failed: MK_BHYVE_SNAPSHOT=$snapshot" >&2
		tail -n 120 "$log" >&2
		exit 1
	fi
	verify_mode "$objroot/$snapshot" "$snapshot"
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
	    MK_BHYVE_SNAPSHOT="$snapshot" >>"$log" 2>&1 ||
	    ! MAKEOBJDIRPREFIX="$toggle" \
	    make -C "$src/usr.sbin/bhyvectl" -j"$jobs" \
	    MK_BHYVE_SNAPSHOT="$snapshot" >>"$log" 2>&1; then
		echo "bhyve build mode transition failed: MK_BHYVE_SNAPSHOT=$snapshot" >&2
		tail -n 120 "$log" >&2
		exit 1
	fi
	verify_mode "$toggle" "$snapshot"
done

echo "PASS bhyve/bhyvectl build modes: isolated and reused snapshot=no,yes"
