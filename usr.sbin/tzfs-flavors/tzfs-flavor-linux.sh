#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# tzfs-flavor-linux -- produce the "linux" tzfsd(8) flavor artifact from the
# official Rocky Linux minimal container base rootfs.
#
# It fetches the container image, extracts its single rootfs layer, and hands
# the tree to tzfs-mkflavor(8), which writes a zstd-compressed ZFS send stream
# that tzfsd(8) receives into its templates and clones per request.  This is a
# build-/admin-time tool: it needs network access and a live ZFS pool.
#
#   tzfs-flavor-linux -s archive-sha256 -l layer-sha256
#       [-r release] [-p pool] [-o out.zfs.zst] [-m mirror]
#
#   -r release   Rocky major release (default: 9)
#   -p pool      scratch pool for tzfs-mkflavor (default: zroot)
#   -o file      output artifact (default: /usr/share/tzfs/rocky9.zfs.zst)
#   -m mirror    Rocky mirror base URL
#   -s digest    required SHA-256 of the downloaded Rocky OCI archive
#   -l digest    required SHA-256 OCI rootfs layer digest
#
# The output path must match the "source" the flavor catalog fragment
# (flavors.ucl) declares for the linux flavor.

set -eu

rel=9
pool=zroot
out=
mirror=https://dl.rockylinux.org/pub/rocky
archive_sha=
layer_sha=

usage() {
	echo "usage: tzfs-flavor-linux -s archive-sha256 -l layer-sha256" \
	    "[-r release] [-p pool] [-o out.zfs.zst] [-m mirror]" >&2
	exit 1
}

while getopts "r:p:o:m:s:l:" opt; do
	case "$opt" in
	r) rel=$OPTARG ;;
	p) pool=$OPTARG ;;
	o) out=$OPTARG ;;
	m) mirror=$OPTARG ;;
	s) archive_sha=$OPTARG ;;
	l) layer_sha=$OPTARG ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || usage

case "$rel" in ""|*[!0-9]*) usage ;; esac
case "$archive_sha" in
????????????????????????????????????????????????????????????????) ;;
*) usage ;;
esac
case "$layer_sha" in
????????????????????????????????????????????????????????????????) ;;
*) usage ;;
esac
case "$archive_sha$layer_sha" in *[!0-9a-f]*) usage ;; esac
case "$mirror" in https://*) ;; *)
	echo "tzfs-flavor-linux: mirror must use HTTPS" >&2
	exit 1
;; esac
[ -n "$out" ] || out="/usr/share/tzfs/rocky${rel}.zfs.zst"

img="Rocky-${rel}-Container-Minimal.latest.x86_64.tar.xz"
url="${mirror}/${rel}/images/x86_64/${img}"

work=$(mktemp -d "${TMPDIR:-/tmp}/tzfs-flavor-linux.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 1' INT TERM HUP
fetch_cmd=${TZFS_FETCH:-/usr/bin/fetch}
mkflavor=${TZFS_MKFLAVOR:-/usr/sbin/tzfs-mkflavor}
[ -x "$fetch_cmd" ] || { echo "tzfs-flavor-linux: fetch tool unavailable" >&2; exit 1; }
[ -x "$mkflavor" ] || { echo "tzfs-flavor-linux: tzfs-mkflavor unavailable" >&2; exit 1; }

echo "tzfs-flavor-linux: fetching $url" >&2
"$fetch_cmd" -o "$work/oci.tar.xz" "$url"

actual=$(/sbin/sha256 -q "$work/oci.tar.xz")
[ "$actual" = "$archive_sha" ] || {
	echo "tzfs-flavor-linux: archive SHA-256 mismatch" >&2
	exit 1
}

# Extract exactly the pinned OCI blob instead of guessing from blob sizes.
# Both the outer archive and layer are listed first so path traversal and OCI
# whiteout semantics can never be interpreted as ordinary rootfs files.
if /usr/bin/tar -tf "$work/oci.tar.xz" | /usr/bin/awk '
    /^\// || /(^|\/)\.\.($|\/)/ { bad = 1 } END { exit bad }'; then :; else
	echo "tzfs-flavor-linux: unsafe path in OCI archive" >&2
	exit 1
fi
layer_path="blobs/sha256/$layer_sha"
if ! /usr/bin/tar -xOf "$work/oci.tar.xz" "$layer_path" >"$work/layer.tar"; then
	echo "tzfs-flavor-linux: pinned OCI layer is absent" >&2
	exit 1
fi
actual=$(/sbin/sha256 -q "$work/layer.tar")
[ "$actual" = "$layer_sha" ] || {
	echo "tzfs-flavor-linux: OCI layer SHA-256 mismatch" >&2
	exit 1
}
if /usr/bin/tar -tf "$work/layer.tar" | /usr/bin/awk '
    /^\// || /(^|\/)\.\.($|\/)/ || /(^|\/)\.wh\./ { bad = 1 }
    END { exit bad }'; then :; else
	echo "tzfs-flavor-linux: unsafe path or unsupported whiteout in layer" >&2
	exit 1
fi
mkdir "$work/rootfs"
/usr/bin/tar -xf "$work/layer.tar" -C "$work/rootfs"

mkdir -p "$(dirname "$out")"
"$mkflavor" -p "$pool" -o "$out" linux "$work/rootfs"
echo "tzfs-flavor-linux: wrote $out" >&2
