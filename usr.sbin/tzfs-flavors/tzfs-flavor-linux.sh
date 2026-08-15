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
#   tzfs-flavor-linux [-r release] [-p pool] [-o out.zfs.zst] [-m mirror]
#
#   -r release   Rocky major release (default: 9)
#   -p pool      scratch pool for tzfs-mkflavor (default: zroot)
#   -o file      output artifact (default: /usr/share/tzfs/rocky9.zfs.zst)
#   -m mirror    Rocky mirror base URL
#
# The output path must match the "source" the flavor catalog fragment
# (flavors.ucl) declares for the linux flavor.

set -e

rel=9
pool=zroot
out=/usr/share/tzfs/rocky9.zfs.zst
mirror=https://dl.rockylinux.org/pub/rocky

usage() {
	echo "usage: tzfs-flavor-linux [-r release] [-p pool] [-o out.zfs.zst]" \
	    "[-m mirror]" >&2
	exit 1
}

while getopts "r:p:o:m:" opt; do
	case "$opt" in
	r) rel=$OPTARG ;;
	p) pool=$OPTARG ;;
	o) out=$OPTARG ;;
	m) mirror=$OPTARG ;;
	*) usage ;;
	esac
done

img="Rocky-${rel}-Container-Minimal.latest.x86_64.tar.xz"
url="${mirror}/${rel}/images/x86_64/${img}"

work=$(mktemp -d "${TMPDIR:-/tmp}/tzfs-flavor-linux.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

echo "tzfs-flavor-linux: fetching $url" >&2
if command -v fetch >/dev/null 2>&1; then
	fetch -o "$work/oci.tar.xz" "$url"
else
	curl -fsSL -o "$work/oci.tar.xz" "$url"
fi

# The image is an OCI archive: blobs/sha256/<digest> plus metadata.  The
# rootfs is the single largest blob, a gzip-compressed layer tarball.
mkdir "$work/oci" "$work/rootfs"
tar xf "$work/oci.tar.xz" -C "$work/oci"
layer=$(ls -S "$work/oci/blobs/sha256/"* 2>/dev/null | head -1)
[ -n "$layer" ] || { echo "tzfs-flavor-linux: no layer blob found" >&2; exit 1; }
tar xzf "$layer" -C "$work/rootfs"

mkdir -p "$(dirname "$out")"
tzfs-mkflavor -p "$pool" -o "$out" linux "$work/rootfs"
echo "tzfs-flavor-linux: wrote $out" >&2
