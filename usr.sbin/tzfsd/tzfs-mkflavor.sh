#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# tzfs-mkflavor -- build a tzfsd flavor artifact (a zstd-compressed ZFS
# send stream) from a directory tree.  The artifact is what tzfsd(8)
# receives at install/first-boot into its .templates and clones per
# request.  This is an admin/build-time tool: it uses raw zfs(8) (it is
# producing a shippable image, not handing out a runtime grant).
#
#   tzfs-mkflavor [-p pool] [-c level] -o out.zfs.zst <flavor> <srcdir>
#
#   -p pool    scratch pool for the build dataset (default: zroot)
#   -c level   zstd compression level (default: 19)
#   -o file    output artifact path (required)
#   flavor     flavor name (the received dataset's leaf; e.g. linux)
#   srcdir     directory tree to populate the template from
#
# The output stream, received by tzfsd, lands as <templates>/<flavor>
# with an @ready snapshot as its clone origin.

set -e

pool=zroot
level=19
out=

usage() {
	echo "usage: tzfs-mkflavor [-p pool] [-c level] -o out.zfs.zst" \
	    "<flavor> <srcdir>" >&2
	exit 1
}

while getopts "p:c:o:" opt; do
	case "$opt" in
	p) pool=$OPTARG ;;
	c) level=$OPTARG ;;
	o) out=$OPTARG ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))

[ $# -eq 2 ] || usage
flavor=$1
srcdir=$2
[ -n "$out" ] || usage
[ -d "$srcdir" ] || { echo "tzfs-mkflavor: $srcdir: not a directory" >&2; exit 1; }

scratch="$pool/.tzfs-build/$flavor"

cleanup() {
	zfs destroy -r "$scratch" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Fresh scratch dataset with a private mountpoint.
zfs destroy -r "$scratch" 2>/dev/null || true
mnt=$(mktemp -d /tmp/tzfs-mkflavor.XXXXXX)
zfs create -o "mountpoint=$mnt" -p "$scratch"

# Populate.  tar preserves ownership, modes, hardlinks and symlinks; the
# send stream then carries the populated tree verbatim.
echo "tzfs-mkflavor: populating $flavor from $srcdir ..." >&2
( cd "$srcdir" && tar -cf - . ) | ( cd "$mnt" && tar -xpf - )

# The @ready snapshot is the clone origin tzfsd expects.
zfs snapshot "$scratch@ready"

echo "tzfs-mkflavor: writing $out (zstd -$level) ..." >&2
zfs send "$scratch@ready" | zstd -q "-$level" -o "$out" -f

# mktemp dir is emptied when the dataset is destroyed on exit.
rmdir "$mnt" 2>/dev/null || true
echo "tzfs-mkflavor: wrote $out" >&2
