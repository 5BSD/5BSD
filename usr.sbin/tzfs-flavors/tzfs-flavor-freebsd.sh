#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# tzfs-flavor-freebsd -- produce the "freebsd" tzfsd(8) flavor artifact from a
# FreeBSD base userland tree.
#
# The source tree is either an installed DESTDIR (from "make installworld
# DESTDIR=...") or the directory an official base.txz was extracted into.  The
# tree is handed to tzfs-mkflavor(8), which writes a zstd-compressed ZFS send
# stream that tzfsd(8) receives into its templates and clones per request.
# Build-/admin-time tool: needs a live ZFS pool.
#
#   tzfs-flavor-freebsd [-p pool] [-o out.zfs.zst] <base-rootfs-dir>
#
#   -p pool      scratch pool for tzfs-mkflavor (default: zroot)
#   -o file      output artifact (default: /usr/share/tzfs/freebsd.zfs.zst)
#
# The output path must match the "source" the flavor catalog fragment
# (flavors.ucl) declares for the freebsd flavor.

set -e

pool=zroot
out=/usr/share/tzfs/freebsd.zfs.zst

usage() {
	echo "usage: tzfs-flavor-freebsd [-p pool] [-o out.zfs.zst]" \
	    "<base-rootfs-dir>" >&2
	exit 1
}

while getopts "p:o:" opt; do
	case "$opt" in
	p) pool=$OPTARG ;;
	o) out=$OPTARG ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))

src=$1
[ -n "$src" ] && [ -d "$src" ] || usage

mkdir -p "$(dirname "$out")"
tzfs-mkflavor -p "$pool" -o "$out" freebsd "$src"
echo "tzfs-flavor-freebsd: wrote $out" >&2
