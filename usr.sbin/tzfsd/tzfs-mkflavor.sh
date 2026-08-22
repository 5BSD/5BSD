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

set -eu

pool=zroot
level=19
out=

usage() {
	echo "usage: tzfs-mkflavor [-p pool] [-c level] -o out.zfs.zst" \
	    "<flavor> <srcdir>" >&2
	exit 1
}

die() {
	echo "tzfs-mkflavor: $*" >&2
	exit 1
}

valid_component() {
	case "$1" in
	""|.|..|-*|*[!A-Za-z0-9_.-]*) return 1 ;;
	esac
}

valid_pool() {
	case "$1" in
	""|.|..|-*|*/*|*[!A-Za-z0-9_.:-]*) return 1 ;;
	esac
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
[ -d "$srcdir" ] || die "$srcdir: not a directory"
valid_pool "$pool" || die "invalid pool name: $pool"
valid_component "$flavor" || die "invalid flavor name: $flavor"
case "$level" in
""|*[!0-9]*) die "compression level must be an integer from 1 through 19" ;;
esac
[ "$level" -ge 1 ] && [ "$level" -le 19 ] ||
	die "compression level must be an integer from 1 through 19"
[ ! -d "$out" ] || die "$out: is a directory"

zfs_cmd=$(command -v zfs) || die "zfs not found"
zstd_cmd=$(command -v zstd) || die "zstd not found"
tar_cmd=$(command -v tar) || die "tar not found"
outdir=$(dirname "$out")
[ -d "$outdir" ] || die "$outdir: output directory does not exist"

state=$(mktemp -d "${TMPDIR:-/tmp}/tzfs-mkflavor.XXXXXX") ||
	die "cannot create private work directory"
token=${state##*/}
scratch="$pool/.tzfs-build/$flavor-$token"
mnt="$state/root"
fifo="$state/stream"
tmpout=
created=false
producer=

cleanup() {
	trap - EXIT INT TERM HUP
	if [ -n "$producer" ]; then
		kill "$producer" 2>/dev/null || true
		wait "$producer" 2>/dev/null || true
	fi
	if [ "$created" = true ]; then
		"$zfs_cmd" destroy -r "$scratch" 2>/dev/null || true
	fi
	rm -f "$fifo"
	[ -z "$tmpout" ] || rm -f "$tmpout"
	rmdir "$mnt" "$state" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

tmpout=$(mktemp "$out.tmp.XXXXXX") || die "cannot create output temporary"

# Fresh scratch dataset with a private mountpoint.
mkdir "$mnt"
if "$zfs_cmd" list -H -o name "$scratch" >/dev/null 2>&1; then
	die "refusing to reuse existing scratch dataset: $scratch"
fi
"$zfs_cmd" create -o "mountpoint=$mnt" -p "$scratch"
created=true

# Populate.  tar preserves ownership, modes, hardlinks and symlinks; the
# send stream then carries the populated tree verbatim.
echo "tzfs-mkflavor: populating $flavor from $srcdir ..." >&2
mkfifo "$fifo"
"$tar_cmd" -C "$srcdir" -cf - . >"$fifo" &
producer=$!
if ! "$tar_cmd" -C "$mnt" -xpf - <"$fifo"; then
	die "failed to extract source tree"
fi
if ! wait "$producer"; then
	producer=
	die "failed to archive source tree"
fi
producer=
rm -f "$fifo"

# The @ready snapshot is the clone origin tzfsd expects.
"$zfs_cmd" snapshot "$scratch@ready"

echo "tzfs-mkflavor: writing $out (zstd -$level) ..." >&2
mkfifo "$fifo"
"$zfs_cmd" send "$scratch@ready" >"$fifo" &
producer=$!
if ! "$zstd_cmd" -q "-$level" -o "$tmpout" -f <"$fifo"; then
	die "failed to compress send stream"
fi
if ! wait "$producer"; then
	producer=
	die "failed to produce send stream"
fi
producer=
rm -f "$fifo"
[ -s "$tmpout" ] || die "compressed artifact is empty"
mv -f "$tmpout" "$out"
tmpout=

# mktemp dir is emptied when the dataset is destroyed on exit.
echo "tzfs-mkflavor: wrote $out" >&2
