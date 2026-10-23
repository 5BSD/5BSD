#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Derive a new 5BSD DUT image from an existing image root (image-5bsd.sh
# output) by reinstalling the kernel and selected programs from the
# current object tree, without root (NO_ROOT METALOG).
#
# usage: image-update.sh SRCTOP OBJPREFIX BASEOUT NEWOUT [subdir ...]
#   subdir: source directories to reinstall (e.g. sbin/pfctl)
set -eu
[ $# -ge 4 ] || { echo "usage: $0 SRCTOP OBJPREFIX BASEOUT NEWOUT [subdir ...]" >&2; exit 64; }
src=$1 objp=$2 base=$3 out=$4; shift 4
case $out in /usr/obj/5BSD-pf-parity/*) ;; *) echo "bad NEWOUT" >&2; exit 64;; esac
[ ! -e "$out" ] || { echo "$out exists" >&2; exit 73; }
mkdir -p "$out"
cp -Rp "$base/root" "$out/root"
R=$out/root
export MAKEOBJDIRPREFIX=$objp
rm -rf "$R/boot/kernel"
# OpenBSD PF: pflog, pfsync and pflow are part of pf.ko.
sed -i '' '/^pflog_load=/d; /^pfsync_load=/d; /^pflow_load=/d' "$R/boot/loader.conf"
# Roots from older images name a UFS root; the new image is ZFS.
sed -i '' '\|^/dev/ufs/root[[:space:]]|d' "$R/etc/fstab"
make -C "$src" -DNO_ROOT DESTDIR="$R" KERNCONF=GENERIC installkernel \
    > "$out/install.log" 2>&1
for d in "$@"; do
	make -C "$src" -DNO_ROOT DESTDIR="$R" buildenv \
	    BUILDENV_SHELL="make -C $src/$d -DNO_ROOT DESTDIR=$R install" \
	    >> "$out/install.log" 2>&1
done
# 5BSD boots from ZFS (GENERIC has no UFS volume labels): the release VM
# image layout, with only the root dataset.
( cd "$R" && makefs -t zfs -s 16g -o poolname=zroot \
    -o bootfs=zroot/ROOT/default -o rootpath=/ \
    -o 'fs=zroot;mountpoint=none' -o 'fs=zroot/ROOT;mountpoint=none' \
    -o 'fs=zroot/ROOT/default;mountpoint=/;canmount=noauto' \
    -D "$out/root.zfs" METALOG ) > "$out/makefs.log" 2>&1
mkimg -s gpt -f raw -b "$R/boot/pmbr" -p freebsd-boot:="$R/boot/gptzfsboot" \
    -p freebsd-zfs:="$out/root.zfs" -o "$out/disk.img"
rm -f "$out/root.zfs"
echo "$out/disk.img"
