#!/bin/sh
# Build a bootable GPT/UFS raw image from a NO_ROOT tree (pkg METALOG or
# installworld METALOG).  Entries on disk but absent from the METALOG (files
# written by package scripts, e.g. pwd.db) are added as root:wheel with their
# on-disk mode; METALOG entries win.  Overrides come from $work/overlay.list:
#   ./path mode=0644 contents=/abs/file   (type=file, root:wheel)
# usage: mkimage.sh ROOT WORK [SIZE]
set -eu
root=$1 work=$2 size=${3:-6g}
mkdir -p "$work"
ov=$work/overlay.list; [ -f "$ov" ] || : > "$ov"
(cd "$root" && find . -mindepth 1 \( -type d -o -type f -o -type l \) \
    ! -path "./METALOG*" -exec stat -f "%N|%HT|%Mp%Lp|%Y" {} +) | \
    awk -F'|' '{
	if ($2 == "Directory") t = "dir"; else if ($2 == "Symbolic Link") t = "link"; else t = "file";
	l = (t == "link") ? " link=" $4 : "";
	printf "%s type=%s uname=root gname=wheel mode=%s%s\n", $1, t, (t == "link") ? "0755" : $3, l
    }' > "$work/disk.list"
ovre=$(awk '{printf "%s%s", sep, $1; sep="|"}' "$ov" | sed 's/\./\\./g')
[ -n "$ovre" ] || ovre='^$'
{
	# The image root: pkg METALOGs never describe ".", and makefs makes an
	# undescribed root mode 000 -- unprivileged services (uid "capability")
	# then cannot resolve /libexec/ld-elf.so.1 and die with SIGABRT in exec
	# (see gsv-record.md).  release/tools/vmimage.subr metalog_normalize
	# does the same for product VM images.  METALOG entries win (first).
	{ grep -E '^\.(/)? ' "$root/METALOG" || :; } | sed -E 's,^\./ ,. ,'
	echo ". type=dir uname=root gname=wheel mode=0755"
	sed 's/$/ type=file uname=root gname=wheel/' "$ov"
	grep -v -E "^($ovre) " "$root/METALOG" | sed 's/ tags=[^ ]*//'
	grep -v -E "^($ovre) " "$work/disk.list"
} | grep -v '^#' | awk '!seen[$1]++' | env -i LC_COLLATE=C sort > "$work/METALOG.body"
{ echo '#mtree 2.0'; cat "$work/METALOG.body"; } > "$work/METALOG"
( cd "$root" && makefs -N "$root/etc" -t ffs -D -B little -s "$size" \
    -o version=2,softupdates=1,label=root "$work/root.ufs" "$work/METALOG" ) \
    > "$work/makefs.log" 2>&1
# dm: an EFI system partition (index 3, after the UFS root, so vtbd0p2
# stays the root) with loader.efi as the removable-media default, so the same
# image boots through bhyveload (BIOS-style, reads UFS directly) and through
# UEFI firmware (devices-sr phase, uefi group).
rm -rf "$work/esp" "$work/esp.img"; mkdir -p "$work/esp/EFI/BOOT"
cp "$root/boot/loader.efi" "$work/esp/EFI/BOOT/BOOTX64.EFI"
makefs -t msdos -o fat_type=16 -o sectors_per_cluster=1 -o volume_label=EFISYS \
    -s 33m "$work/esp.img" "$work/esp" > "$work/makefs-esp.log" 2>&1
mkimg -s gpt -f raw -b "$root/boot/pmbr" -p "freebsd-boot:=$root/boot/gptboot" \
    -p "freebsd-ufs:=$work/root.ufs" -p "efi:=$work/esp.img" -o "$work/guest.img"
rm -rf "$work/root.ufs" "$work/esp.img" "$work/esp"
echo "image $work/guest.img"
