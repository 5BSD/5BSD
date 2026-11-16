#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# stage-linux-compat.sh -- copy the minimal Rocky Linux 9 userland the
# fdops linux_compat_test needs from the host's /compat/linux
# (linux_base-rl9) into a test-data overlay under /usr/obj.  Test data
# only: never part of base, never a package of the build.  No network.
#
# usage: stage-linux-compat.sh [SRC] [DEST]
#   SRC   default /compat/linux
#   DEST  default /usr/obj/5BSD-proxy-objects-vm/linux-compat-overlay
#         (the tree is DEST/compat/linux/...; DEST/MANIFEST lists every
#         file with its sha256 and origin)
#
# Libraries are found by reading DT_NEEDED with readelf, recursively, and
# resolving each name through /lib64 and /usr/lib64 as ld.so.cache would;
# nothing is guessed.  Symlinks are copied as symlinks.
set -eu

src=${1:-/compat/linux}
dest=${2:-/usr/obj/5BSD-proxy-objects-vm/linux-compat-overlay}
bins="stat truncate touch chmod chown sync fallocate"
# Wanted but not in the host's linux_base-rl9 (util-linux flock, attr).
wanted_missing="flock getfattr setfattr"

die() { echo "stage-linux-compat: $*" >&2; exit 1; }
[ -d "$src/usr/lib64" ] || die "no Linux userland at $src"
case "$dest" in
/usr/obj/*) ;;
*) die "DEST must be under /usr/obj (test data), not $dest" ;;
esac

root=$dest/compat/linux
rm -rf "$dest"
mkdir -p "$root"
list=$(mktemp)
trap 'rm -f "$list"' EXIT

# add PATH-INSIDE-SRC: copy it (and, for a symlink, its target chain).
add() {
	local p d t
	p=$1
	[ -e "$src$p" ] || [ -L "$src$p" ] || die "missing $src$p"
	# A path through a symlinked directory: keep the link, file the
	# object under its canonical directory.
	d=$(dirname "$p")
	if [ "$d" != / ]; then
		t=$(cd "$src$d" && pwd -P | sed "s|^$(cd "$src" && pwd -P)||")
		if [ "$t" != "$d" ]; then
			add_dir "$d"
			add "$t/$(basename "$p")"
			return 0
		fi
	fi
	grep -qxF "$p" "$list" && return 0
	echo "$p" >> "$list"
	d=$(dirname "$p")
	# Parent directories may themselves be symlinks (/lib64 -> usr/lib64).
	[ "$d" = / ] || add_dir "$d"
	if [ -L "$src$p" ]; then
		t=$(readlink "$src$p")
		ln -s "$t" "$root$p"
		case "$t" in
		/*) add "$t" ;;
		*) add "$(cd "$src$d" && cd "$(dirname "$t")" && pwd -P |
		    sed "s|^$(cd "$src" && pwd -P)||")/$(basename "$t")" ;;
		esac
	elif [ -d "$src$p" ]; then
		mkdir -p "$root$p"
	else
		cp -p "$src$p" "$root$p"
	fi
}

add_dir() {
	local dd
	dd=$1
	if [ -L "$src$dd" ]; then
		[ -L "$root$dd" ] || add "$dd"
	elif [ ! -d "$root$dd" ]; then
		add_dir "$(dirname "$dd")"
		mkdir -p "$root$dd"
	fi
}

# Resolve a DT_NEEDED name the way the dynamic linker does here.
resolve() {
	local d
	for d in /lib64 /usr/lib64; do
		if [ -e "$src$d/$1" ]; then
			echo "$d/$1"
			return 0
		fi
	done
	die "cannot resolve library $1"
}

needed() {
	readelf -d "$src$1" 2>/dev/null |
	    sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p'
}

interp() {
	readelf -l "$src$1" 2>/dev/null |
	    sed -n 's/.*program interpreter: \(.*\)\]/\1/p'
}

queue=
for b in $bins; do
	[ -e "$src/usr/bin/$b" ] || die "missing /usr/bin/$b"
	add "/usr/bin/$b"
	queue="$queue /usr/bin/$b"
	i=$(interp "/usr/bin/$b")
	[ -z "$i" ] || add "$i"
done
seen=
while [ -n "$queue" ]; do
	set -- $queue
	f=$1
	shift
	queue="$*"
	for n in $(needed "$f"); do
		case " $seen " in *" $n "*) continue ;; esac
		seen="$seen $n"
		l=$(resolve "$n")
		add "$l"
		queue="$queue $(cd "$src" && realpath -q ".$l" |
		    sed "s|^$(cd "$src" && pwd -P)||")"
	done
done
add /etc/ld.so.cache

# Manifest: path, type, sha256, origin.  linux_base-rl9 ships no rpm
# database (no /var/lib/rpm, no rpm(8)), so the origin is the host
# package that installed the file (pkg which), and the rpm within it is
# not recorded.
{
	echo "# linux-compat overlay for tests/sys/dq_regress/fdops"
	echo "# source: $src  host package: $(pkg which -q "$src/usr/bin/stat" 2>/dev/null || echo unknown)"
	echo "# rpm origin: not recorded (linux_base-rl9 installs no rpm database)"
	echo "# path type sha256 origin"
	sort "$list" | while read -r p; do
		if [ -L "$root$p" ]; then
			echo "/compat/linux$p symlink->$(readlink "$root$p") - $(pkg which -q "$src$p" 2>/dev/null || echo unknown)"
		elif [ -d "$root$p" ]; then
			echo "/compat/linux$p dir - -"
		else
			echo "/compat/linux$p file $(sha256 -q "$root$p") $(pkg which -q "$src$p" 2>/dev/null || echo unknown)"
		fi
	done
	for m in $wanted_missing; do
		echo "# uncovered: /usr/bin/$m is not in $src (util-linux/attr not installed, not in /var/cache/pkg)"
	done
} > "$dest/MANIFEST"

echo "staged $(wc -l < "$list" | tr -d ' ') entries, $(du -sk "$root" | cut -f1) KB in $root"
echo "manifest: $dest/MANIFEST"
