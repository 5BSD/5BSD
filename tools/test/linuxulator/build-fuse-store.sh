#!/bin/sh
# Build only; execute exclusively in disposable Linux64/FreeBSD VMs.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 libfuse-musl-sysroot output-directory" >&2; exit 2; }
root=$(realpath "$1")
mkdir -p "$2"
out=$(realpath "$2")
src=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
clang --target=x86_64-linux-musl --sysroot="$root" -fuse-ld=lld \
 -static -nostdlib -O2 -Wall -Wextra -Werror -I"$root/usr/include/fuse3" \
 "$root/usr/lib/crt1.o" "$root/usr/lib/crti.o" \
 "$src/tests/sys/kern/linux_fuse_store.c" -L"$root/usr/lib" -lfuse3 -lc \
 "$root/usr/lib/crtn.o" -o "$out/linux_fuse_store"
