#!/bin/sh
# Build only; runtime probes belong in disposable guests.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 musl-sysroot output-directory" >&2; exit 2; }
r=$(realpath "$1")
mkdir -p "$2"
out=$(realpath "$2")
src=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
clang --target=x86_64-linux-musl --sysroot="$r" -fuse-ld=lld -static \
 -nostdlib -O2 -Wall -Wextra -Werror \
 "$r/usr/lib/crt1.o" "$r/usr/lib/crti.o" \
 "$src/tests/sys/kern/linux_unix_diag.c" -L"$r/usr/lib" -lc \
 "$r/usr/lib/crtn.o" -o "$out/linux_unix_diag"
