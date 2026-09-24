#!/bin/sh
# Build only. Run the resulting probe exclusively in disposable guests.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 musl-sysroot output-directory" >&2; exit 2; }
r=$1
out=$2
src=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
mkdir -p "$out"
clang --target=x86_64-linux-musl --sysroot="$r" -fuse-ld=lld -static \
 -nostdlib -O2 -Wall -Wextra -Werror \
 "$r/usr/lib/crt1.o" "$r/usr/lib/crti.o" \
 "$src/tests/sys/kern/linux_proc_path.c" -L"$r/usr/lib" -lc \
 "$r/usr/lib/crtn.o" -o "$out/proc-path-linux"
brandelf -t Linux "$out/proc-path-linux"
