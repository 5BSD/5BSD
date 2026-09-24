#!/bin/sh
# Build only; execute the outputs in disposable amd64 guests.
# Usage: build-compat-next.sh /path/to/linux-musl-sysroot /path/to/output
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 musl-sysroot output-directory" >&2; exit 2; }
r=$1
out=$2
src=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
mkdir -p "$out"
clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
 -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror \
 "$src/tests/sys/kern/linux_abstract.c" -o "$out/abstract"
for name in linux_compat_next linux_fuse_passthrough; do
 lib=''
 target=compat-next
 if [ "$name" = linux_fuse_passthrough ]; then
  lib=-lfuse3
  target=fuse-passthrough
 fi
 clang --target=x86_64-linux-musl --sysroot="$r" -fuse-ld=lld -static \
  -nostdlib -O2 -Wall -Wextra -Werror -Wno-sign-compare \
  -I"$r/usr/include/fuse3" "$r/usr/lib/crt1.o" "$r/usr/lib/crti.o" \
  "$src/tests/sys/kern/$name.c" -L"$r/usr/lib" $lib -lc \
  "$r/usr/lib/crtn.o" -o "$out/$target"
done
for name in native caps; do
 cc -static -O2 -Wall -Wextra -Werror \
  "$src/tests/sys/kern/linux_abstract_$name.c" -o "$out/abstract-$name"
done
clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static -DLINUX_PROBE \
 "$src/tests/sys/kern/linux_abstract_caps.c" -o "$out/abstract-caps-probe"
