#!/bin/sh
# Build only. Run both binaries exclusively in disposable guests.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 musl-sysroot output-directory" >&2; exit 2; }
r=$1
out=$2
src=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
mkdir -p "$out"
clang --target=x86_64-linux-musl --sysroot="$r" -fuse-ld=lld -static \
 -nostdlib -O2 -Wall -Wextra -Werror \
 "$r/usr/lib/crt1.o" "$r/usr/lib/crti.o" \
 "$src/tests/sys/kern/linux_inotify_lifetime.c" -L"$r/usr/lib" -lc \
 "$r/usr/lib/crtn.o" -o "$out/lifetime-linux"
cc -static -O2 -Wall -Wextra -Werror \
 "$src/tests/sys/kern/linux_inotify_lifetime.c" -o "$out/lifetime-native"
cc -static -O2 -Wall -Wextra "$src/tests/sys/kern/inotify_test.c" \
 -lprivateatf-c -lutil -o "$out/inotify_test"
# Include cleanup metadata so each native ATF case can run in isolation.
awk '
/^ATF_TC_WITH_CLEANUP\(/ {
 name = $0; sub(/^[^(]*\(/, "", name); sub(/\).*/, "", name)
 cleanup[name] = 1
}
/ATF_TP_ADD_TC\(tp, / {
 name = $0; sub(/.*ATF_TP_ADD_TC\(tp, /, "", name); sub(/\).*/, "", name)
 print name, cleanup[name] ? "yes" : "no"
}' "$src/tests/sys/kern/inotify_test.c" > "$out/inotify-cases"
