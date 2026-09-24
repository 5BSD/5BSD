#!/bin/sh
# Build only. Execute these native fixtures exclusively in disposable VMs.
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 output-directory" >&2; exit 2; }
src=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
mkdir -p "$1/native-tests"
out=$(CDPATH= cd -- "$1" && pwd)
make -C "$src/tests/sys/fs/fusefs" MAKEOBJDIR="$out/native-tests" -j4 all
cc -static -O2 -Wall -Wextra -Werror \
 "$src/tests/sys/kern/linux_compat_native_exec.c" -o "$out/native-exec"
