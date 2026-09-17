#!/bin/sh
# boot-qemu.sh IMG [rw] — boot a guest image under the home-dir qemu (TCG),
# serial on tcp 4321.  Default is snapshot mode (image untouched); pass "rw"
# as the second argument to persist writes.  EXTRA="-drive ..." appends
# qemu arguments (e.g. a second raw disk carrying a tar to unpack in-guest).
set -u
QEMU=$HOME/qemu-root/usr/local/bin/qemu-system-x86_64
SHIM=$HOME/vm/libfreesized.so
IMG=${1:-$HOME/vm/bsd-guest.img}
SNAP=on; [ "${2:-}" = "rw" ] && SNAP=off
LD_PRELOAD=$SHIM LD_LIBRARY_PATH=$HOME/qemu-root/usr/local/lib \
exec $QEMU -L $HOME/qemu-root/usr/local/share/qemu \
  -accel tcg,thread=multi -machine q35 -m 8192 -smp 4 \
  -drive file=$IMG,format=raw,if=virtio,snapshot=$SNAP \
  -serial tcp:127.0.0.1:${PORT:-4321},server,nowait \
  -nographic -vga none -display none ${EXTRA:-}
