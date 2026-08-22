#!/bin/sh

set -eu

usage()
{
	echo "usage: $0 freebsd-amd64.raw" >&2
	exit 64
}

[ "$#" -eq 1 ] || usage
image=$1
[ -f "$image" ] || usage

src=${SRCTOP:-/usr/src}
qemu=${QEMU_BIN:-qemu-system-x86_64}
accel=${QEMU_ACCEL:-tcg,thread=multi}
memory=${QEMU_MEMORY:-4096}
cpus=${QEMU_CPUS:-4}

command -v "$qemu" >/dev/null 2>&1 || {
	echo "qemu-system-x86_64 not found; set QEMU_BIN" >&2
	exit 69
}

# A package extracted outside the system prefix may carry private libraries.
qemu_libdir=${QEMU_LIBDIR:-$(dirname "$(dirname "$qemu")")/lib}
if [ -f "$qemu_libdir/libfdt.so.1" ]; then
	LD_LIBRARY_PATH=$qemu_libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH
fi
command -v makefs >/dev/null 2>&1 || {
	echo "makefs not found" >&2
	exit 69
}

module_obj=$(make -C "$src/sys/modules/oes" -V .OBJDIR)
tests_obj=$(make -C "$src/tests/sys/security/oes" -V .OBJDIR)
lib_obj=$(make -C "$src/lib/liboes" -V .OBJDIR)
logger_obj=$(make -C "$src/usr.sbin/oeslogger" -V .OBJDIR)

make -C "$src/sys/modules/oes"
make -C "$src/lib/liboes"
make -C "$src/usr.sbin/oeslogger"
make -C "$src/tests/sys/security/oes"

work=${OES_VM_WORKDIR:-$(mktemp -d /tmp/oes-qemu.XXXXXX)}
payload=$work/payload
iso=$work/oes-tests.iso
mkdir -p "$payload/tests" "$payload/include/security/oes" \
	"$payload/lib" "$payload/bin"

cp "$tests_obj/Kyuafile" "$payload/tests/"
awk -F'"' '/_test_program\{name=/{print $2}' "$tests_obj/Kyuafile" |
while read testname; do
	cp "$tests_obj/$testname" "$payload/tests/"
done
cp "$module_obj/oes.ko" "$payload/"
cp "$lib_obj/liboes.so.1" "$payload/lib/"
cp "$logger_obj/oeslogger" "$payload/bin/"
cp "$src/sys/security/oes/oes.h" \
	"$src/sys/security/oes/oes_event_table.h" \
	"$payload/include/security/oes/"
cp "$src/tools/test/oes-qemu/guest-run.sh" "$payload/"

makefs -t cd9660 -o rockridge,label=OES_TESTS "$iso" "$payload"
sha256 "$iso" "$payload/oes.ko"

echo "Booting a disposable snapshot.  Log in as root, then run:"
echo "  mkdir -p /mnt && mount -t cd9660 /dev/cd0 /mnt"
echo "  sh /mnt/guest-run.sh /mnt"
echo "Payload retained at: $work"

set --
if [ -n "${QEMU_DATADIR:-}" ]; then
	set -- -L "$QEMU_DATADIR"
fi
exec "$qemu" "$@" -machine q35 -accel "$accel" \
	-cpu max -smp "$cpus" -m "$memory" \
	-snapshot -drive "file=$image,format=raw,if=virtio" \
	-drive "file=$iso,format=raw,media=cdrom,readonly=on" \
	-boot c -display none -serial stdio -monitor none -no-reboot
