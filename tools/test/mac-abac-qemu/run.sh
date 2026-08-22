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
qemu_libdir=${QEMU_LIBDIR:-$(dirname "$(dirname "$qemu")")/lib}
if [ -f "$qemu_libdir/libfdt.so.1" ]; then
	LD_LIBRARY_PATH=$qemu_libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH
fi
command -v makefs >/dev/null 2>&1 || {
	echo "makefs not found" >&2
	exit 69
}

module_obj=$(make -C "$src/sys/modules/mac_abac" -V .OBJDIR)
tests_obj=$(make -C "$src/tests/sys/security/mac_abac" -V .OBJDIR)
ctl_obj=$(make -C "$src/usr.sbin/mac_abac_ctl" -V .OBJDIR)
daemon_obj=$(make -C "$src/usr.sbin/mac_abacd" -V .OBJDIR)

make -C "$src/sys/modules/mac_abac"
make -C "$src/usr.sbin/mac_abac_ctl"
make -C "$src/usr.sbin/mac_abacd"
make -C "$src/tests/sys/security/mac_abac"

work=${MAC_ABAC_VM_WORKDIR:-$(mktemp -d /tmp/mac-abac-qemu.XXXXXX)}
payload=$work/payload
iso=$work/mac-abac-tests.iso
mkdir -p "$payload/tests" "$payload/include/security/mac_abac" \
	"$payload/bin" "$payload/examples"

cp "$tests_obj/Kyuafile" "$payload/tests/"
awk -F'"' '/_test_program\{name=/{print $2}' "$tests_obj/Kyuafile" |
while read testname; do
	cp "$tests_obj/$testname" "$payload/tests/"
done
cp "$module_obj/mac_abac.ko" "$payload/"
cp "$ctl_obj/mac_abac_ctl" "$daemon_obj/mac_abacd" "$payload/bin/"
cp "$src/sys/security/mac_abac/mac_abac.h" \
	"$payload/include/security/mac_abac/"
cp "$src/share/examples/mac_abac/"* "$payload/examples/"
cp "$src/tools/test/mac-abac-qemu/guest-run.sh" "$payload/"

makefs -t cd9660 -o rockridge,label=MAC_ABAC_TESTS "$iso" "$payload"
sha256 "$iso" "$payload/mac_abac.ko"

echo "Booting a disposable snapshot. Log in as root, then run:"
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
