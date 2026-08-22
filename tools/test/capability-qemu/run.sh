#!/bin/sh
# Build a read-only test payload and boot it with a disposable disk snapshot.

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
obj=${OBJTOP:-/usr/obj/usr/src/amd64.amd64}
kernel_obj=${CAPABILITY_KERNEL_OBJ:-$obj/sys/VBSD}
qemu=${QEMU_BIN:-qemu-system-x86_64}
accel=${QEMU_ACCEL:-tcg,thread=multi}
memory=${QEMU_MEMORY:-4096}
cpus=${QEMU_CPUS:-4}

command -v "$qemu" >/dev/null 2>&1 || {
	echo "qemu-system-x86_64 not found; set QEMU_BIN" >&2
	exit 69
}
command -v makefs >/dev/null 2>&1 || {
	echo "makefs not found" >&2
	exit 69
}
test -f "$kernel_obj/kernel" || {
	echo "$kernel_obj does not contain a kernel" >&2
	exit 66
}

make -C "$src/lib/libcryptocmp/tests" all
make -C "$src/usr.sbin/localcrypto/tests" all
make -C "$src/tests/sys/opencrypto" cryptodesc_test
make -C "$src/tests/sys/kern" envfd_test
make -C "$src/lib/libnotifycmp/tests" all
make -C "$src/usr.sbin/bsdnotify/tests" all
make -C "$src/lib/libtrustedzfs/tests" all
make -C "$src/tests/sys/zfshandle" all
make -C "$src/tests/sys/tzfs" all

qemu_libdir=${QEMU_LIBDIR:-$(dirname "$(dirname "$qemu")")/lib}
if [ -f "$qemu_libdir/libfdt.so.1" ]; then
	LD_LIBRARY_PATH=$qemu_libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH
fi

work=${CAPABILITY_VM_WORKDIR:-$(mktemp -d /tmp/capability-qemu.XXXXXX)}
payload=$work/payload
iso=$work/capability-tests.iso
mkdir -p "$payload/tests"

copy_test()
{
	source=$1
	name=${2:-${source##*/}}
	test -x "$source" || {
		echo "missing test program: $source" >&2
		exit 66
	}
	cp "$source" "$payload/tests/$name"
}

cp "$kernel_obj/kernel" "$payload/kernel"
for module in zfs cryptodev; do
	path="$kernel_obj/modules/usr/src/sys/modules/$module/$module.ko"
	[ ! -f "$path" ] || cp "$path" "$payload/$module.ko"
done

copy_test "$obj/tests/sys/opencrypto/cryptodesc_test"
copy_test "$obj/tests/sys/kern/envfd_test"
copy_test "$obj/lib/libcryptocmp/tests/cryptocmp_api_test"
copy_test "$obj/lib/libcryptocmp/tests/client_protocol_test"
copy_test "$obj/usr.sbin/localcrypto/tests/policy_test" localcrypto_policy_test
copy_test "$obj/lib/libnotifycmp/tests/notifycmp_test"
copy_test "$obj/lib/libnotifycmp/tests/client_lifecycle_test"
copy_test "$obj/usr.sbin/bsdnotify/tests/broker_test" notify_broker_test
copy_test "$obj/usr.sbin/bsdnotify/tests/transport_test" notify_transport_test
copy_test "$obj/usr.sbin/bsdnotify/tests/dispatcher_test" notify_dispatcher_test
copy_test "$obj/usr.sbin/bsdnotify/tests/policy_test" notify_policy_test
copy_test "$obj/tests/sys/tzfs/tzfsd_config_test"
copy_test "$obj/tests/sys/tzfs/flavor_tools_test"

for name in \
	trustedzfs_capsicum_test \
	zfshandle_rights_test zfshandle_derive_test zfshandle_pin_test \
	zfshandle_phase2_test zfshandle_mount_test zfshandle_pool_test \
	zfshandle_security_test zfshandle_verbs_test zfshandle_negative_test \
	zfshandle_hardening_test tzfsd_test libtzfsd_protocol_test
do
	case "$name" in
	trustedzfs_capsicum_test)
		path="$obj/lib/libtrustedzfs/tests/$name" ;;
	zfshandle_*)
		path="$obj/tests/sys/zfshandle/$name" ;;
	*)
		path="$obj/tests/sys/tzfs/$name" ;;
	esac
	copy_test "$path"
done

# The flavor shell test references the configured source root.  Preserve that
# contract in the guest by staging only the scripts it exercises.
mkdir -p "$payload/source/usr.sbin/tzfsd" \
	"$payload/source/usr.sbin/tzfs-flavors"
cp "$src/usr.sbin/tzfsd/tzfs-mkflavor.sh" \
	"$payload/source/usr.sbin/tzfsd/"
cp "$src/usr.sbin/tzfs-flavors/tzfs-flavor-linux.sh" \
	"$payload/source/usr.sbin/tzfs-flavors/"

for library in libtrustedzfs libtzfsd; do
	dir=$(make -C "$src/lib/$library" -V .OBJDIR)
	[ ! -f "$dir/$library.so.1" ] || cp "$dir/$library.so.1" "$payload/"
done
tzfsd_obj=$(make -C "$src/usr.sbin/tzfsd" -V .OBJDIR)
[ ! -f "$tzfsd_obj/tzfsd" ] || cp "$tzfsd_obj/tzfsd" "$payload/"

cp "$src/tools/test/capability-qemu/guest-install.sh" \
	"$src/tools/test/capability-qemu/guest-run.sh" "$payload/"
makefs -t cd9660 -o rockridge,label=CAP_TESTS "$iso" "$payload"
sha256 "$iso" "$payload/kernel"

echo "Booting a disposable snapshot.  Log in as root, then run:"
echo "  mkdir -p /mnt && mount -t cd9660 /dev/cd0 /mnt"
echo "  sh /mnt/guest-install.sh /mnt"
echo "After reboot, remount the CD and run:"
echo "  sh /mnt/guest-run.sh /mnt"
echo "Payload retained at: $work"

set --
if [ -n "${QEMU_DATADIR:-}" ]; then
	set -- -L "$QEMU_DATADIR"
fi
exec "$qemu" "$@" -machine q35 -accel "$accel" \
	-cpu max -smp "$cpus" -m "$memory" -snapshot \
	-drive "file=$image,format=raw,if=virtio" \
	-drive "file=$iso,format=raw,media=cdrom,readonly=on" \
	-boot c -nic none -display none -serial stdio -monitor none
