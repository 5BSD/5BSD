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
make -C "$src/usr.sbin/localcrypto" all
make -C "$src/usr.sbin/localcrypto/tests" all
make -C "$src/tests/sys/opencrypto" cryptodesc_test
make -C "$src/tests/sys/kern" envfd_test
make -C "$src/lib/libnotify/tests" all
make -C "$src/usr.sbin/bsdnotify" all
make -C "$src/usr.sbin/bsdnotify/tests" all
make -C "$src/usr.sbin/notifyctl/tests" all
make -C "$src/lib/libfilesystemcmp/tests" all
make -C "$src/usr.sbin/localfilesystem" all
make -C "$src/usr.sbin/localfilesystem/tests" all
make -C "$src/usr.sbin/filesystemcmpctl/tests" all
make -C "$src/usr.sbin/servicectl/tests" servicectl_test_bin
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
copy_test "$obj/usr.sbin/localcrypto/tests/bundle_test" localcrypto_bundle_test
copy_test "$obj/lib/libnotify/tests/notify_test"
copy_test "$obj/lib/libnotify/tests/client_lifecycle_test" \
	notify_client_lifecycle_test
copy_test "$obj/usr.sbin/bsdnotify/tests/broker_test" notify_broker_test
copy_test "$obj/usr.sbin/bsdnotify/tests/transport_test" notify_transport_test
copy_test "$obj/usr.sbin/bsdnotify/tests/dispatcher_test" notify_dispatcher_test
copy_test "$obj/usr.sbin/bsdnotify/tests/policy_test" notify_policy_test
copy_test "$obj/usr.sbin/bsdnotify/tests/bundle_test" notify_bundle_test
copy_test "$obj/usr.sbin/notifyctl/tests/notifyctl_test"
cp "$obj/usr.sbin/notifyctl/tests/notifyctl_test_bin" \
	"$obj/usr.sbin/notifyctl/tests/notifyctl_success_bin" \
	"$obj/usr.sbin/notifyctl/tests/valid.conf" \
	"$obj/usr.sbin/notifyctl/tests/invalid.conf" "$payload/tests/"
copy_test "$obj/lib/libfilesystemcmp/tests/filesystemcmp_test"
copy_test "$obj/lib/libfilesystemcmp/tests/path_test" filesystem_path_test
copy_test "$obj/lib/libfilesystemcmp/tests/client_lifecycle_test" \
	filesystem_client_lifecycle_test
for name in scratch_test disk_test store_test provider_test; do
	copy_test "$obj/usr.sbin/localfilesystem/tests/$name" \
	    "filesystem_$name"
done
copy_test "$obj/usr.sbin/localfilesystem/tests/bundle_test" \
	filesystem_bundle_test
copy_test "$obj/usr.sbin/filesystemcmpctl/tests/filesystemcmpctl_test"
cp "$obj/usr.sbin/filesystemcmpctl/tests/filesystemcmpctl_test_bin" \
	"$obj/usr.sbin/filesystemcmpctl/tests/filesystemcmpctl_success_bin" \
	"$payload/tests/"
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
	"$payload/source/usr.sbin/tzfs-flavors" \
	"$payload/source/usr.sbin/localcrypto/capbundle" \
	"$payload/source/usr.sbin/bsdnotify/capbundle" \
	"$payload/source/usr.sbin/localfilesystem/capbundle" \
	"$payload/source/usr.sbin/serviced" \
	"$payload/source/lib/libnotify" \
	"$payload/obj/usr.sbin/localcrypto" \
	"$payload/obj/usr.sbin/bsdnotify" \
	"$payload/obj/usr.sbin/localfilesystem" \
	"$payload/obj/usr.sbin/servicectl/tests"
cp "$src/usr.sbin/tzfsd/tzfs-mkflavor.sh" \
	"$payload/source/usr.sbin/tzfsd/"
cp "$src/usr.sbin/tzfs-flavors/tzfs-flavor-linux.sh" \
	"$payload/source/usr.sbin/tzfs-flavors/"
cp "$src/usr.sbin/localcrypto/Makefile" \
	"$src/usr.sbin/localcrypto/localcrypto.c" \
	"$payload/source/usr.sbin/localcrypto/"
cp "$src/usr.sbin/localcrypto/capbundle/crypto.ucl" \
	"$payload/source/usr.sbin/localcrypto/capbundle/"
cp "$src/usr.sbin/bsdnotify/Makefile" \
	"$src/usr.sbin/bsdnotify/bsdnotify.c" \
	"$src/usr.sbin/bsdnotify/bsdnotify_provider.d" \
	"$payload/source/usr.sbin/bsdnotify/"
cp "$src/usr.sbin/bsdnotify/capbundle/bsdnotify.ucl" \
	"$payload/source/usr.sbin/bsdnotify/capbundle/"
cp "$src/lib/libnotify/notify.c" \
	"$src/lib/libnotify/notify_provider.d" \
	"$payload/source/lib/libnotify/"
cp "$src/usr.sbin/serviced/naming.c" "$src/usr.sbin/serviced/svc_proto.c" \
	"$payload/source/usr.sbin/serviced/"
cp "$src/usr.sbin/localfilesystem/filesystemcmp.c" \
	"$src/usr.sbin/localfilesystem/localfilesystem_provider.d" \
	"$payload/source/usr.sbin/localfilesystem/"
cp "$src/usr.sbin/localfilesystem/capbundle/localfilesystem.ucl" \
	"$payload/source/usr.sbin/localfilesystem/capbundle/"
cp "$obj/usr.sbin/localcrypto/localcrypto" \
	"$payload/obj/usr.sbin/localcrypto/"
cp "$obj/usr.sbin/bsdnotify/bsdnotify" \
	"$payload/obj/usr.sbin/bsdnotify/"
cp "$obj/usr.sbin/localfilesystem/localfilesystem" \
	"$payload/obj/usr.sbin/localfilesystem/"
cp "$obj/usr.sbin/servicectl/tests/servicectl_test_bin" \
	"$payload/obj/usr.sbin/servicectl/tests/"

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
echo "After reboot into single-user mode, accept /bin/sh and run:"
echo "  mount -uw /"
echo "  mkdir -p /mnt && mount -t cd9660 /dev/cd0 /mnt"
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
