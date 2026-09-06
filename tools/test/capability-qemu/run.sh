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

# Build the private libraries first.  Building only their consumers can leave
# an older installed private library in the object tree, producing a payload
# whose tests and runtime do not exercise the same source revision.
# Dependency order matters: a client library linked before its dependency's
# object directory is populated silently falls back to the installed copy,
# recording the wrong soname.
for library in libcapability libchannel libshmring liboraclert libservice \
    libcapbundle libtrustedzfs libtzfsd libauditcmp libcryptocmp \
    libfilesystemcmp liblogcmp libnetworkcmp libnotify libtracecmp; do
	make -C "$src/lib/$library" all
done

make -C "$src/lib/libcryptocmp/tests" all
make -C "$src/lib/libcapability/tests" all
make -C "$src/lib/libnetworkcmp/tests" all
make -C "$src/lib/liblogcmp/tests" all
make -C "$src/lib/libtracecmp/tests" all
make -C "$src/lib/libauditcmp/tests" all
make -C "$src/usr.sbin/localcrypto" all
make -C "$src/usr.sbin/localcrypto/tests" all
make -C "$src/usr.sbin/localdevice" all
make -C "$src/usr.sbin/localdevice/tests" all
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
make -C "$src/lib/libcapbundle/tests" all
make -C "$src/lib/libservice/tests" all
make -C "$src/usr.sbin/oracled" all
make -C "$src/usr.sbin/serviced" all
make -C "$src/usr.sbin/servicectl" all
make -C "$src/usr.sbin/logd" all
make -C "$src/usr.sbin/localnetwork" all
make -C "$src/usr.sbin/traced" all
make -C "$src/usr.sbin/auditbrokerd" all
make -C "$src/usr.sbin/tzfsd" all
make -C "$src/usr.sbin/serviced/tests" all
make -C "$src/usr.sbin/servicectl/tests" all
make -C "$src/usr.sbin/logd/tests" all
make -C "$src/usr.sbin/localnetwork/tests" all
make -C "$src/usr.sbin/traced/tests" all
make -C "$src/usr.sbin/auditbrokerd/tests" all

qemu_libdir=${QEMU_LIBDIR:-$(dirname "$(dirname "$qemu")")/lib}
if [ -f "$qemu_libdir/libfdt.so.1" ]; then
	LD_LIBRARY_PATH=$qemu_libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH
fi

work=${CAPABILITY_VM_WORKDIR:-$(mktemp -d /tmp/capability-qemu.XXXXXX)}
payload=$work/payload
iso=$work/capability-tests.iso
mkdir -p "$payload/tests"
: > "$payload/test-programs"

copy_test()
{
	source=$1
	name=${2:-${source##*/}}
	test -x "$source" || {
		echo "missing test program: $source" >&2
		exit 66
	}
	cp "$source" "$payload/tests/$name"
	echo "$name" >> "$payload/test-programs"
}

copy_atf()
{
	copy_test "$1" "${2:-${1##*/}}"
}

copy_obj_helper()
{
	source=$1
	destination=$2
	test -x "$source" || {
		echo "missing helper program: $source" >&2
		exit 66
	}
	mkdir -p "$(dirname "$payload/obj/$destination")"
	cp "$source" "$payload/obj/$destination"
}

cp "$kernel_obj/kernel" "$payload/kernel"
for module in zfs cryptodev; do
	path="$kernel_obj/modules/usr/src/sys/modules/$module/$module.ko"
	[ ! -f "$path" ] || cp "$path" "$payload/$module.ko"
done
for module_path in "$kernel_obj"/modules/usr/src/sys/modules/mac_capability*/*.ko \
    "$kernel_obj"/modules/usr/src/sys/modules/zfshandle/*.ko; do
	[ ! -f "$module_path" ] || cp "$module_path" "$payload/"
done

copy_test "$obj/tests/sys/opencrypto/cryptodesc_test"
copy_test "$obj/tests/sys/kern/envfd_test"
copy_test "$obj/lib/libcapability/tests/libcapability_test"
copy_test "$obj/lib/libcryptocmp/tests/cryptocmp_api_test"
copy_test "$obj/lib/libcryptocmp/tests/client_protocol_test"
copy_test "$obj/usr.sbin/localcrypto/tests/policy_test" localcrypto_policy_test
copy_test "$obj/usr.sbin/localcrypto/tests/bundle_test" localcrypto_bundle_test
copy_test "$obj/usr.sbin/localdevice/tests/policy_test" localdevice_policy_test
copy_atf "$obj/usr.sbin/localdevice/tests/provider_test" device_provider_test
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
for spec in \
    "lib/libnetworkcmp/tests/networkcmp_test:networkcmp_api_test" \
    "lib/libnetworkcmp/tests/client_lifecycle_test:networkcmp_client_lifecycle_test" \
    "lib/liblogcmp/tests/logcmp_test:logcmp_api_test" \
    "lib/liblogcmp/tests/client_lifecycle_test:logcmp_client_lifecycle_test" \
    "lib/libtracecmp/tests/tracecmp_test:tracecmp_api_test" \
    "lib/libtracecmp/tests/client_lifecycle_test:tracecmp_client_lifecycle_test" \
    "lib/libauditcmp/tests/auditcmp_test:auditcmp_api_test" \
    "lib/libauditcmp/tests/client_lifecycle_test:auditcmp_client_lifecycle_test"
do
	from=${spec%%:*}
	to=${spec#*:}
	copy_test "$obj/$from" "$to"
done
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

# Bundle, bootstrap, service-manager, and control-plane qualification.
for name in api_test storage_key_test; do
	copy_atf "$obj/lib/libcapbundle/tests/$name" "capbundle_$name"
done
copy_atf "$obj/lib/libcapbundle/tests/capbundle_format_test"
copy_atf "$obj/lib/libservice/tests/libservice_api_test"
copy_atf "$obj/lib/libservice/tests/libservice_test"
for name in fd_budget_test launch_limits_test manifest_compare_test \
    bundle_selection_test storage_lifecycle_test on_demand_test rc_ingest_test \
    serviced_integration_test bundle_integration_test component_integration_test \
    component_examples_test serviced_svc_test serviced_naming_test \
    serviced_dynamic_claims_test; do
	copy_atf "$obj/usr.sbin/serviced/tests/$name"
done
copy_atf "$obj/usr.sbin/servicectl/tests/servicectl_test"
copy_atf "$obj/usr.sbin/servicectl/tests/transport_test" \
    servicectl_transport_test
copy_atf "$obj/usr.sbin/logd/tests/provider_test" logd_provider_test
copy_atf "$obj/usr.sbin/logd/tests/bundle_test" logd_bundle_test
for name in config_test session_test store_test storage_test; do
	copy_atf "$obj/usr.sbin/logd/tests/$name" "logd_$name"
done
copy_atf "$obj/usr.sbin/localnetwork/tests/provider_test" \
    network_provider_test
copy_atf "$obj/usr.sbin/localnetwork/tests/bundle_test" \
    network_bundle_test
for name in session_test io_test policy_test; do
	copy_atf "$obj/usr.sbin/localnetwork/tests/$name" "network_$name"
done
copy_atf "$obj/usr.sbin/traced/tests/session_test" trace_session_test
copy_atf "$obj/usr.sbin/traced/tests/bundle_test" trace_bundle_test
copy_atf "$obj/usr.sbin/traced/tests/policy_test" trace_policy_test
for name in policy_test rate_test submit_test session_test bundle_test; do
	copy_atf "$obj/usr.sbin/auditbrokerd/tests/$name" "audit_$name"
done

# The shell integration programs locate these helpers by their source-build
# paths.  Keep helpers out of tests/ so the ATF enumerator never mistakes one
# for a test program.
for spec in \
    "usr.sbin/oracled/oracled:usr.sbin/oracled/oracled" \
    "usr.sbin/serviced/serviced:usr.sbin/serviced/serviced" \
    "usr.sbin/tzfsd/tzfsd:usr.sbin/tzfsd/tzfsd" \
    "usr.sbin/servicectl/servicectl:usr.sbin/servicectl/servicectl" \
    "usr.sbin/servicectl/tests/servicectl_test_bin:usr.sbin/servicectl/tests/servicectl_test_bin" \
    "usr.sbin/serviced/tests/capd_test_guardian:usr.sbin/serviced/tests/capd_test_guardian" \
    "usr.sbin/serviced/tests/capd_service_fixture:usr.sbin/serviced/tests/capd_service_fixture" \
    "usr.sbin/serviced/tests/capd_protocol_fixture:usr.sbin/serviced/tests/capd_protocol_fixture" \
    "usr.sbin/serviced/tests/component_fixture:usr.sbin/serviced/tests/component_fixture" \
    "usr.sbin/localcrypto/localcrypto:usr.sbin/localcrypto/localcrypto" \
    "usr.sbin/localdevice/localdevice:usr.sbin/localdevice/localdevice" \
    "usr.sbin/localfilesystem/localfilesystem:usr.sbin/localfilesystem/localfilesystem" \
    "usr.sbin/localnetwork/localnetwork:usr.sbin/localnetwork/localnetwork" \
    "usr.sbin/logd/logd:usr.sbin/logd/logd" \
    "usr.sbin/bsdnotify/bsdnotify:usr.sbin/bsdnotify/bsdnotify" \
    "usr.sbin/traced/traced:usr.sbin/traced/traced" \
    "usr.sbin/auditbrokerd/auditbrokerd:usr.sbin/auditbrokerd/auditbrokerd"
do
	from=${spec%%:*}
	to=${spec#*:}
	copy_obj_helper "$obj/$from" "$to"
done
for helper in capd_test_guardian capd_service_fixture capd_protocol_fixture \
    component_fixture; do
	cp "$obj/usr.sbin/serviced/tests/$helper" "$payload/tests/$helper"
done
for helper in deps_network_fixture deps_both_fixture servicectl_test_bin; do
	cp "$obj/usr.sbin/servicectl/tests/$helper" "$payload/tests/$helper"
done
cp "$obj/usr.sbin/serviced/tests/test_helpers.sh" \
    "$obj/usr.sbin/serviced/tests/capd_test_harness.sh" \
    "$payload/tests/"

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

# Several shell integration tests reference the configured source root.
# Preserve that contract in the guest by staging only the files they exercise.
mkdir -p "$payload/source/usr.sbin/localcrypto/capbundle" \
	"$payload/source/usr.sbin/localdevice/capbundle" \
	"$payload/source/usr.sbin/bsdnotify/capbundle" \
	"$payload/source/usr.sbin/localfilesystem/capbundle" \
	"$payload/source/usr.sbin/serviced" \
	"$payload/source/lib/libnotify" \
	"$payload/obj/usr.sbin/localcrypto" \
	"$payload/obj/usr.sbin/localdevice" \
	"$payload/obj/usr.sbin/bsdnotify" \
	"$payload/obj/usr.sbin/localfilesystem" \
	"$payload/obj/usr.sbin/servicectl/tests"
cp "$src/usr.sbin/localcrypto/Makefile" \
	"$src/usr.sbin/localcrypto/localcrypto.c" \
	"$payload/source/usr.sbin/localcrypto/"
cp "$src/usr.sbin/localcrypto/capbundle/crypto.ucl" \
	"$payload/source/usr.sbin/localcrypto/capbundle/"
cp "$src/usr.sbin/localdevice/Makefile" \
	"$src/usr.sbin/localdevice/localdevice.c" \
	"$payload/source/usr.sbin/localdevice/"
cp "$src/usr.sbin/localdevice/capbundle/device.ucl" \
	"$payload/source/usr.sbin/localdevice/capbundle/"
cp "$src/usr.sbin/bsdnotify/Makefile" \
	"$src/usr.sbin/bsdnotify/bsdnotify.c" \
	"$src/usr.sbin/bsdnotify/bsdnotify_provider.d" \
	"$payload/source/usr.sbin/bsdnotify/"
cp "$src/usr.sbin/bsdnotify/capbundle/bsdnotify.ucl" \
	"$src/usr.sbin/bsdnotify/capbundle/bsdnotify.conf" \
	"$payload/source/usr.sbin/bsdnotify/capbundle/"
# Global-service integration cases build bare provider bundles and stage the
# daemon's managed config from the source tree; ship the ones they reference.
mkdir -p "$payload/source/usr.sbin/logd/capbundle"
cp "$src/usr.sbin/logd/capbundle/logd.conf" \
	"$payload/source/usr.sbin/logd/capbundle/"
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
cp "$obj/usr.sbin/localdevice/localdevice" \
	"$payload/obj/usr.sbin/localdevice/"
cp "$obj/usr.sbin/bsdnotify/bsdnotify" \
	"$payload/obj/usr.sbin/bsdnotify/"
cp "$obj/usr.sbin/localfilesystem/localfilesystem" \
	"$payload/obj/usr.sbin/localfilesystem/"
cp "$obj/usr.sbin/servicectl/tests/servicectl_test_bin" \
	"$payload/obj/usr.sbin/servicectl/tests/"

# Source-backed shell assertions and generated helpers used by the expanded
# service-manager suite.
mkdir -p "$payload/source/usr.sbin" "$payload/source/lib" \
    "$payload/source/packages" "$payload/source/etc"
for path in usr.sbin/serviced usr.sbin/servicectl usr.sbin/logd \
    usr.sbin/bsdnotify usr.sbin/localcrypto usr.sbin/localdevice \
    usr.sbin/localfilesystem \
    usr.sbin/localnetwork usr.sbin/traced usr.sbin/auditbrokerd \
    lib/libcapbundle lib/libservice lib/libnotify; do
	mkdir -p "$payload/source/$(dirname "$path")"
	cp -R "$src/$path" "$payload/source/$(dirname "$path")/"
done
# Observability tests inspect both halves of each provider definition.
for path in lib/liblogcmp lib/libtracecmp; do
	mkdir -p "$payload/source/$(dirname "$path")"
	cp -R "$src/$path" "$payload/source/$(dirname "$path")/"
done
cp "$src/etc/master.passwd" "$src/etc/group" "$payload/source/etc/"
cp "$src/ObsoleteFiles.inc" "$payload/source/"

# Source-contract fixtures: the component-examples suite asserts against
# these exact source paths.  Copy only when present — several assertions
# verify that a path stays deleted.
for path in \
    Makefile.inc1 \
    contrib/openbsm/etc/audit_event \
    etc/mtree/BSD.tests.dist \
    etc/mtree/BSD.var.dist \
    lib/Makefile \
    lib/libauditcmp \
    lib/libchannel \
    lib/libfilesystemcmp \
    lib/libnetworkcmp \
    lib/liboraclectl \
    lib/libshmring \
    libexec/rc \
    packages \
    release/packages \
    share/mk/src.libnames.mk \
    contrib/openbsm/libbsm/bsm_wrappers.c \
    sys/bsm/audit_kevents.h \
    sys/kern/syscalls.master \
    sys/security/audit/audit_syscalls.c \
    usr.sbin/bluetooth/blued/Makefile \
    usr.sbin/bluetooth/blued/blued.ucl \
    usr.sbin/oracled/Makefile \
    usr.sbin/oracled/oracled.conf \
    usr.sbin/oracled/oracled.conf.5; do
	[ -e "$src/$path" ] || continue
	mkdir -p "$payload/source/$(dirname "$path")"
	cp -R "$src/$path" "$payload/source/$(dirname "$path")/"
done

# Install current private libraries in the disposable guest so dynamically
# linked managers and provider fixtures use the same ABI as the test payload.
mkdir -p "$payload/libs"
for library in libauditcmp libcapability libcapbundle libchannel libcryptocmp \
    libfilesystemcmp liblogcmp libnetworkcmp libnotify liboraclert libservice \
    libshmring libtracecmp libtrustedzfs libtzfsd; do
	dir=$(make -C "$src/lib/$library" -V .OBJDIR)
	# Stage only the current major.  After an SHLIB_MAJOR bump the object
	# directory still holds the previous .so.N; a wildcard would ship a
	# stale library carrying the wrong ABI under the old soname.
	soname=$(readlink "$dir/$library.so") || {
		echo "cannot resolve current soname for $library" >&2
		exit 66
	}
	for shared in "$dir/$soname" "$dir/$soname.debug" "$dir/$soname.full"; do
		[ ! -f "$shared" ] || cp "$shared" "$payload/libs/"
	done
done

for library in libtrustedzfs libtzfsd; do
	dir=$(make -C "$src/lib/$library" -V .OBJDIR)
	[ ! -f "$dir/$library.so.1" ] || cp "$dir/$library.so.1" "$payload/"
done
tzfsd_obj=$(make -C "$src/usr.sbin/tzfsd" -V .OBJDIR)
[ ! -f "$tzfsd_obj/tzfsd" ] || cp "$tzfsd_obj/tzfsd" "$payload/"

# Stage the current component bundles so the guest's installed
# /Capabilities/System matches the staged daemons and parser.  The guest
# otherwise keeps the base image's bundles, which age out of step with the
# bundle schema under test.
world="$work/world"
rm -rf "$world"
mkdir -p "$world/usr/share/man/man5" "$world/usr/share/man/man8" \
    "$world/usr/sbin" "$world/usr/libexec"
: > "$work/world.meta"
make -C "$src/usr.sbin/bluetooth/blued" all
for daemon in localcrypto localdevice bsdnotify localfilesystem localnetwork logd \
    traced auditbrokerd bluetooth/blued; do
	make -C "$src/usr.sbin/$daemon" install installconfig \
	    DESTDIR="$world" -DNO_ROOT METALOG="$work/world.meta" \
	    INSTALL="install -U -M $work/world.meta -D $world" >/dev/null
done
mkdir -p "$payload/capabilities"
cp -R "$world/Capabilities/System" "$payload/capabilities/"

cp "$src/tools/test/capability-qemu/guest-install.sh" \
	"$src/tools/test/capability-qemu/guest-run.sh" "$payload/"

# Kyua is part of the guest base system.  Generate a suite definition so the
# guest gets its user, kmod, timeout, isolation, and cleanup semantics instead
# of approximating ATF by invoking each test program directly.
{
	echo 'syntax(2)'
	echo 'test_suite("capability")'
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		printf 'atf_test_program{name="%s"}\n' "$name"
	done < "$payload/test-programs"
} > "$payload/Kyuafile"

# Refuse to ship a payload whose binaries need a different major of a staged
# private library: a stale, un-relinked consumer reintroduces exactly the ABI
# skew this harness exists to catch.
sonames="$work/sonames.txt"
: > "$sonames"
for library in libauditcmp libcapability libcapbundle libchannel libcryptocmp \
    libfilesystemcmp liblogcmp libnetworkcmp libnotify liboraclert libservice \
    libshmring libtracecmp libtrustedzfs libtzfsd; do
	dir=$(make -C "$src/lib/$library" -V .OBJDIR)
	printf '%s %s\n' "$library" "$(readlink "$dir/$library.so")" >> "$sonames"
done
stale=0
for bin in $(find "$payload/tests" "$payload/obj" "$payload" -maxdepth 3 \
    -type f -perm -0100 2>/dev/null); do
	needed=$(readelf -d "$bin" 2>/dev/null | \
	    sed -n 's/.*NEEDED.*\[\(lib[a-z]*\.so\.[0-9]*\)\].*/\1/p')
	[ -n "$needed" ] || continue
	for entry in $needed; do
		library=${entry%%.so.*}
		want=$(awk -v l="$library" '$1 == l { print $2 }' "$sonames")
		[ -n "$want" ] || continue
		if [ "$entry" != "$want" ]; then
			echo "STALE: $bin needs $entry, staged $want" >&2
			stale=1
		fi
	done
done
if [ "$stale" -ne 0 ]; then
	echo "stale consumers detected — clean and rebuild the offenders" >&2
	exit 65
fi

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
