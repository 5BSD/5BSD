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
cpu=${QEMU_CPU:-max}

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
if [ "${CAPABILITY_VM_SKIP_BUILD:-no}" != yes ]; then
for library in libcapability libchannel libshmring libcapsulert libservice \
    libcapbundle libtrustedzfs libbsdfilesystem libauditcmp libcryptodesc \
    libcryptocmp libdevicecmp \
    libsysctlcmp liblogcmp libnetworkcmp libnotify libtracecmp; do
	make -C "$src/lib/$library" all
done

for tests in \
    lib/libauditcmp lib/libcapsulert lib/libcapability lib/libcapbundle \
    lib/libcryptocmp lib/libcryptodesc lib/libdevicecmp \
    lib/liblogcmp lib/libnetworkcmp lib/libnotify \
    lib/libservice lib/libshmring lib/libsysctlcmp lib/libtracecmp \
    lib/libtrustedzfs lib/libbsdfilesystem; do
	make -C "$src/$tests/tests" all
done
for component in \
    usr.sbin/bsdaudit usr.sbin/authagentd usr.sbin/capsulectl \
    usr.sbin/capsule \
    usr.sbin/bsdnotify usr.sbin/bsdcrypto usr.sbin/bsddevice \
    usr.sbin/bsdnetwork usr.sbin/bsdsysctl usr.sbin/logctl \
    usr.sbin/bsdlog usr.sbin/networkcmpctl usr.sbin/notifyctl \
    usr.sbin/switchboardctl usr.sbin/switchboard usr.sbin/sysctlcmpctl \
    usr.sbin/tracectl usr.sbin/traced usr.sbin/tzfsctl usr.sbin/bsdfilesystem; do
	make -C "$src/$component" all
	make -C "$src/$component/tests" all
done
make -C "$src/tests/sys/opencrypto" cryptodesc_test
make -C "$src/tests/sys/kern" envfd_test
make -C "$src/tests/sys/zfshandle" all
make -C "$src/tests/sys/tzfs" all
fi

qemu_libdir=${QEMU_LIBDIR:-$(dirname "$(dirname "$qemu")")/lib}
if [ -f "$qemu_libdir/libfdt.so.1" ]; then
	LD_LIBRARY_PATH=$qemu_libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH
fi

work=${CAPABILITY_VM_WORKDIR:-$(mktemp -d /tmp/capability-qemu.XXXXXX)}
payload=$work/payload
iso=$work/capability-tests.iso
if [ -e "$payload" ] || [ -e "$iso" ]; then
	echo "CAPABILITY_VM_WORKDIR already contains a staged payload: $work" >&2
	exit 73
fi
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
for spec in zfs:zfs cryptodev:cryptodev linux_common:linux_common \
    linux64:linux64 mqueue:mqueuefs pty:pty fdescfs:fdescfs \
    linprocfs:linprocfs linsysfs:linsysfs hwt:hwt; do
	module_dir=${spec%:*}
	module=${spec#*:}
	path="$kernel_obj/modules$src/sys/modules/$module_dir/$module.ko"
	test -f "$path" || {
		echo "missing kernel module: $path" >&2
		exit 66
	}
	cp "$path" "$payload/$module.ko"
done
for module_path in "$kernel_obj/modules$src/sys/modules"/mac_capability*/*.ko \
    "$kernel_obj/modules$src/sys/modules"/zfshandle/*.ko; do
	[ ! -f "$module_path" ] || cp "$module_path" "$payload/"
done

copy_test "$obj/tests/sys/opencrypto/cryptodesc_test"
copy_test "$obj/tests/sys/kern/envfd_test"
copy_test "$obj/lib/libcapability/tests/libcapability_test"
copy_test "$obj/lib/libcryptodesc/tests/cryptodesc_api_test"
copy_test "$obj/lib/libdevicecmp/tests/devicecmp_api_test"
copy_test "$obj/lib/libdevicecmp/tests/client_protocol_test" \
    devicecmp_client_protocol_test
copy_test "$obj/lib/libcryptocmp/tests/cryptocmp_api_test"
copy_test "$obj/lib/libcryptocmp/tests/client_protocol_test"
copy_test "$obj/usr.sbin/BSDCrypto/tests/policy_test" bsdcrypto_policy_test
copy_test "$obj/usr.sbin/BSDCrypto/tests/bundle_test" bsdcrypto_bundle_test
copy_test "$obj/usr.sbin/BSDDevice/tests/policy_test" bsddevice_policy_test
copy_atf "$obj/usr.sbin/BSDDevice/tests/provider_test" device_provider_test
copy_test "$obj/lib/libnotify/tests/notify_test"
copy_test "$obj/lib/libnotify/tests/client_lifecycle_test" \
	notify_client_lifecycle_test
copy_test "$obj/usr.sbin/BSDNotify/tests/broker_test" notify_broker_test
copy_test "$obj/usr.sbin/BSDNotify/tests/transport_test" notify_transport_test
copy_test "$obj/usr.sbin/BSDNotify/tests/dispatcher_test" notify_dispatcher_test
copy_test "$obj/usr.sbin/BSDNotify/tests/policy_test" notify_policy_test
copy_test "$obj/usr.sbin/BSDNotify/tests/bundle_test" notify_bundle_test
copy_test "$obj/usr.sbin/notifyctl/tests/notifyctl_test"
cp "$obj/usr.sbin/notifyctl/tests/notifyctl_test_bin" \
	"$obj/usr.sbin/notifyctl/tests/notifyctl_success_bin" "$payload/tests/"
sed -i "" \
	-e 's,)/valid\.conf,)/notifyctl-valid.conf,g' \
	-e 's,)/invalid\.conf,)/notifyctl-invalid.conf,g' \
	"$payload/tests/notifyctl_test"
cp "$obj/usr.sbin/notifyctl/tests/valid.conf" \
	"$payload/tests/notifyctl-valid.conf"
cp "$obj/usr.sbin/notifyctl/tests/invalid.conf" \
	"$payload/tests/notifyctl-invalid.conf"
copy_test "$obj/lib/libsysctlcmp/tests/sysctlcmp_test"
copy_test "$obj/lib/libsysctlcmp/tests/client_strings_test"
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
copy_test "$obj/usr.sbin/BSDSysctl/tests/config_test" bsdsysctl_config_test
copy_test "$obj/usr.sbin/BSDSysctl/tests/provider_test" bsdsysctl_provider_test
copy_test "$obj/usr.sbin/sysctlcmpctl/tests/sysctlcmpctl_test"
cp "$obj/usr.sbin/sysctlcmpctl/tests/sysctlcmpctl_success_bin" \
	"$payload/tests/"
copy_test "$obj/tests/sys/tzfs/bsdfilesystem_config_test"
copy_test "$obj/lib/libcapsulert/tests/claim_parse_test"
copy_test "$obj/lib/libshmring/tests/shmring_test"
copy_test "$obj/lib/libbsdfilesystem/tests/bsdfilesystem_test" libbsdfilesystem_test
copy_test "$obj/usr.sbin/BSDFilesystem/tests/namespace_test" bsdfilesystem_namespace_test
copy_test "$obj/usr.sbin/BSDFilesystem/tests/provider_test" bsdfilesystem_provider_test
copy_test "$obj/usr.sbin/capsulectl/tests/capsulectl_test"
cp "$obj/usr.sbin/capsulectl/tests/capsulectl_test_bin" \
	"$obj/usr.sbin/capsulectl/tests/capsulectl_success_bin" \
	"$payload/tests/"
copy_test "$obj/usr.sbin/networkcmpctl/tests/networkcmpctl_test"
cp "$obj/usr.sbin/networkcmpctl/tests/networkcmpctl_test_bin" \
	"$obj/usr.sbin/networkcmpctl/tests/networkcmpctl_success_bin" \
	"$payload/tests/"
copy_test "$obj/usr.sbin/logctl/tests/logctl_test"
cp "$obj/usr.sbin/logctl/tests/logctl_test_bin" \
	"$obj/usr.sbin/logctl/tests/logctl_success_bin" "$payload/tests/"
sed -i "" \
	-e 's,)/valid\.conf,)/logctl-valid.conf,g' \
	-e 's,)/invalid\.conf,)/logctl-invalid.conf,g' \
	"$payload/tests/logctl_test"
cp "$obj/usr.sbin/logctl/tests/valid.conf" \
	"$payload/tests/logctl-valid.conf"
cp "$obj/usr.sbin/logctl/tests/invalid.conf" \
	"$payload/tests/logctl-invalid.conf"
copy_test "$obj/usr.sbin/tracectl/tests/tracectl_test"
cp "$obj/usr.sbin/tracectl/tests/tracectl_test_bin" "$payload/tests/"
copy_test "$obj/usr.sbin/tzfsctl/tests/tzfsctl_test"
cp "$obj/usr.sbin/tzfsctl/tests/tzfsctl_success_bin" "$payload/tests/"

# Bundle, bootstrap, service-manager, and control-plane qualification.
for name in api_test manifest_activation_test management_test \
    principal_policy_test manifest_policy_test sysctl_isolate_test; do
	copy_atf "$obj/lib/libcapbundle/tests/$name" "capbundle_$name"
done
copy_atf "$obj/lib/libcapbundle/tests/capbundle_format_test"
cp "$obj/lib/libcapbundle/tests/switchboardctl" "$payload/tests/"
for name in libservice_api_test libservice_test service_ambient_test \
    reclaim_msg_test ambient_lookup_test; do
	copy_atf "$obj/lib/libservice/tests/$name"
done
for name in activation_test domain_test on_demand_test fd_budget_test \
    launch_limits_test manifest_compare_test management_enforce_test \
    bundle_selection_test label_lifecycle_test rc_ingest_test rc_adopt_test \
    activation_calendar_test ambient_hygiene_test sctl_gate_test \
    reclaim_gate_test register_lookup_gate_test reclaim_bridge_test \
    switchboard_naming_test switchboard_svc_test switchboard_integration_test \
    switchboard_dynamic_claims_test bundle_integration_test helper_integration_test \
    service_reachability_test; do
	copy_atf "$obj/usr.sbin/switchboard/tests/$name"
done
copy_atf "$obj/usr.sbin/switchboardctl/tests/switchboardctl_test"
copy_atf "$obj/usr.sbin/BSDLog/tests/provider_test" bsdlog_provider_test
copy_atf "$obj/usr.sbin/BSDLog/tests/bundle_test" bsdlog_bundle_test
for name in config_test session_test store_test storage_test; do
	copy_atf "$obj/usr.sbin/BSDLog/tests/$name" "bsdlog_$name"
done
copy_atf "$obj/usr.sbin/BSDNetwork/tests/provider_test" \
    network_provider_test
copy_atf "$obj/usr.sbin/BSDNetwork/tests/bundle_test" \
    network_bundle_test
for name in config_test policy_test; do
	copy_atf "$obj/usr.sbin/BSDNetwork/tests/$name" "network_$name"
done
copy_atf "$obj/usr.sbin/BSDTrace/tests/session_test" trace_session_test
copy_atf "$obj/usr.sbin/BSDTrace/tests/bundle_test" trace_bundle_test
copy_atf "$obj/usr.sbin/BSDTrace/tests/policy_test" trace_policy_test
for name in policy_test rate_test submit_test session_test bundle_test; do
	copy_atf "$obj/usr.sbin/BSDAudit/tests/$name" "audit_$name"
done
for name in gate_test identity_test mint_decision_test provider_test; do
	copy_atf "$obj/usr.sbin/BSDAuth/tests/$name" "authagent_$name"
done

# The shell integration programs locate these helpers by their source-build
# paths.  Keep helpers out of tests/ so the ATF enumerator never mistakes one
# for a test program.
for spec in \
    "usr.sbin/capsule/capsule:usr.sbin/capsule/capsule" \
    "usr.sbin/capsulectl/capsulectl:usr.sbin/capsulectl/capsulectl" \
    "usr.sbin/switchboard/switchboard:usr.sbin/switchboard/switchboard" \
    "usr.sbin/BSDFilesystem/bsdfilesystem:usr.sbin/BSDFilesystem/bsdfilesystem" \
    "usr.sbin/switchboardctl/switchboardctl:usr.sbin/switchboardctl/switchboardctl" \
    "usr.sbin/switchboardctl/tests/switchboardctl_test_bin:usr.sbin/switchboardctl/tests/switchboardctl_test_bin" \
    "usr.sbin/switchboardctl/tests/switchboardctl_success_bin:usr.sbin/switchboardctl/tests/switchboardctl_success_bin" \
    "usr.sbin/switchboard/tests/capd_test_guardian:usr.sbin/switchboard/tests/capd_test_guardian" \
    "lib/libservice/tests/capd_service_fixture:usr.sbin/switchboard/tests/capd_service_fixture" \
    "usr.sbin/switchboard/tests/capd_protocol_fixture:usr.sbin/switchboard/tests/capd_protocol_fixture" \
    "usr.sbin/switchboard/tests/service_probe:usr.sbin/switchboard/tests/service_probe" \
    "usr.sbin/BSDCrypto/bsdcrypto:usr.sbin/BSDCrypto/bsdcrypto" \
    "usr.sbin/BSDDevice/bsddevice:usr.sbin/BSDDevice/bsddevice" \
    "usr.sbin/BSDSysctl/bsdsysctl:usr.sbin/BSDSysctl/bsdsysctl" \
    "usr.sbin/BSDNetwork/bsdnetwork:usr.sbin/BSDNetwork/bsdnetwork" \
    "usr.sbin/BSDLog/bsdlog:usr.sbin/BSDLog/bsdlog" \
    "usr.sbin/BSDNotify/bsdnotify:usr.sbin/BSDNotify/bsdnotify" \
    "usr.sbin/BSDTrace/traced:usr.sbin/BSDTrace/traced" \
    "usr.sbin/BSDAuth/authagentd:usr.sbin/BSDAuth/authagentd" \
    "usr.sbin/BSDAudit/bsdaudit:usr.sbin/BSDAudit/bsdaudit"
do
	from=${spec%%:*}
	to=${spec#*:}
	copy_obj_helper "$obj/$from" "$to"
done
for helper in capd_test_guardian capd_protocol_fixture service_probe; do
	cp "$obj/usr.sbin/switchboard/tests/$helper" "$payload/tests/$helper"
done
cp "$obj/lib/libservice/tests/capd_service_fixture" \
    "$payload/tests/capd_service_fixture"
cp "$obj/usr.sbin/switchboardctl/tests/switchboardctl_test_bin" \
    "$obj/usr.sbin/switchboardctl/tests/switchboardctl_success_bin" \
    "$payload/tests/"
cp "$obj/usr.sbin/switchboard/tests/test_helpers.sh" \
    "$obj/usr.sbin/switchboard/tests/capd_test_harness.sh" \
    "$payload/tests/"

for name in \
	trustedzfs_capsicum_test \
	zfshandle_rights_test zfshandle_derive_test zfshandle_pin_test \
	zfshandle_phase2_test zfshandle_mount_test zfshandle_pool_test \
	zfshandle_security_test zfshandle_verbs_test zfshandle_negative_test \
	zfshandle_hardening_test
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
mkdir -p "$payload/source/usr.sbin/BSDCrypto/capbundle" \
	"$payload/source/usr.sbin/BSDDevice/capbundle" \
	"$payload/source/usr.sbin/BSDNotify/capbundle" \
	"$payload/source/usr.sbin/BSDSysctl/capbundle" \
	"$payload/source/usr.sbin/switchboard" \
	"$payload/source/lib/libnotify" \
	"$payload/obj/usr.sbin/bsdcrypto" \
	"$payload/obj/usr.sbin/bsddevice" \
	"$payload/obj/usr.sbin/bsdnotify" \
	"$payload/obj/usr.sbin/bsdsysctl" \
	"$payload/obj/usr.sbin/switchboardctl/tests"
cp "$src/usr.sbin/BSDCrypto/Makefile" \
	"$src/usr.sbin/BSDCrypto/bsdcrypto.c" \
	"$payload/source/usr.sbin/BSDCrypto/"
cp "$src/usr.sbin/BSDCrypto/capbundle/crypto.ucl" \
	"$payload/source/usr.sbin/BSDCrypto/capbundle/"
cp "$src/usr.sbin/BSDDevice/Makefile" \
	"$src/usr.sbin/BSDDevice/bsddevice.c" \
	"$payload/source/usr.sbin/BSDDevice/"
cp "$src/usr.sbin/BSDDevice/capbundle/device.ucl" \
	"$payload/source/usr.sbin/BSDDevice/capbundle/"
cp "$src/usr.sbin/BSDNotify/Makefile" \
	"$src/usr.sbin/BSDNotify/bsdnotify.c" \
	"$src/usr.sbin/BSDNotify/bsdnotify_provider.d" \
	"$payload/source/usr.sbin/BSDNotify/"
cp "$src/usr.sbin/BSDNotify/capbundle/bsdnotify.ucl" \
	"$src/usr.sbin/BSDNotify/capbundle/bsdnotify.conf" \
	"$payload/source/usr.sbin/BSDNotify/capbundle/"
# Global-service integration cases build bare provider bundles and stage the
# daemon's managed config from the source tree; ship the ones they reference.
mkdir -p "$payload/source/usr.sbin/BSDLog/capbundle"
cp "$src/usr.sbin/BSDLog/capbundle/bsdlog.conf" \
	"$payload/source/usr.sbin/BSDLog/capbundle/"
cp "$src/lib/libnotify/notify.c" \
	"$src/lib/libnotify/notify_provider.d" \
	"$payload/source/lib/libnotify/"
cp "$src/usr.sbin/switchboard/naming.c" "$src/usr.sbin/switchboard/svc_proto.c" \
	"$payload/source/usr.sbin/switchboard/"
cp "$src/usr.sbin/BSDSysctl/capbundle/bsdsysctl.ucl" \
	"$payload/source/usr.sbin/BSDSysctl/capbundle/"
cp "$obj/usr.sbin/BSDCrypto/bsdcrypto" \
	"$payload/obj/usr.sbin/BSDCrypto/"
cp "$obj/usr.sbin/BSDDevice/bsddevice" \
	"$payload/obj/usr.sbin/BSDDevice/"
cp "$obj/usr.sbin/BSDNotify/bsdnotify" \
	"$payload/obj/usr.sbin/BSDNotify/"
cp "$obj/usr.sbin/BSDSysctl/bsdsysctl" \
	"$payload/obj/usr.sbin/BSDSysctl/"
cp "$obj/usr.sbin/switchboardctl/tests/switchboardctl_test_bin" \
    "$obj/usr.sbin/switchboardctl/tests/switchboardctl_success_bin" \
	"$payload/obj/usr.sbin/switchboardctl/tests/"

# Source-backed shell assertions and generated helpers used by the expanded
# service-manager suite.
mkdir -p "$payload/source/usr.sbin" "$payload/source/lib" \
    "$payload/source/packages" "$payload/source/etc"
for path in usr.sbin/switchboard usr.sbin/switchboardctl usr.sbin/bsdlog \
    usr.sbin/bsdnotify usr.sbin/bsdcrypto usr.sbin/bsddevice \
    usr.sbin/bsdsysctl \
    usr.sbin/bsdnetwork usr.sbin/traced usr.sbin/bsdaudit \
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
    lib/libcryptodesc \
    lib/libdevicecmp \
    lib/libsysctlcmp \
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
    usr.sbin/bluetooth/BSDBluetooth/Makefile \
    usr.sbin/bluetooth/BSDBluetooth/blued.ucl \
    usr.sbin/capsule/Makefile \
    usr.sbin/capsule/capsule-daemon.conf \
    usr.sbin/capsule/capsule-loader.conf \
    usr.sbin/capsule/capsule.conf.5; do
	[ -e "$src/$path" ] || continue
	mkdir -p "$payload/source/$(dirname "$path")"
	cp -R "$src/$path" "$payload/source/$(dirname "$path")/"
done

# Install current private libraries in the disposable guest so dynamically
# linked managers and provider fixtures use the same ABI as the test payload.
mkdir -p "$payload/libs"
for library in libauditcmp libcapability libcapbundle libchannel libcryptodesc \
    libcryptocmp libdevicecmp libsysctlcmp liblogcmp libnetworkcmp \
    libnotify libcapsulert libservice \
    libshmring libtracecmp libtrustedzfs libbsdfilesystem; do
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

for library in libtrustedzfs libbsdfilesystem; do
	dir=$(make -C "$src/lib/$library" -V .OBJDIR)
	[ ! -f "$dir/$library.so.1" ] || cp "$dir/$library.so.1" "$payload/"
done
bsdfilesystem_obj=$(make -C "$src/usr.sbin/bsdfilesystem" -V .OBJDIR)
[ ! -f "$bsdfilesystem_obj/bsdfilesystem" ] || cp "$bsdfilesystem_obj/bsdfilesystem" "$payload/"

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
for daemon in bsdcrypto bsddevice bsdnotify bsdsysctl bsdnetwork bsdlog \
    traced bsdaudit authagentd bluetooth/blued; do
	make -C "$src/usr.sbin/$daemon" install installconfig \
	    DESTDIR="$world" -DNO_ROOT METALOG="$work/world.meta" \
	    INSTALL="install -U -M $work/world.meta -D $world" >/dev/null
done
mkdir -p "$payload/capabilities"
cp -R "$world/Capabilities/System" "$payload/capabilities/"

cp "$src/tools/test/capability-qemu/guest-install.sh" \
	"$src/tools/test/capability-qemu/guest-run.sh" "$payload/"
cp "$src/libexec/rc/rc.d/linux" "$payload/linux.rc"
printf '%s\n' "$src" > "$payload/source-root"
printf '%s\n' "$obj" > "$payload/object-root"
cp "$src/usr.sbin/capsule/capsule-daemon.conf" "$payload/"
cp "$src/usr.sbin/capsule/capsule-loader.conf" "$payload/"

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
for library in libauditcmp libcapability libcapbundle libchannel libcryptodesc \
    libcryptocmp libdevicecmp libsysctlcmp liblogcmp libnetworkcmp \
    libnotify libcapsulert libservice \
    libshmring libtracecmp libtrustedzfs libbsdfilesystem; do
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
	-cpu "$cpu" -smp "$cpus" -m "$memory" -snapshot \
	-drive "file=$image,format=raw,if=virtio" \
	-drive "file=$iso,format=raw,media=cdrom,readonly=on" \
	-boot c -nic none -display none -serial stdio -monitor none
