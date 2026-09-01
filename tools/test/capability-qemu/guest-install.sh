#!/bin/sh
# Install the kernel and userland pieces needed by the descriptor regression
# payload.  The caller must reboot before invoking guest-run.sh.

set -eu

payload=${1:-/mnt}

install -m 555 "$payload/kernel" /boot/kernel/kernel
for module in zfs.ko cryptodev.ko; do
	if [ -f "$payload/$module" ]; then
		install -m 555 "$payload/$module" "/boot/kernel/$module"
	fi
done
for module in "$payload"/mac_capability*.ko "$payload"/zfshandle.ko; do
	[ ! -f "$module" ] || install -m 555 "$module" /boot/kernel/
done
for library in libtrustedzfs.so.1 libtzfsd.so.1; do
	if [ -f "$payload/$library" ]; then
		install -m 555 "$payload/$library" "/lib/$library"
	fi
done
for library in "$payload"/libs/*.so.*; do
	[ ! -f "$library" ] || install -m 555 "$library" /usr/lib/
done
if [ -f "$payload/tzfsd" ]; then
	install -m 555 "$payload/tzfsd" /usr/sbin/tzfsd
fi

# Replace the service-manager stack too: an installed daemon from an older
# world paired with the freshly staged private libraries is exactly the ABI
# skew this harness exists to catch, and it aborts serviced at startup.
if [ -f "$payload/obj/usr.sbin/serviced/serviced" ]; then
	install -m 555 "$payload/obj/usr.sbin/serviced/serviced" \
	    /usr/libexec/serviced
	# Pre-move location; a stale copy here shadows the current binary
	# through PATH lookups.
	rm -f /usr/sbin/serviced
fi
if [ -f "$payload/obj/usr.sbin/oracled/oracled" ]; then
	install -m 555 "$payload/obj/usr.sbin/oracled/oracled" /usr/sbin/oracled
	# PID 1 is the same program installed under /sbin; a stale init would
	# keep the old shutdown ordering and world supervision.
	install -m 555 "$payload/obj/usr.sbin/oracled/oracled" /sbin/oracle-init
fi
if [ -f "$payload/obj/usr.sbin/servicectl/servicectl" ]; then
	install -m 555 "$payload/obj/usr.sbin/servicectl/servicectl" \
	    /usr/sbin/servicectl
fi

# Storage plane: component descriptors are backed by tzfsd leases, which
# need a real pool.  Give the UFS qualification guest a file-backed one.
if ! zpool list capability >/dev/null 2>&1; then
	kldload zfs 2>/dev/null || true
	if [ ! -f /var/capability-pool.img ]; then
		truncate -s 2g /var/capability-pool.img
	fi
	zpool create -f -o failmode=continue -O mountpoint=none capability \
	    /var/capability-pool.img || true
fi
# Quiesce the pool before the disposable reboot: a file-backed vdev on the
# root filesystem suspends on I/O failure during the reboot sync and wedges
# the shutdown.  tzfsd re-imports it on demand.
zpool export capability 2>/dev/null || true
mkdir -p /Capabilities/Config
printf 'pool = "capability";\n' > /Capabilities/Config/tzfsd.ucl

# Replace the system bundle set with the one staged from this source
# revision.  A leftover bundle from an older world is not benign: serviced
# treats an invalid SYSTEM bundle as a boot-convergence failure by design,
# so the qualification guest must carry exactly the current set.
if [ -d "$payload/capabilities/System" ]; then
	mkdir -p /Capabilities/System
	for bundle in /Capabilities/System/*.cap; do
		[ -d "$bundle" ] || continue
		rm -rf "$bundle"
	done
	for bundle in "$payload/capabilities/System"/*.cap; do
		[ -d "$bundle" ] || continue
		cp -R "$bundle" /Capabilities/System/
	done
fi

# Exercise TrustedZFS enumeration limits without creating thousands of ZFS
# objects under TCG.  The kernel permits only a stricter-than-production value.
if ! grep -q '^vfs.zfs.trustedzfs.enum_max_entries=' \
    /boot/loader.conf.local 2>/dev/null; then
	printf '%s\n' 'vfs.zfs.trustedzfs.enum_max_entries="64"' >> \
	    /boot/loader.conf.local
fi

# The provider transport cases must run before init claims /dev/mac_capability
# for the system-wide service supervisor.  Single-user mode leaves the device
# unclaimed while still loading the production MAC policies and test kernel.
sysrc -f /boot/loader.conf.local boot_single=YES >/dev/null

echo "Capability test payload installed; rebooting disposable guest"
# This is a throwaway snapshot and the installed files have already been
# synchronously written.  Avoid letting unrelated service shutdown hooks block
# the qualification reboot.
reboot -q
