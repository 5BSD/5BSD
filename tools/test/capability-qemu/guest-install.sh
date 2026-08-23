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
for library in libtrustedzfs.so.1 libtzfsd.so.1; do
	if [ -f "$payload/$library" ]; then
		install -m 555 "$payload/$library" "/lib/$library"
	fi
done
if [ -f "$payload/tzfsd" ]; then
	install -m 555 "$payload/tzfsd" /usr/sbin/tzfsd
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
