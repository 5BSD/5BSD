#!/bin/sh
# Install a TrustedZFS test payload into a disposable QEMU guest, then reboot
# so the replacement ZFS module is loaded from a clean boot.

set -eu

payload=${1:-/mnt}

install -m 555 "${payload}/zfs.ko" /boot/kernel/zfs.ko
install -m 555 "${payload}/mac_test.ko" /boot/kernel/mac_test.ko
install -m 555 "${payload}/libtrustedzfs.so.1" /lib/libtrustedzfs.so.1
install -m 555 "${payload}/libbsdfilesystem.so.1" /lib/libbsdfilesystem.so.1
install -m 555 "${payload}/bsdfilesystem" /usr/sbin/bsdfilesystem

# Exercise the real enumeration boundary without manufacturing 16K ZFS
# objects under TCG.  The kernel accepts only stricter-than-production values.
printf '%s\n' 'vfs.zfs.trustedzfs.enum_max_entries="64"' >> \
    /boot/loader.conf.local

echo "TrustedZFS payload installed; rebooting the disposable guest"
shutdown -r now
