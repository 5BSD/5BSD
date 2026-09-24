#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Disposable amd64 ZFS-root guest only; called by guest-gate.sh.
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mkdir -p /tmp/quota-work /tmp/quota-tmpfs
sha256 /root/linux_quota /root/quota_native /root/quota_capmode /root/quota_capmode_probe /root/quota_capmode_path_probe
zpool upgrade linuxgate || exit 1
zfs create -o mountpoint=/tmp/quota-work -o compression=off linuxgate/quota || exit 1
for round in 1 2 3; do
    for case in hard_limit_roundtrip invalid_arguments device_path_validation quota_sync permissions ignored_fields descriptor_lifetime fork_exec_lifetime enforcement_and_usage group_enforcement_and_usage unsupported_updates_are_atomic; do
        (cd /tmp/quota-work && timeout 60 /root/linux_quota "$case")
        rc=$?
        echo GATE_QUOTA "$round" "$case" "$rc"
        [ "$rc" = 0 ] || exit 1
    done
    timeout 30 /root/quota_capmode /root/quota_capmode_probe || exit 1
    echo GATE_QUOTA_CAPMODE "$round" fd 0
    timeout 30 /root/quota_capmode /root/quota_capmode_path_probe || exit 1
    echo GATE_QUOTA_CAPMODE "$round" path 0
    (cd /tmp/quota-work && /root/linux_quota native_get_prepare) || exit 1
    /root/quota_native get /tmp/quota-work 16386 || exit 1
    /root/quota_native permissions /tmp/quota-work 0 || exit 1
    /root/quota_native set /tmp/quota-work 16385 || exit 1
    (cd /tmp/quota-work && /root/linux_quota native_set_check) || exit 1
    /root/quota_native set /tmp/quota-work 0 || exit 1
    echo GATE_QUOTA_NATIVE "$round" 0
done
(cd /tmp/quota-work && /root/linux_quota native_get_prepare) || exit 1
zfs unmount linuxgate/quota || exit 1
zfs mount linuxgate/quota || exit 1
(cd /tmp/quota-work && /root/linux_quota native_set_check) || exit 1
/root/quota_native set /tmp/quota-work 0 || exit 1
echo GATE_QUOTA_REMOUNT 0
zfs set readonly=on linuxgate/quota || exit 1
(cd /tmp/quota-work && /root/linux_quota readonly) || exit 1
echo GATE_QUOTA_READONLY 0
zfs set readonly=off linuxgate/quota || exit 1
zfs set defaultuserquota=1G linuxgate/quota || exit 1
(cd /tmp/quota-work && /root/linux_quota unsupported_fs) || exit 1
echo GATE_QUOTA_DEFAULT 0
zfs set defaultuserquota=none linuxgate/quota || exit 1
mount -t tmpfs tmpfs /tmp/quota-tmpfs || exit 1
(cd /tmp/quota-tmpfs && /root/linux_quota unsupported_fs) || exit 1
echo GATE_QUOTA_TMPFS 0
umount /tmp/quota-tmpfs || exit 1
zfs destroy linuxgate/quota || exit 1
mkdir -p /tmp/quota-vdev || exit 1
/bin/dd if=/dev/zero of=/tmp/quota-vdev/disk bs=1m count=128 || exit 1
zpool create -f -o cachefile=none -m /tmp/quota-ro quota_ro /tmp/quota-vdev/disk || exit 1
zpool export quota_ro || exit 1
zpool import -d /tmp/quota-vdev -o readonly=on -o cachefile=none quota_ro || exit 1
(cd /tmp/quota-ro && /root/linux_quota readonly && timeout 60 /root/linux_quota quota_sync) || exit 1
zpool export quota_ro || exit 1
rm /tmp/quota-vdev/disk || exit 1
rmdir /tmp/quota-vdev || exit 1
echo GATE_QUOTA_READONLY_POOL 0
echo GATE_QUOTA_DONE
