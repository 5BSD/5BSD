#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Run only in the disposable image used by qemu-rwf-durability.py.
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
set -e
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
df -T / | {
    read -r header
    read -r device type rest
    [ "$type" = zfs ]
}
[ "$(zfs get -H -o value sync linuxgate)" = standard ]
echo RWF_DURABILITY_ROOT_ZFS
uname -a
sha256 /boot/kernel/kernel /boot/kernel/linux64.ko /root/squeue_options_native /root/squeue_options_linux
kldstat -q -n linux64.ko || kldload /boot/kernel/linux64.ko
if [ -f /root/rwf-durable-prepared ]; then
    for abi in native linux; do
        (cd /root/rwf-durable-$abi && /root/squeue_options_$abi durable_check)
        echo "RWF_DURABILITY_VERIFIED $abi"
    done
    zpool sync linuxgate
    [ "$(zpool status -x)" = "all pools are healthy" ]
    echo RWF_DURABILITY_DONE
    halt -p
    exit 0
fi
# Commit names and initial zero contents before testing synchronous writes.
for abi in native linux; do
    mkdir /root/rwf-durable-$abi
    (cd /root/rwf-durable-$abi && /root/squeue_options_$abi durable_prepare)
done
: > /root/rwf-durable-prepared
zpool sync linuxgate
# Reduce incidental TXG commits during this short write sequence.  This does
# not disable resource-pressure TXGs; retain that limitation in the report.
sysctl vfs.zfs.txg.timeout=120
for abi in native linux; do
    (cd /root/rwf-durable-$abi && /root/squeue_options_$abi durable_write)
    echo "RWF_DURABILITY_WRITTEN $abi"
done
echo RWF_DURABILITY_CUT_NOW
# The controller kills this QEMU process without guest shutdown or pool sync.
while :; do sleep 1; done
