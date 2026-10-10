#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Disposable VM only: sources and ATF programs must be staged in /usr/tests.
set -eu
trap 'rc=$?; echo STARNIX_ATF_EXIT "$rc"; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
testdir=${STARNIX_ATF_TESTDIR:-/usr/tests/starnix-prebinder}
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
chmod 1777 /tmp
ifconfig lo0 inet 127.0.0.1 up
for module in linux64 linprocfs linsysfs uinput; do
    kldstat -q -m "$module" || kldstat -q -n "$module.ko" ||
        kldload "/boot/kernel/$module.ko"
done
mkdir -p /compat/linux/proc /compat/linux/sys /tmp/starnix-atf-tmpfs
mount -t linprocfs linprocfs /compat/linux/proc
mount -t linsysfs linsysfs /compat/linux/sys
mount -t tmpfs tmpfs /tmp/starnix-atf-tmpfs
chmod 1777 /tmp/starnix-atf-tmpfs
echo STARNIX_ATF_BEGIN
uname -a
mount -p
sha256 /boot/kernel/kernel /boot/kernel/linux64.ko \
    /boot/kernel/linux_common.ko /boot/kernel/linprocfs.ko \
    /boot/kernel/uinput.ko "$testdir"/*
failed=0
for fs in zfs tmpfs; do
    if [ "$fs" = zfs ]; then TMPDIR=/tmp; else TMPDIR=/tmp/starnix-atf-tmpfs; fi
    export TMPDIR
    echo STARNIX_ATF_FS_BEGIN "$fs"
    rc=0
    kyua -v unprivileged_user=nobody test \
        -k "$testdir/Kyuafile" \
        -r "/root/starnix-atf-$fs.db" || rc=$?
    kyua report --verbose --results-filter=passed,skipped,xfail,broken,failed \
        -r "/root/starnix-atf-$fs.db"
    echo STARNIX_ATF_FS_END "$fs" "$rc"
    [ "$rc" -eq 0 ] || failed=1
done
zpool sync
zpool status -x
echo STARNIX_ATF_DONE
exit "$failed"
