#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Disposable VM: native rename suite plus Linux64 NOREPLACE protocol checks.
set -eu
trap 'rc=$?; echo FUSE_PROTOCOL_EXIT "$rc"; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
chmod 1777 /tmp
for module in fusefs linux64; do
    kldstat -q -m "$module" || kldstat -q -n "$module.ko" || kldload "$module"
done
for artifact in kernel fusefs linux64 linux_common; do
    path=/boot/kernel/$artifact.ko
    [ "$artifact" != kernel ] || path=/boot/kernel/kernel
    echo FUSE_PROTOCOL_ARTIFACT "$artifact" "$(sha256 -q "$path")"
done
echo FUSE_PROTOCOL_ARTIFACT linux_rename_probe "$(sha256 -q /root/linux-fuse-rename)"
failed=0
for mode in native linux; do
    mkdir -p "/tmp/fuse-rename-$mode"
    cd "/tmp/fuse-rename-$mode"
    unset FUSE_LINUX_RENAME_PROBE
    filter='*'
    if [ "$mode" = linux ]; then
        FUSE_LINUX_RENAME_PROBE=/root/linux-fuse-rename
        export FUSE_LINUX_RENAME_PROBE
        filter='Rename.noreplace_existing_destination:RenameOld.*:DaemonReply/RenameNoReplace.*'
    fi
    echo FUSE_PROTOCOL_BEGIN "rename_$mode"
    echo FUSE_PROTOCOL_ARTIFACT "rename_$mode" "$(sha256 -q /root/fuse-tests/rename)"
    rc=0
    timeout -k 5 180 /root/native-exec 0 /root/fuse-tests/rename \
        "--gtest_filter=$filter" --gtest_repeat=1 || rc=$?
    echo FUSE_PROTOCOL_END "rename_$mode" "$rc"
    [ "$rc" -eq 0 ] || failed=1
    cd /
done
zpool sync linuxgate
zpool status -x
echo FUSE_PROTOCOL_DONE
exit "$failed"
