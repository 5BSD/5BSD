#!/bin/sh
# Disposable guest only; requires the Linux64 libfuse probe in /root.
set -eu
trap 'rc=$?; echo FUSE_FLAGS_EXIT "$rc"; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
kldload linux64
kldload fusefs
mkdir -p /tmp/fuse-create-flags
for round in 1 2 3 4 5; do
 /root/linux_fuse_create_flags /tmp/fuse-create-flags
 /root/linux_fuse_create_flags /tmp/fuse-create-flags exclusive
 echo FUSE_FLAGS_ROUND "$round" 0
done
kldunload fusefs
zpool sync linuxgate
zpool status -x
echo FUSE_FLAGS_DONE
