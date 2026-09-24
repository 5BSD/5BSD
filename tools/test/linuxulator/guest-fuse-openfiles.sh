#!/bin/sh
# Disposable guest only. Requires the matching kernel/modules and Linux probe.
set -eu
trap 'rc=$?; echo OPENFILES_EXIT "$rc"; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
kldload linux64
kldload fusefs
mkdir -p /tmp/openfiles-probe
for round in 1 2 3; do
 for mode in direct cached writeback; do
  OPENFILES_TRACE=1 /root/linux_fuse_openfiles /tmp/openfiles-probe "$mode"
  echo OPENFILES_RESULT "$round" "$mode" 0
 done
done
kldunload fusefs
zpool sync linuxgate
zpool status -x
echo OPENFILES_DONE
