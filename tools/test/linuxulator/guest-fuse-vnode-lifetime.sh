#!/bin/sh
# Run only as a boot job in a disposable, otherwise idle ZFS-root VM.
# FUSE's node counter misses reclaimed vnodes with leaked native references.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
trap 'rc=$?; echo FUSE_LIFETIME_EXIT "$rc"; /sbin/halt -p' EXIT

mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
kldstat -q -m fusefs || kldload /boot/kernel/fusefs.ko
sysctl vfs.usermount=1
chmod 666 /dev/fuse
mkdir -p /tmp/fuse-lifetime
cd /tmp/fuse-lifetime
sha256 /boot/kernel/kernel /boot/kernel/fusefs.ko \
    /root/fuse-tests/lookup /root/fuse-lifetime.sh

# Create logs and warm executable/mount infrastructure before sampling.
: > repeat.log
timeout -k 5 30 /root/native-exec 0 /root/fuse-tests/lookup \
    --gtest_filter=Lookup.vtype_conflict > warmup.log 2>&1
before=$(sysctl -n vfs.numvnodes)
echo FUSE_LIFETIME_BEFORE "$before"
rc=0
timeout -k 5 120 /root/native-exec 0 /root/fuse-tests/lookup \
    --gtest_filter=Lookup.vtype_conflict --gtest_repeat=256 \
    > repeat.log 2>&1 || rc=$?
after=$(sysctl -n vfs.numvnodes)
nodes=$(sysctl -n vfs.fusefs.stats.node_count)
passes=$(awk '/^\[       OK \] Lookup.vtype_conflict / { n++ }
    END { print n+0 }' repeat.log)
delta=$((after - before))
echo FUSE_LIFETIME_AFTER "$after"
echo FUSE_LIFETIME_DELTA "$delta"
echo FUSE_LIFETIME_REPEAT_EXIT "$rc"
echo FUSE_LIFETIME_PASSES "$passes"
echo FUSE_LIFETIME_FUSE_NODES "$nodes"
tail -16 repeat.log
zpool sync
zpool status -x
test "$rc" -eq 0
test "$passes" -eq 256
test "$nodes" -eq 0
# Global vnode counts have small background fluctuations. A leaked reference
# per replacement grows by 256; allow at most 16 in this isolated guest.
test "$delta" -le 16
echo FUSE_LIFETIME_PASS
