#!/bin/sh
# Run only as a boot job in a disposable, otherwise idle ZFS-root VM.
# Race LOOKUP/READDIRPLUS replies with forced unmount and check cleanup.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
trap 'rc=$?; echo FUSE_TEARDOWN_EXIT "$rc"; /sbin/halt -p' EXIT

mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
kldstat -q -m fusefs || kldload /boot/kernel/fusefs.ko
sysctl vfs.usermount=1
chmod 666 /dev/fuse
mkdir -p /tmp/fuse-teardown
cd /tmp/fuse-teardown
sha256 /boot/kernel/kernel /boot/kernel/fusefs.ko \
    /root/fuse-tests/destroy /root/fuse-tests/readdir /root/fuse-teardown.sh

cases='destroy:Destroy.forced_unmount_pending_lookup
readdir:ReaddirPlus.forced_unmount_pending_reply'
# Create logs and warm both executable/mount paths before sampling.
for spec in $cases; do
    binary=${spec%%:*}
    name=${spec#*:}
    : > "repeat-$binary.log"
    if ! timeout -k 5 30 /root/native-exec 0 "/root/fuse-tests/$binary" \
        --gtest_filter="$name" > "warmup-$binary.log" 2>&1; then
        cat "warmup-$binary.log"
        exit 1
    fi
done
before=$(sysctl -n vfs.numvnodes)
echo FUSE_TEARDOWN_BEFORE "$before"
failed=0
passes=0
for spec in $cases; do
    binary=${spec%%:*}
    name=${spec#*:}
    rc=0
    timeout -k 5 120 /root/native-exec 0 "/root/fuse-tests/$binary" \
        --gtest_filter="$name" --gtest_repeat=256 --gtest_break_on_failure \
        > "repeat-$binary.log" 2>&1 || rc=$?
    count=$(awk -v name="$name" \
        'index($0, "[       OK ] " name " (") == 1 { n++ }
        END { print n+0 }' "repeat-$binary.log")
    echo FUSE_TEARDOWN_CASE "$name" "$count" "$rc"
    tail -16 "repeat-$binary.log"
    passes=$((passes + count))
    [ "$rc" -eq 0 ] && [ "$count" -eq 256 ] || failed=1
done
after=$(sysctl -n vfs.numvnodes)
nodes=$(sysctl -n vfs.fusefs.stats.node_count)
tickets=$(sysctl -n vfs.fusefs.stats.ticket_count)
delta=$((after - before))
echo FUSE_TEARDOWN_AFTER "$after"
echo FUSE_TEARDOWN_DELTA "$delta"
echo FUSE_TEARDOWN_REPEAT_EXIT "$failed"
echo FUSE_TEARDOWN_PASSES "$passes"
echo FUSE_TEARDOWN_FUSE_NODES "$nodes"
echo FUSE_TEARDOWN_FUSE_TICKETS "$tickets"
zpool sync
zpool status -x
test "$failed" -eq 0
test "$passes" -eq 512
test "$nodes" -eq 0
test "$tickets" -eq 0
# Global vnode counts fluctuate slightly; a leak per mount grows by 256.
# Allow at most 16 extra vnodes in this isolated guest.
test "$delta" -le 16
echo FUSE_TEARDOWN_PASS
