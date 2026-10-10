#!/bin/sh
# Run only in a disposable FreeBSD VM with the protocol fixtures staged.
set -eu
trap 'rc=$?; echo FUSE_PROTOCOL_EXIT "$rc"; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
chmod 1777 /tmp
chmod 755 /root
kldload /boot/kernel/fusefs.ko
echo FUSE_PROTOCOL_ARTIFACT kernel "$(sha256 -q "$(sysctl -n kern.bootfile)")"
echo FUSE_PROTOCOL_ARTIFACT fusefs "$(sha256 -q /boot/kernel/fusefs.ko)"
sysctl vfs.usermount=1
sysctl vfs.aio.enable_unsafe=1
chmod 666 /dev/fuse
failed=0
while IFS= read -r name; do
 case "$name" in ''|*[!a-zA-Z0-9_-]*) exit 2 ;; esac
 mkdir -p /tmp/fuse-protocol/$name
 chmod 777 /tmp/fuse-protocol/$name
 cd /tmp/fuse-protocol/$name
 uid=0
 [ "$name" != default_permissions ] || uid=65534
 echo FUSE_PROTOCOL_BEGIN "$name"
 echo FUSE_PROTOCOL_ARTIFACT "$name" "$(sha256 -q /root/fuse-tests/"$name")"
 rc=0
 timeout -k 5 180 /root/native-exec "$uid" /root/fuse-tests/"$name" \
  '--gtest_filter=*' --gtest_repeat=1 || rc=$?
 echo FUSE_PROTOCOL_END "$name" "$rc"
 [ "$rc" -eq 0 ] || failed=1
 cd /
done < /root/fuse-protocol.programs
zpool sync linuxgate
zpool status -x
echo FUSE_PROTOCOL_DONE
exit "$failed"
