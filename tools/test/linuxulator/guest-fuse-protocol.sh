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
kldload fusefs
sysctl vfs.usermount=1
sysctl vfs.aio.enable_unsafe=1
chmod 666 /dev/fuse
failed=0
for name in access allow_other bad_server bmap cache copy_file_range create default_permissions default_permissions_privileged destroy dev_fuse_poll fallocate fifo flush forget fsync fsyncdir getattr interrupt io ioctl last_local_modify link locks lookup lseek mkdir mknod mount nfs notify open openfile opendir pre-init read readdir readlink release releasedir rename rmdir setattr statfs symlink unlink write xattr; do
 mkdir -p /tmp/fuse-protocol/$name
 chmod 777 /tmp/fuse-protocol/$name
 cd /tmp/fuse-protocol/$name
 uid=0
 [ "$name" != default_permissions ] || uid=65534
 echo FUSE_PROTOCOL_BEGIN "$name"
 rc=0
 timeout -k 5 180 /root/native-exec "$uid" /root/fuse-tests/"$name" || rc=$?
 echo FUSE_PROTOCOL_END "$name" "$rc"
 [ "$rc" -eq 0 ] || failed=1
 cd /
done
zpool sync linuxgate
zpool status -x
echo FUSE_PROTOCOL_DONE
exit "$failed"
