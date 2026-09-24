#!/bin/sh
# Disposable amd64 guests only: creates and removes a guest loopback interface.
set -eu
trap 'rc=$?; echo UEVENT_EXIT "$rc"; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
chmod 1777 /tmp
kldload linux64
mkdir -p /proc /sys
mount -t linprocfs linprocfs /proc
mount -t linsysfs linsysfs /sys
cp /root/kobject-uevent-linux /tmp/kobject-uevent-linux
chmod 755 /tmp/kobject-uevent-linux
sockets_before=$(sysctl -n kern.ipc.numopensockets)
failed=0
for uid in root unprivileged; do
 for kind in raw dgram; do
  rc=0
  timeout -k 3 90 /tmp/kobject-uevent-linux "$kind" "$uid" bsd || rc=$?
  echo UEVENT_RESULT "$uid" "$kind" "$rc"
  [ "$rc" -eq 0 ] || failed=1
 done
done
timeout -k 3 240 /root/uevent-jail || failed=1
sockets_after=$(sysctl -n kern.ipc.numopensockets)
echo UEVENT_SOCKET_COUNTS "$sockets_before" "$sockets_after"
[ "$sockets_before" = "$sockets_after" ] || failed=1
zpool status -x
echo UEVENT_DONE
exit "$failed"
