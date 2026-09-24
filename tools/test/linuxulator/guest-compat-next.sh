#!/bin/sh
set -eu
trap 'rc=$?; echo NEXT_EXIT "$rc"; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
chmod 1777 /tmp
kldload linux64
mkdir -p /proc /sys
mount -t linprocfs linprocfs /proc
mount -t linsysfs linsysfs /sys
ifconfig lo0 up
cp /root/compat-next /tmp/compat-next
chmod 755 /tmp/compat-next
cp /root/abstract /tmp/abstract
chmod 755 /tmp/abstract
for round in 1 2 3; do
 for user in root unprivileged; do
  for c in stream dgram seqpacket binary autobind; do
   rc=0; timeout -k 3 90 /tmp/abstract "$c" "$user" || rc=$?
   echo ABSTRACT "$round" "$user" "$c" "$rc"
   [ "$rc" -eq 0 ] || exit "$rc"
  done
 done
done
for user in root unprivileged; do
 for c in notify notifyrace discovery abstractextra abstractlife xattredges notifydelete; do
  rc=0; timeout -k 3 150 /tmp/compat-next "$c" "$user" || rc=$?
  echo NEXT "$user" "$c" "$rc"
 done
done
for mode in jail vnet; do
 rc=0; /tmp/compat-next isolate "$mode" || rc=$?; echo NEXT "$mode" isolation "$rc"
done
rc=0; /tmp/compat-next caps || rc=$?; echo NEXT cap isolation "$rc"
kldload fusefs
mkdir -p /mnt/fuse-next /tmp/fuse-backing
chmod 777 /tmp/fuse-backing
: > /tmp/fuse-backing/.ready
for mode in base permissions writeback; do
 args=''
 [ "$mode" != permissions ] || args='-o default_permissions'
 FUSE_TEST_ROOT=/tmp/fuse-backing FUSE_TEST_WRITEBACK="$mode" /root/fuse-passthrough -f -s -o allow_other $args /mnt/fuse-next > /tmp/fuse.log 2>&1 &
 daemon=$!
 ready=0
 for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if [ -f /mnt/fuse-next/.ready ]; then ready=1; break; fi
  kill -0 "$daemon" 2>/dev/null || break
  sleep 1
 done
 cat /tmp/fuse.log
 [ "$ready" -eq 1 ] || exit 1
 if [ "$mode" = writeback ]; then
  negotiated=0
  while IFS= read -r line; do
   [ "$line" != FUSE_TEST_WRITEBACK_NEGOTIATED ] || negotiated=1
  done < /tmp/fuse.log
  [ "$negotiated" -eq 1 ] || exit 1
 fi
 rc=0; timeout -k 3 150 /tmp/compat-next fuse /mnt/fuse-next || rc=$?
 echo NEXT "$mode" fuse "$rc"
 if [ "$rc" -eq 0 ]; then
  rc=0; timeout -k 3 150 /tmp/compat-next fuse /mnt/fuse-next unprivileged || rc=$?
  echo NEXT "$mode" fuse_unprivileged "$rc"
 fi
 kill -KILL "$daemon"
 wait "$daemon" 2>/dev/null || true
 rc=0; /tmp/compat-next fusefailure /mnt/fuse-next || rc=$?
 echo NEXT "$mode" fuse_failure "$rc"
 umount /mnt/fuse-next
 rm -rf /tmp/fuse-backing/*
done
mkdir -p /tmp/native-fuse
cd /tmp/native-fuse
rc=0; timeout -k 3 120 /root/fuse-link-native || rc=$?
echo NEXT native fuse_link "$rc"
cd /
zpool sync linuxgate
zpool status -x
echo NEXT_DONE
