#!/bin/sh
# Run only in a disposable BSD guest with /proc and /sys mounted.
set -eu
cp /root/linux_filesystems /tmp/fsprobe
chmod 755 /tmp/fsprobe
for round in 1 2 3; do
 for c in mount invalid limits sysfs_mount cpu network options inode readonly bind faults permissions stream counters many race; do
  rc=0
  timeout -k 3 30 /tmp/fsprobe "$c" || rc=$?
  echo FS_ROOT "$round" "$c" "$rc"
  [ "$rc" -eq 0 ] || exit "$rc"
 done
 for c in cpu network stream counters; do
  rc=0
  timeout -k 3 30 /tmp/fsprobe "$c" unprivileged || rc=$?
  echo FS_UNPRIV "$round" "$c" "$rc"
  [ "$rc" -eq 0 ] || exit "$rc"
 done
done

# Dynamic interfaces, VNET visibility, and teardown of cached pseudofs nodes.
check()
{
 rc=0
 timeout -k 3 90 /tmp/fsprobe "$2" "$3" || rc=$?
 echo FS_LINK "$round" "$1" "$rc"
 [ "$rc" -eq 0 ] || exit "$rc"
}
for round in 1 2 3; do
 ifconfig lo1 create
 check down link_down lo1
 ifconfig lo1 up
 check up link_up lo1
 ifconfig lo1 name fslab
 check old link_absent lo1
 check renamed link_up fslab
 ifconfig fslab destroy
 check gone link_absent fslab
 timeout -k 3 90 /tmp/fsprobe churn &
 reader=$!
 for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
  ifconfig lo1 create
  ifconfig lo1 up
  ifconfig lo1 destroy
 done
 rc=0
 wait "$reader" || rc=$?
 echo FS_LINK "$round" churn "$rc"
 [ "$rc" -eq 0 ] || exit "$rc"
 ifconfig lo2 create
 ifconfig lo2 name fshost
 ifconfig fshost up
 rc=0
 timeout -k 3 60 /root/fsjail || rc=$?
 echo FS_JAIL "$round" "$rc"
 [ "$rc" -eq 0 ] || exit "$rc"
 check host_after_jail link_up fshost
 ifconfig fshost destroy
done
for round in 1 2 3; do
 umount /sys
 umount /proc
 kldunload linsysfs
 kldunload linprocfs
 mount -t linprocfs linprocfs /proc
 mount -t linsysfs linsysfs /sys
 /tmp/fsprobe sysfs_mount
 /tmp/fsprobe cpu
 /tmp/fsprobe network
 echo FS_RELOAD "$round" 0
done
