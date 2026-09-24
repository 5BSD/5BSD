#!/bin/sh
set -eu
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo PROC_VIEWS_FAILED "$rc"; /sbin/halt -p; fi' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
ifconfig lo0 inet 127.0.0.1 up
chmod 1777 /tmp
kldload linux_common
kldload linux64
mkdir -p /proc /sys /nativeproc /nativefd
mount -t linprocfs linprocfs /proc
mount -t linsysfs linsysfs /sys
cp /root/proc_views /tmp/proc_views
chmod 755 /tmp/proc_views
sh /root/guest-fuse.sh
for round in 1 2 3; do
 for user in root unprivileged; do
  for c in names memory filesystems topology threads churn comm taskfiles statfields descriptors mountids fdchurn mounttree fdpermissions fdresolve fdexec tasklinks fdextra fdscale sockettables; do
   rc=0
   timeout -k 3 90 /tmp/proc_views "$c" "$user" || rc=$?
   echo PROC_VIEW "$round" "$user" "$c" "$rc"
   [ "$rc" -eq 0 ] || exit "$rc"
  done
 done
done
mount -t procfs proc /nativeproc
cat /nativeproc/curproc/status
ls /nativeproc/curproc > /tmp/native-list
umount /nativeproc
if kldstat -q -n procfs.ko; then kldunload procfs; fi
mount -t fdescfs fdesc /nativefd
ls /nativefd > /tmp/native-fd-list
umount /nativefd
if kldstat -q -n fdescfs.ko; then kldunload fdescfs; fi
echo NATIVE_PROC_PASS
if [ -f /root/guest-proc-stress.sh ]; then
 sh /root/guest-proc-stress.sh
fi
sh /root/guest-filesystems.sh
umount /sys
umount /proc
kldunload linsysfs
kldunload linprocfs
echo PROC_RELOAD_PASS
kldunload linux64
kldunload linux_common
kldload linux_common
kldload linux64
mount -t linprocfs linprocfs /proc
/tmp/proc_views mountids
umount /proc
kldunload linprocfs
kldunload linux64
kldunload linux_common
echo COMMON_RELOAD_PASS
zpool sync linuxgate
zpool status -x
echo PROC_VIEWS_DONE
/sbin/halt -p
