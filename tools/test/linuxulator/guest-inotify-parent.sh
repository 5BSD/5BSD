#!/bin/sh
# Disposable VM only. Record the complete inventory, including failures.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
trap 'rc=$?; echo PARENT_EXIT "$rc"; /sbin/halt -p' EXIT
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
kldload linux64 || exit 1
kldload linprocfs || exit 1
mkdir -p /proc
mount -t linprocfs linprocfs /proc || exit 1
before=$(sysctl -n vfs.inotify.watches)
paths=$(sysctl -n vfs.inotify.paths)
kldload nullfs || exit 1
mkdir -p /parent-lower
chmod 1777 /parent-lower
failed=0
for fs in zfs tmpfs nullfs; do
 case "$fs" in
 tmpfs) mount -t tmpfs -o mode=1777 tmpfs /tmp || exit 1 ;;
 nullfs) mount -t nullfs /parent-lower /tmp || exit 1 ;;
 esac
for user in root unprivileged; do
 for case in hardlinks rename crossrename unlink exclude recreate overwrite dup procfd procfddeleted failedopen createlate fork mapclose unlinklast excludelast procfdlast renamechurn unlinkrace excluderace dual; do
  rc=0
  /root/parent-linux "$case" "$user" || rc=$?
  echo PARENT_RESULT "$fs" "$user" "$case" "$rc"
  [ "$rc" -eq 0 ] || failed=1
 done
done
[ "$fs" = zfs ] || umount /tmp || exit 1
done
echo PARENT_WATCHES "$before" "$(sysctl -n vfs.inotify.watches)"
echo PARENT_PATHS "$paths" "$(sysctl -n vfs.inotify.paths)"
zpool sync linuxgate
zpool status -x
echo PARENT_DONE
exit "$failed"
