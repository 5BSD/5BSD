#!/bin/sh
# Disposable VM only. Record all cases, including failures.
set -eu
trap 'rc=$?; echo PROC_PATH_EXIT "$rc"; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
kldload linux64
kldload linprocfs
mkdir -p /proc
mount -t linprocfs linprocfs /proc
mkdir -p /tmp/procpath-zfs /tmp/procpath-tmpfs /tmp/procpath-back /tmp/procpath-nullfs
mount -t tmpfs tmpfs /tmp/procpath-tmpfs
kldload nullfs
mount -t nullfs /tmp/procpath-back /tmp/procpath-nullfs
chmod 1777 /tmp/procpath-zfs /tmp/procpath-tmpfs /tmp/procpath-back
cd /tmp
parents_before=$(sysctl -n vfs.inotify.parents)
paths_before=$(sysctl -n vfs.inotify.paths)
failed=0
cache_modes=on
if sysctl -n debug.vfscache >/dev/null 2>&1; then cache_modes="on off"; fi
for cache in $cache_modes; do
 if [ "$cache" = off ]; then sysctl debug.vfscache=0; fi
for fs in zfs tmpfs nullfs; do
 cd /tmp/procpath-$fs
for user in root unprivileged; do
 for case in simple hardlink opath rename unlink recreate procfd ancestor_rename crossrename rename_race ancestor_race replace_parent_race ancestor_removed deep_removed removed_then_rename opath_events opath_dot_events opath_search directory dot dotdot opath_directory; do
  rc=0
  /root/proc-path-linux "$case" "$user" || rc=$?
  echo PROC_PATH_RESULT "$cache" "$fs" "$user" "$case" "$rc"
  [ "$rc" -eq 0 ] || failed=1
 done
done
done
done
if [ "$cache_modes" = "on off" ]; then sysctl debug.vfscache=1; fi
cd /tmp
umount /tmp/procpath-nullfs
umount /tmp/procpath-tmpfs
parents_after=$(sysctl -n vfs.inotify.parents)
paths_after=$(sysctl -n vfs.inotify.paths)
echo PROC_PATH_COUNTS "$paths_before" "$paths_after" "$parents_before" "$parents_after"
[ "$paths_before" = "$paths_after" ] || failed=1
[ "$parents_before" = "$parents_after" ] || failed=1
zpool sync linuxgate
zpool status -x
echo PROC_PATH_DONE
exit "$failed"
