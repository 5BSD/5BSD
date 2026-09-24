#!/bin/sh
# Disposable VM only. Record all cases, including failures.
set -eu
trap 'rc=$?; echo PIPE_REOPEN_EXIT "$rc"; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
kldload linux64
kldload linprocfs
mkdir -p /proc
mount -t linprocfs linprocfs /proc
failed=0
for user in root unprivileged; do
 for case in identity matrix flags reader_lifetime writer_lifetime rdwr no_readers no_writers opath opath_queue cloexec directory queue epoll epoll_writer splice churn exhaustion async full_writer metadata permission; do
  rc=0
  /root/pipe-reopen-linux "$case" "$user" || rc=$?
  echo PIPE_REOPEN_RESULT "$user" "$case" "$rc"
  [ "$rc" -eq 0 ] || failed=1
 done
done
zpool sync linuxgate
zpool status -x
echo PIPE_REOPEN_DONE
exit "$failed"
