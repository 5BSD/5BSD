#!/bin/sh
# Disposable FreeBSD guest only. Linux64 mapping semantics, native regressions.
set -eu
trap 'rc=$?; echo MAPPING_EXIT "$rc"; sync; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
kldload linux64
kldstat -q -m nullfs || kldload nullfs
kldstat -q -m tmpfs || kldload tmpfs
mkdir -p /proc
mount -t linprocfs linprocfs /proc
before=$(sysctl -n vfs.inotify.watches)
failed=0
for fs in zfs tmpfs; do
 if [ "$fs" = tmpfs ]; then mount -t tmpfs tmpfs /tmp; fi
 chmod 1777 /tmp
 for program in mapping-linux lifetime-linux; do
  cp "/root/$program" "/tmp/$program"
  chmod 755 "/tmp/$program"
 done
 for round in 1 2 3 4 5; do
  for user in root unprivileged; do
   for program in mapping-linux lifetime-linux; do
    if [ "$program" = mapping-linux ]; then
     cases='private shared readonly split fork-unmap fork-exit fork-exec fixed two-maps two-opens remap-pages dontneed failed-fixed merge shrink fork-wired noreplace remap-merge'
    else
     cases='dup opens directory shared-map private-map late-watch hardlink replace remove-watch close-watches fork-exit'
    fi
    for c in $cases; do
     rc=0
     timeout -k 3 60 "/tmp/$program" "$c" "$user" || rc=$?
     echo MAPPING_RESULT "$fs" "$round" "$program" "$user" "$c" "$rc"
     [ "$rc" -eq 0 ] || failed=1
    done
   done
  done
 done
done
while read -r testcase cleanup; do
 mkdir -p "/tmp/native-$testcase"
 cd "/tmp/native-$testcase"
 rc=0
 timeout -k 3 90 /root/inotify_test -r result "$testcase" || rc=$?
 cat result
 echo INOTIFY_NATIVE "$testcase" "$rc"
 if [ "$cleanup" = yes ]; then
  timeout -k 3 30 /root/inotify_test "$testcase:cleanup"
 fi
 [ "$rc" -eq 0 ] && [ "$(cat result)" = passed ] || failed=1
 cd /
done < /root/inotify-cases
for attempt in 1 2 3 4 5; do
 after=$(sysctl -n vfs.inotify.watches)
 [ "$after" != "$before" ] || break
 sleep 1
done
echo MAPPING_WATCHES "$before" "$after"
[ "$before" = "$after" ] || failed=1
zpool status -x
echo MAPPING_DONE
exit "$failed"
