#!/bin/sh
# Disposable FreeBSD guest only.
set -eu
trap 'rc=$?; echo LIFETIME_EXIT "$rc"; sync; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
chmod 1777 /tmp
kldload linux64
kldstat -q -m nullfs || kldload nullfs
kldstat -q -m tmpfs || kldload tmpfs
if [ "${INOTIFY_TMPFS:-0}" = 1 ]; then
 mount -t tmpfs tmpfs /tmp
 chmod 1777 /tmp
fi
mkdir -p /proc
mount -t linprocfs linprocfs /proc
for program in lifetime-linux lifetime-native; do
 cp "/root/$program" "/tmp/$program"
 chmod 755 "/tmp/$program"
done
before=$(sysctl -n vfs.inotify.watches)
failed=0
for round in 1 2 3 4 5; do
 for program in lifetime-linux lifetime-native; do
  for user in root unprivileged; do
   for c in dup opens directory shared-map private-map late-watch hardlink replace remove-watch close-watches fork-exit; do
    rc=0; timeout -k 3 90 "/tmp/$program" "$c" "$user" || rc=$?
    echo LIFETIME_RESULT "$round" "$program" "$user" "$c" "$rc"
    [ "$rc" -eq 0 ] || failed=1
   done
  done
 done
done
while read -r testcase cleanup; do
 mkdir -p "/tmp/native-$testcase"
 cd "/tmp/native-$testcase"
 rc=0; timeout -k 3 90 /root/inotify_test -r result "$testcase" || rc=$?
 cat result
 echo INOTIFY_NATIVE "$testcase" "$rc"
 if [ "$cleanup" = yes ]; then
  timeout -k 3 30 /root/inotify_test "$testcase:cleanup"
 fi
 [ "$rc" -eq 0 ] && [ "$(cat result)" = passed ] || exit 1
 cd /
done < /root/inotify-cases
# Deferred watch destruction is allowed to finish before measuring retention.
for attempt in 1 2 3 4 5; do
 after=$(sysctl -n vfs.inotify.watches)
 [ "$after" != "$before" ] || break
 sleep 1
done
echo LIFETIME_WATCHES "$before" "$after"
[ "$before" = "$after" ]
zpool status -x
echo LIFETIME_DONE
exit "$failed"
