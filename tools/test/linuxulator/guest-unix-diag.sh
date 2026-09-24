#!/bin/sh
# UNIX socket diagnostics, disposable VM only.
set -eu
trap 'rc=$?; echo UNIX_DIAG_EXIT "$rc"; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
chmod 755 /root
chmod 1777 /tmp
kldload linux64
for round in 1 2 3; do
 churn=0; [ "$round" != 1 ] || churn=1
 for uid in 0 65534; do
  for type in 1 2 5; do
   for mode in path abstract pair; do
    DIAG_CHURN="$churn" /root/native-exec "$uid" /root/linux_unix_diag "$type" "$mode"
    echo UNIX_DIAG_RESULT host "$round" "$uid" "$type" "$mode" 0
   done
  done
 done
done
/root/linux_unix_diag hold /tmp/unix-diag-hidden &
holder=$!
tries=0
while [ ! -s /tmp/unix-diag-hidden ]; do
 tries=$((tries+1)); [ "$tries" -lt 30 ]; sleep 1
done
hidden=$(cat /tmp/unix-diag-hidden)
DIAG_SHOW_INO="$hidden" /root/linux_unix_diag 2 pair
echo UNIX_DIAG_VISIBLE_PASS
sysctl security.bsd.see_other_uids=0
DIAG_HIDE_INO="$hidden" /root/native-exec 65534 /root/linux_unix_diag 2 pair
echo UNIX_DIAG_VISIBILITY_PASS
sysctl security.bsd.see_other_uids=1
for scope in vnet shared; do
 if [ "$scope" = vnet ]; then
  jail -c name=unixdiag path=/ persist vnet allow.raw_sockets=1
 else
  jail -c name=unixdiag path=/ persist ip4=inherit ip6=inherit allow.raw_sockets=1
 fi
 for uid in 0 65534; do
  for type in 1 2 5; do
   for mode in path abstract pair; do
    DIAG_HIDE_INO="$hidden" jexec unixdiag /root/native-exec "$uid" /root/linux_unix_diag "$type" "$mode"
    echo UNIX_DIAG_RESULT "$scope" 1 "$uid" "$type" "$mode" 0
   done
  done
 done
 jail -r unixdiag
done
kill "$holder"
wait "$holder" || true
zpool sync linuxgate
zpool status -x
echo UNIX_DIAG_DONE
