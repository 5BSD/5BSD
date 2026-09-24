#!/bin/sh
# Disposable VM only: diagnostic and jail-scoping tests.
set -eu
trap 'rc=$?; echo DIAG_EXIT "$rc"; /sbin/halt -p' EXIT
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
chmod 755 /root
kldload linux64
ifconfig lo0 inet 127.0.0.1/8 up
ifconfig lo0 inet6 ::1/128 alias
for round in 1 2 3; do
 for uid in 0 65534; do
  for family in 4 6; do
   for proto in tcp udp tcp-connected; do
    DIAG_BULK=1 DIAG_CHURN=1 /root/native-exec "$uid" /root/linux_sock_diag "$family" "$proto"
    echo DIAG_RESULT host "$round" "$uid" "$family" "$proto" 0
   done
  done
 done
done
/root/linux_sock_diag hold /tmp/diag-hidden-port 300 &
holder=$!
tries=0
while [ ! -s /tmp/diag-hidden-port ]; do
 tries=$((tries + 1)); [ "$tries" -lt 30 ]; sleep 1
done
hidden=$(cat /tmp/diag-hidden-port)
sysctl security.bsd.see_other_uids=0
DIAG_HIDE_PORT="$hidden" /root/native-exec 65534 /root/linux_sock_diag 4 tcp
echo DIAG_VISIBILITY_PASS
sysctl security.bsd.see_other_uids=1
jail -c name=diag path=/ persist vnet allow.raw_sockets=1
jexec diag ifconfig lo0 inet 127.0.0.1/8 up
jexec diag ifconfig lo0 inet6 ::1/128 alias
for uid in 0 65534; do
 for family in 4 6; do
  for proto in tcp udp tcp-connected; do
   DIAG_HIDE_PORT="$hidden" jexec diag /root/native-exec "$uid" /root/linux_sock_diag "$family" "$proto"
   echo DIAG_RESULT vnet 1 "$uid" "$family" "$proto" 0
  done
 done
done
jail -r diag
ifconfig lo0 inet 127.0.0.2/8 alias
jail -c name=diag-shared path=/ persist ip4.addr=127.0.0.2 allow.raw_sockets=1
for uid in 0 65534; do
 for proto in tcp udp tcp-connected; do
  DIAG_IPV4=127.0.0.2 DIAG_HIDE_PORT="$hidden" jexec diag-shared /root/native-exec "$uid" /root/linux_sock_diag 4 "$proto"
  echo DIAG_RESULT shared 1 "$uid" 4 "$proto" 0
 done
done
jail -r diag-shared
kill "$holder"
wait "$holder" || true
zpool sync linuxgate
zpool status -x
echo DIAG_DONE
