#!/bin/sh
# Disposable BSD VM only; /proc must already be linprocfs.
set -eu
cp /root/proc_native /tmp/proc_native
chmod 755 /tmp/proc_native
/tmp/proc_native
for round in 1 2 3; do
 timeout -k 3 90 /root/proc_net_jail
 echo PROC_NET_JAIL "$round" 0
done
mkdir -p /mnt/proc-force
for round in 1 2 3 4 5 6 7 8; do
 rm -f /tmp/proc-force-ready /tmp/proc-force-stop
 mount -t tmpfs tmpfs /mnt/proc-force
 timeout -k 3 90 /root/proc_lifetime &
 reader=$!
 attempts=0
 while [ ! -f /tmp/proc-force-ready ]; do
  attempts=$((attempts + 1))
  [ "$attempts" -lt 30 ] || exit 1
  sleep 1
 done
 umount -f /mnt/proc-force
 : > /tmp/proc-force-stop
 wait "$reader"
 echo PROC_FORCE "$round" 0
 pids=''
 for user in root unprivileged; do
  for case in fdchurn churn fdpermissions descriptors fdextra fdscale sockettables tasklinks; do
   (
    for iteration in 1 2 3 4; do
     rc=0
     timeout -k 3 120 /tmp/proc_views "$case" "$user" || rc=$?
     echo PROC_STRESS "$round" "$user" "$case" "$iteration" "$rc"
     [ "$rc" -eq 0 ] || exit "$rc"
    done
   ) &
   pids="$pids $!"
  done
 done
 for pid in $pids; do wait "$pid"; done
done
iteration=0
while [ "$iteration" -lt 64 ]; do
 iteration=$((iteration + 1))
 timeout -k 3 90 /tmp/proc_views fdexec unprivileged
 echo PROC_EXEC_STRESS "$iteration" 0
done
echo PROC_STRESS_DONE
