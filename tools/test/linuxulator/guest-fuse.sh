#!/bin/sh
# Run upstream libfuse's statically linked Linux64 hello daemon in a guest.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
kldload fusefs
mkdir -p /mnt/fuse-test
for options in base default_permissions allow_other; do
 if [ "$options" = base ]; then
  /root/fuse-hello -f -s /mnt/fuse-test > /tmp/fuse-daemon.log 2>&1 &
 else
  /root/fuse-hello -f -s -o "$options" /mnt/fuse-test > /tmp/fuse-daemon.log 2>&1 &
 fi
 daemon=$!
 ready=0
 attempt=0
 while [ "$attempt" -lt 30 ]; do
  attempt=$((attempt + 1))
  if [ -f /mnt/fuse-test/hello ]; then ready=1; break; fi
  if ! kill -0 "$daemon" 2>/dev/null; then break; fi
  sleep 1
 done
 if [ "$ready" -ne 1 ]; then cat /tmp/fuse-daemon.log; exit 1; fi
 [ "$(cat /mnt/fuse-test/hello)" = 'Hello World!' ]
 [ "$(dd if=/mnt/fuse-test/hello bs=1 skip=6 count=5 2>/dev/null)" = 'World' ]
 ls -la /mnt/fuse-test > /tmp/fuse-list
 if cat /mnt/fuse-test/missing 2>/dev/null; then exit 2; fi
 umount /mnt/fuse-test
 wait "$daemon"
 echo FUSE_CLIENT "$options" 0
done
/tmp/proc_views fuseoptions
echo FUSE_OPTIONS_PASS
kldunload fusefs
echo FUSE_CLIENT_DONE
