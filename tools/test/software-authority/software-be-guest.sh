#!/bin/sh
set -eu
[ "$(hostname)" = auth-policy-vm ]
root_dataset=$(mount -p | awk '$2 == "/" {print $1}')
case "$1" in
prepare)
 [ "$root_dataset" = policyvm/ROOT/default ]
 bectl check
 mkdir -p /var/tmp
 printf '%s\n' original > /var/tmp/software-be-data
 printf '%s\n' rollback > /root/software-be-phase
 # Let the ZFS loader select the activated root rather than forcing default.
 for file in /boot/loader.conf /boot/loader.conf.local; do
  [ ! -f "$file" ] || sed -i '' '/^vfs.root.mountfrom=/d' "$file"
 done
 bectl create software-policy-test
 mkdir -p /mnt/software-be
 bectl mount software-policy-test /mnt/software-be
 printf '%s\n' candidate > /mnt/software-be/root/software-be-phase
 printf '%s\n' candidate > /mnt/software-be/var/tmp/software-be-data
 policy=/mnt/software-be/Capabilities/System/Fixture-reload-control.cap/Units/reload-control.unit/Unit.ucl
 printf '%s\n' 'program="reload-control"; activation { exec=true; } attributes=[];' > "$policy"
 chmod 644 "$policy"
 [ "$(cat /var/tmp/software-be-data)" = original ]
 bectl unmount software-policy-test
 bectl activate software-policy-test
 printf '%s\n' SOFTWARE_BE_PREPARED
 /usr/sbin/capsulectl reboot
 ;;
candidate)
 [ "$root_dataset" = policyvm/ROOT/software-policy-test ]
 [ "$(cat /var/tmp/software-be-data)" = candidate ]
 switchboardctl status
 /usr/bin/authority-session-check check none
 if LC_ALL=C /usr/bin/reload-control reload > /tmp/software-be-denial 2>&1; then
  echo UNEXPECTED_CANDIDATE_POLICY_AUTHORITY
  exit 1
 fi
 cat /tmp/software-be-denial
 grep -qx 'reload-control: reload: Operation not permitted' /tmp/software-be-denial
 kldstat -m dtrace
 dtrace -qn 'BEGIN { printf("SOFTWARE_BE_CANDIDATE_DTRACE_PASS\n"); exit(0); }'
 printf '%s\n' SOFTWARE_BE_CANDIDATE_PASS
 bectl activate default
 /usr/sbin/capsulectl reboot
 ;;
rollback)
 [ "$root_dataset" = policyvm/ROOT/default ]
 [ "$(cat /var/tmp/software-be-data)" = original ]
 /usr/bin/reload-control reload
 switchboardctl status
 kldstat -m dtrace
 dtrace -qn 'BEGIN { printf("SOFTWARE_BE_ROLLBACK_DTRACE_PASS\n"); exit(0); }'
 bectl destroy -o software-policy-test
 rm /root/software-be-phase /var/tmp/software-be-data
 printf '%s\n' SOFTWARE_BE_ROLLBACK_PASS SOFTWARE_APPLICATION_PASS
 /usr/sbin/capsulectl poweroff
 ;;
*) exit 2 ;;
esac
