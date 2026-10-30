#!/bin/sh
set -eu
[ "$(hostname)" = auth-policy-vm ]
root_dataset=$(mount -p | awk '$2 == "/" {print $1}')
# Admission check for this disposable fixture, not an atomic retirement API.
# The caller supplies identities captured after successful candidate creation.
retirement_check()
{
 candidate=$1
 candidate_guid=$2
 survivor=$3
 survivor_guid=$4
 for identity in "$candidate_guid" "$survivor_guid"; do
  case "$identity" in ''|*[!0-9]*|0) return 1 ;; esac
 done
 [ "$candidate" != "$survivor" ] || return 1
 [ "$root_dataset" = "$survivor" ] || return 1
 actual=$(zfs get -Hp -o value guid "$candidate") || return 1
 [ "$actual" = "$candidate_guid" ] || return 1
 actual=$(zfs get -Hp -o value guid "$survivor") || return 1
 [ "$actual" = "$survivor_guid" ] || return 1
 actual=$(zfs get -H -o value mounted "$candidate") || return 1
 [ "$actual" = no ] || return 1
 actual=$(zpool get -H -o value bootfs "${candidate%%/*}") || return 1
 [ "$actual" = "$survivor" ] || return 1
 # bootfs does not include a one-time selection. Do not let bectl destroy
 # silently clear bootonce while this fixture reports an unused BE removed.
 listing=$(bectl -r "${candidate%/*}" list -H) || return 1
 printf '%s\n' "$listing" | awk -F '\t' -v candidate="${candidate##*/}" '
  $1 == candidate { count++; if (NF != 5 || $2 != "-" || $3 != "-") bad=1 }
  END { exit !(count == 1 && !bad) }'
}
# End retirement admission helper.
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
 [ ! -e /root/software-be-identities ]
 bectl create software-policy-test
 zfs get -Hp -o value guid policyvm/ROOT/software-policy-test > /root/software-be-identities
 zfs get -Hp -o value guid policyvm/ROOT/default >> /root/software-be-identities
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
 [ "$(wc -l < /root/software-be-identities | tr -d ' ')" = 2 ]
 candidate_guid=$(sed -n '1p' /root/software-be-identities)
 survivor_guid=$(sed -n '2p' /root/software-be-identities)
 retirement_check policyvm/ROOT/software-policy-test "$candidate_guid" \
     policyvm/ROOT/default "$survivor_guid"
 bectl destroy -o software-policy-test
 # Successful deletion must be observable, while the rollback identity survives.
 zfs list -H -o name -r policyvm/ROOT > /tmp/software-be-survivors
 if grep -qx policyvm/ROOT/software-policy-test /tmp/software-be-survivors; then
  echo UNEXPECTED_RETIRED_BE_PRESENT
  exit 1
 fi
 actual=$(zfs get -Hp -o value guid policyvm/ROOT/default)
 [ "$actual" = "$survivor_guid" ]
 actual=$(zpool get -H -o value bootfs policyvm)
 [ "$actual" = policyvm/ROOT/default ]
 [ "$(cat /var/tmp/software-be-data)" = original ]
 rm /root/software-be-identities
 rm /root/software-be-phase /var/tmp/software-be-data
 printf '%s\n' SOFTWARE_BE_ROLLBACK_PASS SOFTWARE_APPLICATION_PASS
 /usr/sbin/capsulectl poweroff
 ;;
*) exit 2 ;;
esac
