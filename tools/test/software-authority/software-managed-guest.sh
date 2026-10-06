#!/bin/sh
set -eu
[ "$(hostname)" = auth-policy-vm ]
for expectation in allow deny; do
 mv "/root/managed-fixtures/Fixture-managed-$expectation.cap" /Capabilities/System/
done
switchboardctl reload
tries=0
while [ ! -f /tmp/managed-allow-result ] || [ ! -f /tmp/managed-deny-result ]; do
 tries=$((tries + 1))
 if [ "$tries" -ge 45 ]; then
  switchboardctl status
  tail -100 /var/log/capability.log
  echo MANAGED_CONTROL_TIMEOUT
  exit 1
 fi
 sleep 1
done
grep -qx allow /tmp/managed-allow-result
grep -qx deny /tmp/managed-deny-result
printf '%s\n' SOFTWARE_MANAGED_CONTROL_PASS
