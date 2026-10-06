#!/bin/sh
set -eu
[ "$(hostname)" = auth-policy-vm ]
bundle=/Capabilities/System/Fixture-reload-control.cap
unit=$bundle/Units/reload-control.unit
control=$unit/bin/reload-control
policy=$unit/Unit.ucl
"$control" status > /tmp/reload-before
ln "$control" /tmp/registered-control-image
/tmp/registered-control-image status > /tmp/reload-hardlink-before
revoke_policy=/Capabilities/System/Fixture-revocation-probe.cap/Units/revocation-probe.unit/Unit.ucl
/usr/bin/revocation-probe hold-control /tmp/revoke-ready /tmp/revoke-trigger > /tmp/revoke-result 2>&1 &
revoke_pid=$!
tries=0
while [ ! -f /tmp/revoke-ready ]; do
 kill -0 "$revoke_pid"
 tries=$((tries + 1))
 [ "$tries" -lt 30 ]
 sleep 1
done
printf '%s\n' 'program="revocation-probe"; activation { exec=true; } attributes=[];' > "$revoke_policy.next"
chmod 644 "$revoke_policy.next"
mv "$revoke_policy.next" "$revoke_policy"
# Publish each policy completely before the broker reads it.
printf '%s\n' 'program="reload-control"; activation { exec=true; } attributes=[];' > "$policy.next"
chmod 644 "$policy.next"
mv "$policy.next" "$policy"
switchboardctl reload
touch /tmp/revoke-trigger
if ! wait "$revoke_pid"; then
 cat /tmp/revoke-result
 exit 1
fi
cat /tmp/revoke-result
grep -qx SOFTWARE_CACHED_REVOCATION_PASS /tmp/revoke-result
if "$control" reload > /tmp/reload-denied 2>&1; then
 echo UNEXPECTED_REMOVED_ATTRIBUTE_AUTHORITY
 exit 1
fi
if /tmp/registered-control-image reload > /tmp/reload-hardlink-denied 2>&1; then
 echo UNEXPECTED_HARDLINK_ATTRIBUTE_AUTHORITY
 exit 1
fi
printf '%s\n' 'program="reload-control"; activation { exec=true; } attributes=["system.switchboard.admin"];' > "$policy.next"
chmod 644 "$policy.next"
mv "$policy.next" "$policy"
switchboardctl reload
"$control" reload > /tmp/reload-restored
mv "$bundle" /root/retired-reload-control.cap
switchboardctl reload
if /tmp/registered-control-image status > /tmp/reload-removed 2>&1; then
 echo UNEXPECTED_REMOVED_BUNDLE_AUTHORITY
 exit 1
fi
mv /root/retired-reload-control.cap "$bundle"
switchboardctl reload
"$control" reload > /tmp/reload-reinstalled
rm -f /tmp/registered-control-image
printf '%s\n' SOFTWARE_POLICY_RELOAD_PASS
