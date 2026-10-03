#!/bin/sh
set -eu
[ "$(hostname)" = auth-policy-vm ] || exit 1
trap 'result=$?; trap - EXIT; set +e; tar --exclude=usr/obj/usr/src/amd64.amd64/sys -cf /dev/vtbd1 -C / usr/obj boot/kernel/kernel root/build.log root/sshd.log root/ssh-tests.log root/login-test.log var/log/capability.log var/log/messages; sync; exit "$result"' EXIT
test "$(df -T / | awk 'NR==2 {print $1}')" = policyvm/ROOT/default
cmp /root/original-policy.ucl /Capabilities/Config/principal-policy.ucl
/usr/bin/policy-probe stop test.policy.storage/worker 0
/usr/bin/policy-probe start test.policy.storage/worker 0
/usr/bin/policy-probe stop system.Auth/bsdauth 1
echo ZFS_BE_ROLLBACK_PASS
