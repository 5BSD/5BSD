#!/bin/sh
set -eu
[ "$(hostname)" = auth-policy-vm ] || exit 1
trap 'result=$?; trap - EXIT; set +e; tar -cf /dev/vtbd1 -C / usr/obj root/build.log root/sshd.log root/ssh-tests.log root/login-test.log var/log/capability.log var/log/messages; sync; exit "$result"' EXIT
if [ -f /root/policy-zfs-test ]; then
    test "$(df -T / | awk 'NR==2 {print $1}')" = policyvm/ROOT/policy-empty
    echo ZFS_BE_ACTIVATED_PASS
fi
# Even root now has an empty grant, because that is this boot's explicit policy.
/usr/bin/policy-probe stop test.policy.network/worker 1
/usr/bin/policy-probe stop system.Auth/bsdauth 1
/usr/bin/policy-probe open system.Trace 2
/usr/bin/policy-probe open system.Notify 0
echo NEXT_BOOT_POLICY_PASS
