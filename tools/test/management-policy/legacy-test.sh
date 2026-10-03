#!/bin/sh
# Reboot into the same freshly built manager with the feature disabled.
set -eu
[ "$(hostname)" = auth-policy-vm ]
[ "$(kenv switchboard_management_policy)" = NO ]
probe=/usr/bin/policy-probe
"$probe" stop test.policy.network/worker 0
su -l policyuser -c '/usr/bin/policy-probe start test.policy.network/worker 1'
"$probe" start test.policy.network/worker 0
"$probe" stop system.Auth/bsdauth 1
/usr/sbin/sshd -f /root/sshd-policy.conf -E /root/sshd.log
timeout 60 ssh -F /root/ssh-client.conf -o BatchMode=yes policyuser@policy-vm \
    'set -e; [ "$(id -u)" = 2001 ]; /usr/bin/policy-probe open system.Notify 0; /usr/bin/policy-probe open system.Trace 0; /usr/bin/policy-probe stop test.policy.network/worker 1'
kill "$(cat /var/run/sshd-policy.pid)"
echo LEGACY_COMPAT_PASS
sha256 /usr/libexec/switchboard
tar -cf /dev/vtbd1 -C / usr/obj root/build.log root/sshd.log root/ssh-tests.log root/login-test.log var/log/capability.log var/log/messages
sync
