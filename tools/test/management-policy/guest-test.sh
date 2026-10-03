#!/bin/sh
# Run only after the disposable guest reboots into its freshly built manager.
set -eu
[ "$(hostname)" = auth-policy-vm ] || exit 1
[ -f /root/policy-build-passed ] || exit 1
[ "$(kenv switchboard_management_policy)" = YES ] || exit 1
# Preserve diagnostics even when an assertion fails, before the runner exits.
trap 'result=$?; trap - EXIT; set +e; tar -cf /dev/vtbd1 -C / usr/obj root/build.log root/sshd.log root/ssh-tests.log root/login-test.log var/log/capability.log var/log/messages; sync; exit "$result"' EXIT
probe=/root/policy-probe
# Ordinary UNIX programs still execute, fork, use pipes, and obey file modes.
su -l policyuser -c 'set -e; d=$(mktemp -d); printf "ordinary UNIX\n" > "$d/file"; cp "$d/file" "$d/copy"; cmp "$d/file" "$d/copy"; cat "$d/file" | wc -l; (sleep 1) & wait; chmod 000 "$d/file"; if cat "$d/file" 2>/dev/null; then exit 1; fi; chmod 600 "$d/file"; rm -r "$d"; echo UNIX_COMPAT_PASS'
# Probe is readable/executable by test users, without write access.
install -m 0555 "$probe" /usr/bin/policy-probe
su -l policyuser -c '/usr/bin/policy-probe stop test.policy.network/worker 0'
sleep 2
su -l policyuser -c '/usr/bin/policy-probe start test.policy.network/worker 0'
sleep 2
su -l policyuser -c '/usr/bin/policy-probe stop test.policy.storage/worker 1'
su -l otheruser -c '/usr/bin/policy-probe stop test.policy.network/worker 1'
su -l policyuser -c '/usr/bin/policy-probe stop system.Auth/bsdauth 1'
su -l policyuser -c '/usr/bin/policy-probe reload "" 1'
# A broad existing root grant cannot bypass an explicit deny.
"$probe" stop test.policy.storage/worker 1
"$probe" stop system.Auth/bsdauth 1
# Retain a real channel across atomic publication of a deny policy.
"$probe" revoke test.policy.network/worker 0
cp /root/policy.allow /Capabilities/Config/switchboard/management-policy.next
chmod 644 /Capabilities/Config/switchboard/management-policy.next
mv /Capabilities/Config/switchboard/management-policy.next /Capabilities/Config/switchboard/management-policy.ucl
sleep 2
su -l policyuser -c '/usr/bin/policy-probe start test.policy.network/worker 0'
# Malformed and missing policy never reactivate the admin bypass.
printf 'broken\n' > /Capabilities/Config/switchboard/management-policy.next
mv /Capabilities/Config/switchboard/management-policy.next /Capabilities/Config/switchboard/management-policy.ucl
"$probe" stop test.policy.network/worker 1
rm /Capabilities/Config/switchboard/management-policy.ucl
"$probe" stop test.policy.network/worker 1
cp /root/policy.allow /Capabilities/Config/switchboard/management-policy.ucl
chmod 644 /Capabilities/Config/switchboard/management-policy.ucl
su -l policyuser -c '/usr/bin/policy-probe stop test.policy.network/worker 0'
# An untrusted or nonregular policy must deny without blocking the manager.
chmod 666 /Capabilities/Config/switchboard/management-policy.ucl
"$probe" stop test.policy.network/worker 1
chmod 644 /Capabilities/Config/switchboard/management-policy.ucl
chown policyuser /Capabilities/Config/switchboard/management-policy.ucl
"$probe" stop test.policy.network/worker 1
chown root /Capabilities/Config/switchboard/management-policy.ucl
rm /Capabilities/Config/switchboard/management-policy.ucl
ln -s /root/policy.allow /Capabilities/Config/switchboard/management-policy.ucl
"$probe" stop test.policy.network/worker 1
rm /Capabilities/Config/switchboard/management-policy.ucl
mkfifo /Capabilities/Config/switchboard/management-policy.ucl
timeout 10 "$probe" stop test.policy.network/worker 1
rm /Capabilities/Config/switchboard/management-policy.ucl
cp /root/policy.allow /Capabilities/Config/switchboard/management-policy.ucl
chmod 644 /Capabilities/Config/switchboard/management-policy.ucl
echo POLICY_FILE_TRUST_PASS
sh /usr/src/tools/test/management-policy/ssh-test.sh
sha256 /usr/libexec/switchboard
echo POLICY_VM_PASS
