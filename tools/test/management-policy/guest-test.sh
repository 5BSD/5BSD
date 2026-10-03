#!/bin/sh
# Run only after the disposable guest reboots into its freshly built manager.
set -eu
[ "$(hostname)" = auth-policy-vm ] || exit 1
[ -f /root/policy-build-passed ] || exit 1
# Preserve diagnostics even when an assertion fails, before the runner exits.
trap 'result=$?; trap - EXIT; set +e; tar -cf /dev/vtbd1 -C / usr/obj root/build.log root/sshd.log root/ssh-tests.log root/login-test.log var/log/capability.log var/log/messages; sync; exit "$result"' EXIT
probe=/root/policy-probe
# Ordinary UNIX programs still execute, fork, use pipes, and obey file modes.
su -l policyuser -c 'set -e; d=$(mktemp -d); printf "ordinary UNIX\n" > "$d/file"; cp "$d/file" "$d/copy"; cmp "$d/file" "$d/copy"; cat "$d/file" | wc -l; (sleep 1) & wait; chmod 000 "$d/file"; if cat "$d/file" 2>/dev/null; then exit 1; fi; chmod 600 "$d/file"; rm -r "$d"; echo UNIX_COMPAT_PASS'
# Probe is readable/executable by test users, without write access.
install -m 0555 "$probe" /usr/bin/policy-probe
# An explicit all grant may manage SYSTEM services, never CORE.
"$probe" stop test.policy.storage/worker 0
"$probe" start test.policy.storage/worker 0
"$probe" stop system.Auth/bsdauth 1
cp /Capabilities/Config/principal-policy.ucl /root/original-policy.ucl
# Stage a policy with no grants. The current boot snapshot must not change,
# including for fresh login/SSH sessions tested below.
printf 'principals { default { anointments=[]; admin_rights=false; } }\n' > /Capabilities/Config/principal-policy.next
chmod 644 /Capabilities/Config/principal-policy.next
mv /Capabilities/Config/principal-policy.next /Capabilities/Config/principal-policy.ucl
# Exercise an in-place write too; neither publication style changes this boot.
printf 'principals { default { anointments=[]; admin_rights=false; } }\n' > /Capabilities/Config/principal-policy.ucl
echo POLICY_SNAPSHOT_PASS
sh /usr/src/tools/test/management-policy/ssh-test.sh
sha256 /usr/libexec/switchboard
if [ -f /root/policy-zfs-test ]; then
    # Restore the active BE's persistent policy before cloning a candidate.
    cp /root/original-policy.ucl /Capabilities/Config/principal-policy.ucl
    touch /root/policy-integration-passed
    bectl create policy-empty
    mkdir -p /mnt/policy-candidate
    bectl mount policy-empty /mnt/policy-candidate
    candidate=/mnt/policy-candidate/Capabilities/Config/principal-policy.ucl
    policyctl init > "$candidate"
    policyctl validate "$candidate"
    cmp /root/original-policy.ucl /Capabilities/Config/principal-policy.ucl
    # Config and /var belong to each BE, not shared child datasets.
    test "$(df -T /mnt/policy-candidate/Capabilities/Config | awk 'NR==2 {print $1}')" = policyvm/ROOT/policy-empty
    test "$(df -T /mnt/policy-candidate/var | awk 'NR==2 {print $1}')" = policyvm/ROOT/policy-empty
    bectl unmount policy-empty
    bectl activate -t policy-empty
    echo ZFS_BE_STAGED_PASS
fi
echo POLICY_VM_PASS
