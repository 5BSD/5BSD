#!/bin/sh
set -eu
[ "$(hostname)" = auth-policy-vm ] || exit 1
[ -f /root/policy-zfs-test ] || exit 1
mkdir -p /mnt/policy-original
bectl mount default /mnt/policy-original
touch /mnt/policy-original/root/policy-rollback-test
bectl unmount default
# Temporary activation should already leave the permanent default unchanged.
test "$(zpool get -H -o value bootfs policyvm)" = policyvm/ROOT/default
echo ZFS_BE_ROLLBACK_READY
shutdown -r now
