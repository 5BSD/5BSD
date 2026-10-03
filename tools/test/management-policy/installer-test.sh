#!/bin/sh
# Validate installer output with the same parser BSDAuth uses, in the guest.
set -eu
[ "$(hostname)" = auth-policy-vm ] || exit 1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root/etc" "$work/state"
cp /etc/master.passwd /etc/group "$work/root/etc/"
export BSDINSTALL_CHROOT="$work/root" BSDINSTALL_TMPETC="$work/state"
export BSDINSTALL_CAPABILITY_POLICY_NONINTERACTIVE=yes
export BSDINSTALL_CAPABILITY_COMPAT=no
export BSDINSTALL_CAPABILITY_ADMIN_USERS=policyuser
export BSDINSTALL_CAPABILITY_ADMIN_GROUPS=
export BSDINSTALL_CAPABILITY_MANAGE_USERS=otheruser
sh /usr/src/usr.sbin/bsdinstall/scripts/capabilitypolicy
policy="$work/root/Capabilities/Config/principal-policy.ucl"
policyctl validate "$policy"
policyctl explain "$policy" root | grep -Fx 'anointments = [];'
policyctl explain "$policy" policyuser | grep -Fx 'anointments = ["*"];'
policyctl explain "$policy" otheruser | grep -Fx 'anointments = ["system.switchboard.admin"];'
policyctl explain "$policy" otheruser | grep -Fx 'admin_rights = false;'
export BSDINSTALL_CAPABILITY_ADMIN_USERS= BSDINSTALL_CAPABILITY_MANAGE_USERS=
sh /usr/src/usr.sbin/bsdinstall/scripts/capabilitypolicy
policyctl validate "$policy"
policyctl explain "$policy" root | grep -Fx 'anointments = [];'
policyctl explain "$policy" policyuser | grep -Fx 'anointments = [];'
echo INSTALLER_GRANTS_PASS
