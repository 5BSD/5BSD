#!/bin/sh
set -eux
[ "$(hostname)" = auth-policy-vm ]
[ "$(mount -p | awk '$2 == "/" {print $1}')" = policyvm/ROOT/default ]
[ ! -e /Capabilities/System/Auth.cap ]
fixture=/root/retired-package-fixtures
pkg=$fixture/pkg-static
mountpoint=/mnt/retired-package-test
bectl create retired-package-test
mkdir -p "$mountpoint"
bectl mount retired-package-test "$mountpoint"
# This test never activates or boots the retired provider.
[ "$(df -P "$mountpoint/var" | awk 'END {print $1}')" = policyvm/ROOT/retired-package-test ]
for archive in "$fixture"/5BSD-bsdauth*.pkg; do
 "$pkg" -r "$mountpoint" add -M "$archive"
done
[ -f "$mountpoint/Capabilities/System/Auth.cap/Bundle.ucl" ]
"$pkg" -r "$mountpoint" query '%n' | sort > /tmp/retired-before
[ "$(grep -c '^5BSD-bsdauth' /tmp/retired-before)" -eq 4 ]
policy=$mountpoint/Capabilities/Config/principal-policy.ucl
printf '\n# local retired policy retained for review\n' >> "$policy"
cp "$policy" /tmp/retired-policy-copy
# Preserve edited configuration explicitly before removing its owning package.
mkdir -p "$mountpoint/root/retired-policy"
cp "$policy" "$mountpoint/root/retired-policy/principal-policy.ucl"
"$pkg" -r "$mountpoint" delete -fy -x '^5BSD-bsdauth($|-)'
if "$pkg" -r "$mountpoint" query '%n' | grep '^5BSD-bsdauth'; then exit 1; fi
[ ! -e "$mountpoint/Capabilities/System/Auth.cap/Bundle.ucl" ]
[ ! -e "$mountpoint/Capabilities/System/Auth.cap/Units/bsdauth.unit/bin/BSDAuth" ]
cmp /tmp/retired-policy-copy "$mountpoint/root/retired-policy/principal-policy.ucl"
# Any pkg-preserved local config is inert; remove it after archiving.
rm -f "$policy"
[ ! -e /Capabilities/System/Auth.cap ]
[ ! -e /root/retired-policy ]
bectl unmount retired-package-test
bectl destroy -o retired-package-test
printf '%s\n' SOFTWARE_RETIRED_PACKAGE_PASS
