#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Read-only checks in a disposable, signed, plane-on VM. Use as EXTRA_SCRIPT
# with tools/build/fuchsia/vm-provider.sh, after its provider-convergence gate.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
fail() { echo "SIGNED_SYSTEM_FAIL: $*" >&2; exit 1; }
echo SIGNED_SYSTEM_BEGIN
[ "$(sysctl -n kern.mac_capability_isolation.enforce)" = 1 ] ||
    fail 'production capability-device isolation is not enforced'
[ -f /etc/capability/require-signatures ] || fail 'signature enforcement missing'
[ "$(ps -o comm= -p 1 | tr -d ' ')" = capsule ] || fail 'Capsule is not PID 1'
bundles=0
images=0
for bundle in /Capabilities/System/*.cap; do
    [ -d "$bundle" ] || continue
    capsign bundle-verify "$bundle"
    bundles=$((bundles + 1))
    for unit in "$bundle"/Units/*.unit; do
        [ -d "$unit" ] || continue
        [ ! -e "$unit/Unit.ucl" ] || fail "external unit policy retained: $unit"
        for program in "$unit"/bin/*; do
            [ -f "$program" ] || continue
            capsign verify "$program"
            capsign show "$program" > /dev/null
            images=$((images + 1))
        done
    done
done
[ "$bundles" -gt 0 ] && [ "$images" -ge "$bundles" ] || fail 'empty unit inventory'
echo "SIGNED_SYSTEM_END bundles=$bundles images=$images"
