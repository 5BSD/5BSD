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
elfcache verify /usr/libdata/5bsd/cache/elf.cache
# These are live providers launched by SwitchBoard with separate capability
# bootstrap descriptors, rather than synthetic loader-only workers.
for label in system.Time/bsdtime system.Network/bsdnetwork system.Log/bsdlog; do
    counters=$(switchboardctl cache-status "$label") ||
        fail "cannot query cache mappings: $label"
    printf '%s\n' "$counters" | awk '
        { for (i = 1; i <= NF; i++) {
            split($i, field, "=")
            if (field[1] == "cache_selected") selected = field[2]
            if (field[1] == "executable_mappings") mappings = field[2]
        } }
        END { exit !(selected == 1 && mappings > 0) }' ||
        fail "no executable shared-cache mappings: $label"
    echo "SIGNED_PROVIDER_CACHE_OK label=$label $counters"
done
# A label query must not silently become an arbitrary PID query, and a
# missing unit must produce a broker error rather than plausible zero counts.
for label in system.CacheProbe/nonexistent 1; do
    if error=$(switchboardctl cache-status "$label" 2>&1); then
        fail "cache query accepted unknown unit: $label"
    fi
    case "$error" in
    *'cache-status: No such file or directory'*) ;;
    *) fail "unexpected unknown-unit error: $error" ;;
    esac
done
echo SIGNED_PROVIDER_CACHE_UNKNOWN_REFUSED
echo "SIGNED_SYSTEM_END bundles=$bundles images=$images"
