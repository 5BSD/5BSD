#!/bin/sh
# vm-provider.sh: skips that name the tier they belong to are counted on
# their own summary line, and CAPABILITY_FIXTURES_DIR must hold all three
# fixture modules.  Runs the actual blocks of vm-provider.sh; no guest.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

sed -n '/^nskip=/,/^done$/p' "$root/vm-provider.sh" > "$work/summary.sh"
grep -q DEFERRED_DEVICE_TIER "$work/summary.sh"
log=$work/serial.log
cat > "$log" <<'EOS'
KYUA_SKIPPED_LIST_BEGIN
sys/a:one  ->  skipped: DEFERRED_ENFORCED_TIER: enforce=0  [0.1s]
sys/a:two  ->  skipped: DEFERRED_ENFORCED_TIER: enforce=0  [0.1s]
sys/b:three  ->  skipped: DEFERRED_DEVICE_TIER: claimed  [0.1s]
sys/c:four  ->  skipped: something else  [0.1s]
KYUA_SKIPPED_LIST_END
EOS
out=$(log=$log sh -c ". '$work/summary.sh'")
echo "$out" | grep -q '^skipped=4 '
echo "$out" | grep -q '^DEFERRED_TO_ENFORCED_TIER=2 '
echo "$out" | grep -q '^DEFERRED_TO_DEVICE_TIER=1 '
printf 'KYUA_SKIPPED_LIST_BEGIN\nKYUA_SKIPPED_LIST_END\n' > "$log"
out=$(log=$log sh -c ". '$work/summary.sh'")
if echo "$out" | grep -q DEFERRED_TO; then echo "FAIL: deferred line without deferred skips"; exit 1; fi

# A fixtures directory missing a module is refused before anything is built.
mkdir "$work/fx" "$work/stage"
: > "$work/fx/mac_capability_test_keystore.ko"
: > "$work/fx/mac_capability_test_kernelstore.ko"
status=0
CAPABILITY_FIXTURES_DIR=$work/fx sh "$root/vm-provider.sh" "$work/stage" "$work/run" lib/libfidl 1 > "$work/out" 2>&1 || status=$?
[ "$status" = 2 ]
grep -q 'CAPABILITY_FIXTURES_DIR lacks mac_capability_test_cleanup.ko' "$work/out"
echo 'PASS deferred-tier skips are counted per tier; an incomplete fixtures directory is refused'
