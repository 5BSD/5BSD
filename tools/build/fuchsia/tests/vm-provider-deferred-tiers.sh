#!/bin/sh
# vm-provider.sh: skips that name the tier they belong to are counted on
# their own summary line.  Runs the actual block of vm-provider.sh; no guest.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

sed -n '/^# --- deferred tiers/,/^# --- end of the deferred tiers/p' \
    "$root/vm-provider.sh" > "$work/summary.sh"
grep -q DEFERRED_UNKNOWN "$work/summary.sh"
grep -q DEFERRED_DEVICE_TIER "$work/summary.sh"
log=$work/serial.log
cat > "$log" <<'EOS'
KYUA_SKIPPED_LIST_BEGIN
sys/a:one  ->  skipped: DEFERRED_ENFORCED_TIER: enforce=0  [0.1s]
sys/a:two  ->  skipped: DEFERRED_ENFORCED_TIER: enforce=0  [0.1s]
sys/b:three  ->  skipped: DEFERRED_DEVICE_TIER: claimed  [0.1s]
usr.sbin/x:five  ->  skipped: DEFERRED_PLANEOFF_TIER: test-local stack  [0.1s]
sys/c:four  ->  skipped: something else  [0.1s]
usr.sbin/s:six  ->  skipped: DEFERRED_STACK_TIER: requires a unit issuer  [0.1s]
usr.sbin/s:seven  ->  skipped: DEFERRED_STACK_TIER: requires a unit issuer  [0.1s]
usr.sbin/s:eight  ->  skipped: DEFERRED_PID1_ONLY: protected crypto  [0.1s]
usr.sbin/b:nine  ->  skipped: DEFERRED_SOURCE_TIER: source build frontend requires /usr/src  [0.1s]
sys/m:ten  ->  skipped: Required configuration property 'authority_anchor' not defined  [0.1s]
sys/m:eleven  ->  skipped: DEFERRED_TEST_KERNEL_TIER: needs the handler park  [0.1s]
sys/m:twelve  ->  skipped: DEFERRED_RACCT_ZERO_TIER: needs a boot with kern.racct.enable=0  [0.1s]
sys/v:thirteen  ->  skipped: DEFERRED_QUOTA_KERNEL_TIER: kernel without options QUOTA  [0.1s]
sys/v:fourteen  ->  skipped: DEFERRED_DEBUG_KERNEL_TIER: WITNESS is not running  [0.1s]
sys/v:fifteen  ->  skipped: DEFERRED_DEBUG_KERNEL_TIER: no INVARIANTS  [0.1s]
usr.sbin/c:sixteen  ->  skipped: DEFERRED_GUEST_SETUP: requires the explicit disposable scratch-device input  [0.1s]
sys/dq/d:seventeen  ->  skipped: DEFERRED_PLANEON_TIER: needs Capsule as PID 1; this boot has capability_plane=NO (PID 1 is init)  [0.1s]
KYUA_SKIPPED_LIST_END
EOS
out=$(log=$log sh -c "verdict=VM_CLEAN; . '$work/summary.sh'; echo verdict=\$verdict")
echo "$out" | grep -q '^skipped=17 '
echo "$out" | grep -q '^DEFERRED_TO_ENFORCED_TIER=2 '
echo "$out" | grep -q '^DEFERRED_TO_DEVICE_TIER=1 '
echo "$out" | grep -q '^DEFERRED_TO_PLANEOFF_TIER=1 '
echo "$out" | grep -q '^DEFERRED_TO_PLANEON_TIER=1 '
echo "$out" | grep -q '^DEFERRED_TO_STACK_TIER=2 '
echo "$out" | grep -q '^DEFERRED_PID1_ONLY=1 '
echo "$out" | grep -q '^DEFERRED_TO_SOURCE_TIER=1 '
echo "$out" | grep -q '^DEFERRED_TO_ANCHOR_RUN=1 '
echo "$out" | grep -q '^DEFERRED_TO_TEST_KERNEL_TIER=1 '
echo "$out" | grep -q '^DEFERRED_TO_RACCT_ZERO_TIER=1 '
echo "$out" | grep -q '^DEFERRED_TO_QUOTA_KERNEL_TIER=1 '
echo "$out" | grep -q '^DEFERRED_TO_DEBUG_KERNEL_TIER=2 '
echo "$out" | grep -q '^DEFERRED_GUEST_SETUP=1 '
echo "$out" | grep -q '^verdict=VM_CLEAN$'
if echo "$out" | grep -q 'DEFERRED_UNKNOWN'; then echo "FAIL: known tokens reported as unknown"; exit 1; fi
# A token the runner does not list is reported, every line, and the run is
# not clean; a known token's longer neighbour is not mistaken for it.
cat > "$log" <<'EOS'
KYUA_SKIPPED_LIST_BEGIN
sys/a:one  ->  skipped: DEFERRED_ENFORCED_TIER: enforce=0  [0.1s]
sys/n:new  ->  skipped: DEFERRED_NEW_TIER: a token nobody listed  [0.1s]
sys/n:near  ->  skipped: DEFERRED_STACK_TIER_TWO: a longer name  [0.1s]
KYUA_SKIPPED_LIST_END
EOS
out=$(log=$log sh -c "verdict=VM_CLEAN; . '$work/summary.sh'; echo verdict=\$verdict")
echo "$out" | grep -q '^DEFERRED_UNKNOWN=2 '
echo "$out" | grep -q '^DEFERRED_UNKNOWN: sys/n:new  ->  '
echo "$out" | grep -q '^DEFERRED_UNKNOWN: sys/n:near  ->  '
echo "$out" | grep -q '^verdict=VM_NOT_CLEAN$'
printf 'KYUA_SKIPPED_LIST_BEGIN\nKYUA_SKIPPED_LIST_END\n' > "$log"
out=$(log=$log sh -c "verdict=VM_CLEAN; . '$work/summary.sh'; echo verdict=\$verdict")
if echo "$out" | grep -q 'DEFERRED_TO\|DEFERRED_GUEST_SETUP='; then echo "FAIL: deferred line without deferred skips"; exit 1; fi

echo 'PASS deferred-tier skips are counted per tier; an unlisted DEFERRED_* token is DEFERRED_UNKNOWN, not clean'
