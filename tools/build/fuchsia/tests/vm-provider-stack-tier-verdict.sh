#!/bin/sh
# vm-provider.sh STACK_TIER=1: the verdict reads the results disk's tier.txt,
# not only the console, so a run whose console shows no STACK_TIER_FAIL line
# but whose tier.txt says the tier was not met, or that its issuers were not
# created or not freed, is not clean.  Runs the actual block; no guest.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }
sed -n '/^# --- stack-tier verdict/,/^# --- end of the stack-tier verdict$/p' \
    "$root/vm-provider.sh" > "$work/block.sh"
grep -q 'stack_tier_met()' "$work/block.sh" || fail 'no block'
grep -q '\[ \$guest_off = 1 \] && stack_tier_met &&$' "$root/vm-provider.sh" ||
    fail 'the verdict does not call stack_tier_met'
t=$work/results/kyua-results/tier.txt
mkdir -p "${t%/*}"
met() { sh -c 'stack_tier_request=$2; . "$1"; stack_tier_met' met "$work/block.sh" "$1"; }
export work
tier() { printf '%s\n' "$@" > "$t"; }
good='STACK_TIER: test issuers created=3 live=0 state=test'
# The console of these runs has no STACK_TIER_FAIL line: only tier.txt decides.
tier 'stack-tier=yes' "$good"
met 1 || fail 'a met stack tier not clean'
tier 'stack-tier=no' "$good"
met 1 && fail 'stack-tier=no clean'
tier 'stack-tier=yes'
met 1 && fail 'no STACK_TIER line clean'
tier 'stack-tier=yes' 'STACK_TIER: test issuers created=0 live=0 state=test'
met 1 && fail 'no issuer created clean'
tier 'stack-tier=yes' 'STACK_TIER: test issuers created=3 live=1 state=test'
met 1 && fail 'a live issuer clean'
tier 'stack-tier=yes' 'STACK_TIER: test issuers created=3 live=0 state=test' \
    'STACK_TIER: test issuers created=3 live=2 state=test'
met 1 && fail 'a later live count ignored'
rm -f "$t"
met 1 && fail 'a missing tier.txt clean'
met 0 || fail 'STACK_TIER=0 needs tier.txt'
echo 'PASS STACK_TIER=1 needs stack-tier=yes and issuers created and freed in tier.txt'
