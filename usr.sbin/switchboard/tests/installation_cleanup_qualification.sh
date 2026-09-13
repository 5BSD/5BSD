#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Run explicitly as root in a disposable, normally booted capability-plane VM.
# Usage: installation_cleanup_qualification.sh FIXTURE NEW_WORK_DIRECTORY
set -eu
fixture=$1
work=$2
[ "$(id -u)" = 0 ] && [ -x "$fixture" ] && [ ! -e "$work" ]
case "$work" in /*) ;; *) exit 64 ;; esac
mkdir -m 755 "$work"
exec > "$work/results.log" 2>&1
software=$(sysctl -n kern.crypto.allow_soft)
# TCG guests may have no accelerated crypto backend. Restore this test setting.
trap 'sysctl kern.crypto.allow_soft="$software" >/dev/null' EXIT
sysctl kern.crypto.allow_soft=1
prefix=${CLEANUP_QUALIFICATION_PREFIX:-org.test.cleanup.qual.$$}
case "$prefix" in ""|*[!A-Za-z0-9._-]*) exit 64 ;; esac
a=$prefix.a/main
b=$prefix.b/main
printf 'work=%s\n' "$work"
fail() { echo "FAIL: $*"; exit 1; }
authority_read()
{
    for read_attempt in $(jot 120); do
        if switchboardctl lifecycle "$@"; then return 0; else read_status=$?; fi
        [ "$read_status" = 75 ] || return "$read_status"
        sleep .1
    done
    return 75
}
query_id()
{
    answer=$(authority_read query / "$1") || return
    printf '%s\n' "$answer" | awk '{print $2}'
}
installed()
{
    answer=$(authority_read query / "$1" "$2") || return
    printf '%s\n' "$answer" | grep -q ' installed '
}
make_bundle()
{
    bid=$1 seq=$2 role=$3
    dir="$work/staging/$role-$seq.cap"
    mkdir -p "$dir/Units/main.unit/bin" "$work/results/$role" "$work/jails/$role"
    chown 976:976 "$work/results/$role"
    cp "$fixture" "$dir/Units/main.unit/bin/main"
    chmod 755 "$dir/Units/main.unit/bin/main"
    cat > "$dir/Bundle.ucl" <<UCL
schema = "org.5bsd.capability-bundle";
schema_version = 1;
bundle_id = "$bid";
version = "1.0.$seq";
sequence = $seq;
author = "test";
publisher = "org.test";
units = ["main"];
UCL
    cat > "$dir/Units/main.unit/Unit.ucl" <<UCL
domain = "system";
activation { boot = true; }
restart = "never";
directories = ["$work/results/$role"];
arguments = ["$work/results/$role", "resources", "$work/jails/$role"];
UCL
    switchboardctl install "$dir"
}
wait_resources()
{
    role=$1
    for attempt in $(jot 120); do
        if grep -q '^PASS resources=5$' "$work/results/$role/resources" 2>/dev/null; then
            cat "$work/results/$role/resources"
            return
        fi
        sleep 1
    done
    cat "$work/results/$role/resources" 2>/dev/null || true
    fail "resources unavailable for $role"
}
dataset() { sed -n 's/^filesystem=//p' "$work/results/$1/resources"; }
has_dataset() { zfs list -H "$1" >/dev/null 2>&1; }
has_jail() { jls -n path | grep -Fqx "path=$work/jails/$1"; }
remove_version()
{
    label=$1 seq=$2 bid=${1%/main}
    operation=$(switchboardctl lifecycle issue /)
    source=$(printf 'bundle:%s@%020d' "$bid" "$seq")
    switchboardctl lifecycle prepare / "$operation" "$source" "$label"
    published=$(printf '/Capabilities/%s@%020d.cap' "$bid" "$seq")
    mkdir -p "$work/removed"
    mv "$published" "$work/removed/"
    sync
    switchboardctl lifecycle retire / "$operation" "$source" "$label"
    printf '%s %s %s\n' "$operation" "$source" "$label" >> "$work/removals"
}
wait_complete()
{
    label=$1 id=$2 output=$3
    for attempt in $(jot 120); do
        if switchboardctl lifecycle cleanup / "$label" "$id" > "$output"; then
            grep -q 'cleanup=complete' "$output" || fail 'missing completion marker'
            [ "$(grep -c 'acknowledged' "$output")" = 5 ] || fail 'missing provider receipts'
            return
        fi
        sleep 1
    done
    cat "$output"
    fail 'cleanup did not complete'
}
make_bundle "$prefix.a" 1 a
make_bundle "$prefix.b" 1 b
switchboardctl reload
wait_resources a
wait_resources b
old=$(query_id "$a")
peer=$(query_id "$b")
old_dataset=$(dataset a)
peer_dataset=$(dataset b)
# Updating and removing a superseded source retain the exact private owner.
previous_pid=$(sed -n 's/^ready pid=//p' "$work/results/a/resources")
make_bundle "$prefix.a" 2 a
switchboardctl reload
for attempt in $(jot 120); do
    current_pid=$(sed -n 's/^ready pid=//p' "$work/results/a/resources")
    [ -n "$current_pid" ] && [ "$current_pid" != "$previous_pid" ] && break
    sleep 1
done
[ "$current_pid" != "$previous_pid" ] || fail "upgrade did not restart fixture"
wait_resources a
[ "$(query_id "$a")" = "$old" ] || fail 'upgrade changed identity'
remove_version "$a" 1
installed "$a" "$old" || fail 'superseded removal ended installation'
has_dataset "$old_dataset" || fail 'upgrade removed storage'
op=$(switchboardctl lifecycle issue /)
switchboardctl lifecycle prepare / "$op" "bundle:$prefix.a@00000000000000000002" "$a"
switchboardctl lifecycle cancel / "$op" "bundle:$prefix.a@00000000000000000002" "$a"
installed "$a" "$old" || fail 'cancelled removal did not restore installation'
has_dataset "$old_dataset" || fail 'cancelled removal deleted storage'
echo 'PASS upgrade, multiple sources, and cancellation'
# An operator-disabled provider must stay unavailable, with its work durable.
switchboardctl disable system.Waspnest
remove_version "$a" 2
for attempt in $(jot 120); do
    switchboardctl lifecycle cleanup / "$a" "$old" > "$work/pending" || [ "$?" = 75 ]
    if [ "$(grep -c acknowledged "$work/pending" || true)" = 4 ]; then break; fi
    sleep 1
done
grep -q 'provider=system.Waspnest/waspnest pending' "$work/pending" || fail 'disabled provider was acknowledged'
[ "$(grep -c acknowledged "$work/pending")" = 4 ] || fail 'other providers did not finish'
! has_dataset "$old_dataset" || fail 'old storage survived successful receipt'
! has_jail a || fail 'old jail survived successful receipt'
has_dataset "$peer_dataset" && has_jail b || fail 'peer resources were removed'
heartbeat=$(cat "$work/results/b/heartbeat")
sleep 2
[ "$(cat "$work/results/b/heartbeat")" -gt "$heartbeat" ] || fail 'peer storage session stopped working'
echo 'PASS disabled-provider pending state and peer preservation'
# A replacement is valid while old cleanup remains pending.
make_bundle "$prefix.a" 3 replacement
switchboardctl reload
fresh=$(query_id "$a")
[ "$fresh" != "$old" ] || fail 'reinstall reused old identity'
switchboardctl enable system.Waspnest
# Reload retains a stopped slot; start explicitly after the missing provider is enabled.
for attempt in $(jot 30); do
    switchboardctl start "$a" >/dev/null 2>&1 || true
    grep -q '^PASS resources=5$' "$work/results/replacement/resources" 2>/dev/null && break
    sleep 1
done
wait_resources replacement
wait_complete "$a" "$old" "$work/old-complete"
fresh_dataset=$(dataset replacement)
[ "$fresh_dataset" != "$old_dataset" ] || fail 'replacement reused private storage'
has_dataset "$fresh_dataset" && has_dataset "$peer_dataset" || fail 'cleanup removed live storage'
has_jail replacement && has_jail b || fail 'cleanup removed live jail'
# Replaying the original completed transaction must not target the replacement.
while read -r operation source label; do
    switchboardctl lifecycle retire / "$operation" "$source" "$label"
done < "$work/removals"
installed "$a" "$fresh" && installed "$b" "$peer" || fail 'late hook removed live installation'
echo 'PASS replacement, late completion, and all five provider receipts'
printf '%s %s\n%s %s\n' "$a" "$fresh" "$b" "$peer" > "$work/live-identities"
printf '%s\n%s\n' "$fresh_dataset" "$peer_dataset" > "$work/live-datasets"
switchboardctl status > "$work/status"
authority_read status / > "$work/ledger"
echo 'PASS normal-plane cleanup qualification'
