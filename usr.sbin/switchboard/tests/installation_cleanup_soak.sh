#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Explicitly run from an administrator session in a disposable normal-plane VM.
# Exit 85 requests a normal reboot and another invocation with the same paths.
set -eu
[ "$#" = 3 ] || { echo "usage: $0 FIXTURE WORK EVIDENCE" >&2; exit 64; }
fixture=$1 work=$2 evidence=$3
case "$fixture:$work:$evidence" in /*:/*:/*) ;; *) exit 64 ;; esac
[ "$(id -u)" = 0 ] && [ -x "$fixture" ]
[ "$(kenv capability_plane)" = YES ]
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$work" "$evidence"
[ ! -e "$evidence/complete" ] || exit 0
[ ! -e "$evidence/failed" ] || exit 1
trap 'rc=$?; if [ "$rc" != 0 ] && [ "$rc" != 85 ]; then echo "failure status=$rc" > "$evidence/failed"; fi' EXIT
export CLEANUP_QUALIFICATION_PREFIX=${CLEANUP_QUALIFICATION_PREFIX:-org.test.cleanup.soak}
minimum_seconds=${CLEANUP_SOAK_SECONDS:-7200}
minimum_rounds=${CLEANUP_SOAK_ROUNDS:-200}
minimum_reboots=${CLEANUP_SOAK_REBOOTS:-10}
reboot_interval=${CLEANUP_SOAK_REBOOT_INTERVAL:-20}
for value in "$minimum_seconds" "$minimum_rounds" "$minimum_reboots" "$reboot_interval"; do
    case "$value" in ''|*[!0-9]*) exit 64 ;; esac
done
[ "$reboot_interval" -gt 0 ]
fail() { echo "FAIL: $*" >&2; exit 1; }
read_authority()
{
    for attempt in $(jot 120); do
        if switchboardctl lifecycle "$@"; then return 0; else rc=$?; fi
        [ "$rc" = 75 ] || return "$rc"
        sleep .1
    done
    return 75
}
if [ ! -e "$work/start" ]; then
    for suffix in a b; do
        state=$(read_authority query / "$CLEANUP_QUALIFICATION_PREFIX.$suffix/main")
        printf '%s\n' "$state" | grep -q ' unknown ' || fail 'soak labels already exist'
    done
    date +%s > "$work/start"
    echo 0 > "$work/round"
    echo 0 > "$work/reboots"
fi
round=$(cat "$work/round")
reboots=$(cat "$work/reboots")
boot=$(sysctl -n kern.boottime)
if [ -e "$work/reboot-requested" ]; then
    [ "$boot" != "$(cat "$work/reboot-requested")" ] || fail 'requested reboot has not occurred'
    while read -r label identity; do
        read_authority query / "$label" "$identity" | grep -q ' removed ' || fail 'completed identity lost on reboot'
    done < "$work/last-identities"
    reboots=$((reboots + 1))
    echo "$reboots" > "$work/reboots"
    rm "$work/reboot-requested"
    echo "PASS reboot=$reboots boot=$boot" >> "$evidence/reboots.log"
fi
retire()
{
    label=$1 seq=$2
    source=$(printf 'bundle:%s@%020d' "${label%/main}" "$seq")
    op=$(switchboardctl lifecycle issue /)
    switchboardctl lifecycle prepare / "$op" "$source" "$label"
    published=$(printf '/Capabilities/%s@%020d.cap' "${label%/main}" "$seq")
    mv "$published" "$round_work/removed/"
    sync
    switchboardctl lifecycle retire / "$op" "$source" "$label"
}
while :; do
    next=$((round + 1))
    round_work=$work/round-$next
    sh "$script_dir/installation_cleanup_qualification.sh" "$fixture" "$round_work"
    read -r a aid <<END
$(head -1 "$round_work/live-identities")
END
    read -r b bid <<END
$(tail -1 "$round_work/live-identities")
END
    if [ -e "$work/last-identities" ]; then
        ! grep -Fq "$aid" "$work/last-identities" || fail 'reinstall reused identity'
        ! grep -Fq "$bid" "$work/last-identities" || fail 'peer reinstall reused identity'
    fi
    retire "$a" 3
    retire "$b" 1
    while read -r label identity; do
        for attempt in $(jot 120); do
            if switchboardctl lifecycle cleanup / "$label" "$identity" > "$round_work/complete.tmp"; then break; fi
            sleep 1
        done
        grep -q 'cleanup=complete' "$round_work/complete.tmp" || fail 'final cleanup pending'
        [ "$(grep -c acknowledged "$round_work/complete.tmp")" = 5 ] || fail 'missing final receipts'
        cat "$round_work/complete.tmp" >> "$round_work/final-receipts"
    done < "$round_work/live-identities"
    while read -r dataset; do
        ! zfs list -H "$dataset" >/dev/null 2>&1 || fail 'private dataset leaked'
    done < "$round_work/live-datasets"
    ! jls -n path | grep -Fq "path=$round_work/jails/" || fail 'jail leaked'
    switchboardctl reload
    switchboardctl status > "$round_work/final-status"
    ps ax -o pid -o rss -o command > "$round_work/process-sample"
    read_authority status / > "$round_work/final-ledger"
    rows=$(wc -l < "$round_work/final-ledger" | tr -d ' ')
    [ "$rows" -lt 8192 ] || fail 'history failed to remain bounded'
    cp "$round_work/live-identities" "$work/last-identities"
    round=$next
    echo "$round" > "$work/round.next"
    mv "$work/round.next" "$work/round"
    elapsed=$(($(date +%s) - $(cat "$work/start")))
    echo "PASS round=$round elapsed_s=$elapsed reboots=$reboots ledger_rows=$rows" >> "$evidence/progress.log"
    if [ "$round" -ge "$minimum_rounds" ] && [ "$elapsed" -ge "$minimum_seconds" ] && [ "$reboots" -ge "$minimum_reboots" ]; then
        cp "$evidence/progress.log" "$evidence/complete"
        sync
        exit 0
    fi
    if [ $((round % reboot_interval)) = 0 ] && [ "$reboots" -lt "$minimum_reboots" ]; then
        printf '%s\n' "$boot" > "$work/reboot-requested"
        sync
        exit 85
    fi
done
