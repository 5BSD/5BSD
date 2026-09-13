#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Explicit operator test for a disposable, plane-free VM. Resume after reboot
# from rc.local using daemon(8). Never run against the host's installation root.
set -eu
[ "$#" -eq 3 ] || { echo "usage: $0 QA_DIRECTORY NEW_OR_RESUMED_WORK EVIDENCE" >&2; exit 64; }
qa=$1
work=$2
evidence=$3
case "$qa:$work:$evidence" in /*:/*:/*) ;; *) exit 64 ;; esac
[ "$(id -u)" -eq 0 ] || exit 77
mkdir -p "$work" "$evidence"
[ ! -e "$evidence/complete" ] || exit 0
[ ! -e "$evidence/failed" ] || exit 1
trap 'status=$?; if [ "$status" -ne 0 ]; then echo "failure status=$status" > "$evidence/failed"; fi' EXIT
export CAPD_TEST_CAPSULE=/usr/sbin/capsule
export CAPD_TEST_SWITCHBOARD=/usr/libexec/switchboard
export CAPD_TEST_ARTIFACTS="$evidence/stack"
helper=$qa/authority_qualification
[ -x /usr/local/sbin/pkg ]
[ -x /usr/libexec/switchboard-pkg-reclaim ]
sysctl -n kern.boottime >> "$evidence/boots.log"
store=$work/root/Capabilities/Config/switchboard/lifecycle
mkdir -p "$store"
chmod 0700 "$store"
[ -e "$work/start" ] || date +%s > "$work/start"
[ -e "$work/round" ] || echo 0 > "$work/round"
[ -e "$work/reboots" ] || echo 0 > "$work/reboots"
start=$(cat "$work/start")
round=$(cat "$work/round")
reboots=$(cat "$work/reboots")
minimum_seconds=${AUTHORITY_SOAK_SECONDS:-3600}
minimum_rounds=${AUTHORITY_SOAK_ROUNDS:-200}
maximum_reboots=${AUTHORITY_SOAK_REBOOTS:-10}
"$helper" churn "$store" 0 > "$evidence/resume-$round.log"
id=$(/usr/sbin/switchboardctl lifecycle query "$work/root" org.test.load/subject | awk '{print $2}')
if [ -e "$work/identity" ]; then
    [ "$id" = "$(cat "$work/identity")" ]
else
    echo "$id" > "$work/identity"
fi
while :; do
    round=$((round + 1))
    "$helper" churn "$store" 100 > "$evidence/churn-$round.log"
    cd "$qa/cli"
    kyua test --results-file="$evidence/pkg-$round.db" pkg_lifecycle_live_test > "$evidence/pkg-$round.log" 2>&1
    grep -q '2/2 passed (0 broken, 0 failed, 0 skipped)' "$evidence/pkg-$round.log"
    cd "$qa/tests"
    kyua test --results-file="$evidence/restart-$round.db" \
        switchboard_integration_test:installation_authority_live_query > "$evidence/restart-$round.log" 2>&1
    grep -q '1/1 passed (0 broken, 0 failed, 0 skipped)' "$evidence/restart-$round.log"
    current=$(/usr/sbin/switchboardctl lifecycle query "$work/root" org.test.load/subject | awk '{print $2}')
    [ "$id" = "$current" ]
    echo "$round" > "$work/round.next"
    mv "$work/round.next" "$work/round"
    elapsed=$(($(date +%s) - start))
    echo "PASS round=$round elapsed_s=$elapsed reboots=$reboots identity=$id" >> "$evidence/progress.log"
    if [ "$round" -ge "$minimum_rounds" ] && [ "$elapsed" -ge "$minimum_seconds" ] && [ "$reboots" -ge "$maximum_reboots" ]; then
        cp "$evidence/progress.log" "$evidence/complete"
        sync
        exit 0
    fi
    if [ $((round % 20)) -eq 0 ] && [ "$reboots" -lt "$maximum_reboots" ]; then
        reboots=$((reboots + 1))
        echo "$reboots" > "$work/reboots"
        sync
        exec /root/reboot-qualified
    fi
done
