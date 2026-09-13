#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Explicitly invoked in an isolated VM; never an automatic host test.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 NEW_WORK_DIRECTORY EVIDENCE_DIRECTORY" >&2; exit 64; }
base=$1
evidence=$2
case "$base:$evidence" in /*:/*) ;; *) exit 64 ;; esac
srcdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
atf_get_srcdir() { echo "$srcdir"; }
atf_fail() { echo "$*" >&2; exit 1; }
atf_skip() { atf_fail "qualification prerequisite absent: $*"; }
mkdir "$base"
mkdir -p "$evidence"
export CAPD_TEST_CAPSULE=/usr/sbin/capsule
export CAPD_TEST_SWITCHBOARD=/usr/libexec/switchboard
unset SWITCHBOARD_TRACE_INSTALLATION
. "$srcdir/test_helpers.sh"
helper=${AUTHORITY_QUALIFICATION_HELPER:-"$srcdir/authority_qualification"}
[ -x "$helper" ] || helper="$srcdir/../authority_qualification"
trap 'stop_stack >/dev/null 2>&1 || true' EXIT INT TERM
for records in ${AUTHORITY_LOAD_RECORDS:-1000 10000 50000}; do
    mkdir "$base/$records"
    cd "$base/$records"
    export WORK="$(pwd)"
    APPS_DIR="$WORK/Capabilities/System"
    USER_APPS_DIR="$WORK/Capabilities"
    prepare_paths
    write_config
    "$helper" churn "$SWITCHBOARD_LIFECYCLE_DIR" 300 > "$evidence/seed-history-$records.log"
    id=$(/usr/sbin/switchboardctl lifecycle query "$WORK" org.test.load/subject | awk '{print $2}')
    count=${AUTHORITY_LOAD_REQUESTS:-100}
    if [ "$records" = 50000 ] && [ -z "${AUTHORITY_LOAD_REQUESTS:-}" ]; then count=40; fi
    for client in 1 2 3 4 5 6 7 8; do
        make_fixture_svc system "load$client" 'restart = "never";' \
            installation-load org.test.load/subject "$id" "$count" \
            "$WORK/client$client.result" "$WORK/go" >/dev/null
    done
    "$helper" seed "$SWITCHBOARD_LIFECYCLE_DIR" "$records" > "$evidence/seed-$records.log"
    modes=${AUTHORITY_LOAD_MODES:-readonly mixed recovery}
    if [ "$records" = capacity ]; then modes=readonly; fi
    for mode in $modes; do
        rm -f go client*.result client*.result.ready monitor.stop
        start_stack
        manager=$(pgrep -P "$daemon_pid" | head -1)
        for client in 1 2 3 4 5 6 7 8; do
            wait_for_file "client$client.result.ready" 120 || atf_fail 'load fixture not ready'
        done
        (
            while [ ! -e monitor.stop ]; do
                date +%s
                ps -p "$manager" -o pid= -o rss= -o vsz= -o time=
                sleep "${AUTHORITY_SAMPLE_SECONDS:-2}"
            done
        ) > "$evidence/memory-$records-$mode.log" &
        sampler=$!
        writer=
        if [ "$mode" = mixed ]; then
            "$helper" churn "$SWITCHBOARD_LIFECYCLE_DIR" 32 > "$evidence/writer-$records.log" 2>&1 &
            writer=$!
        fi
        echo 1 > go
        for client in 1 2 3 4 5 6 7 8; do
            wait_for_file "client$client.result" 900 || atf_fail 'query load timed out'
            grep -q 'unexpected=0 ' "client$client.result" || atf_fail 'unexpected query state or error'
            if [ "$mode" != mixed ]; then
                grep -q "success=$count busy=0 unexpected=0 " "client$client.result" || atf_fail 'reader did not recover without a writer'
            fi
        done
        [ -z "$writer" ] || wait "$writer"
        touch monitor.stop
        wait "$sampler"
        cat client*.result > "$evidence/queries-$records-$mode.log"
        cp "$logfile" "$evidence/daemon-$records-$mode.log"
        stop_stack
        echo "PASS records=$records clients=8 mode=$mode"
    done
    "$helper" churn "$SWITCHBOARD_LIFECYCLE_DIR" 0 > "$evidence/retention-$records.log"
done
