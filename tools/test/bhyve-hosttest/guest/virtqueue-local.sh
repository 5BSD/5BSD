#!/bin/sh
# Observe negotiated root queue mode and actual I/O before/after restore.
set -eu
case "${1:-no}" in no) mode=0 ;; yes) mode=1 ;; *) exit 2 ;; esac
D=$(mktemp -d /tmp/ht-virtqueue.XXXXXX) || exit 1
trap 'rm -rf "$D"' EXIT
trap 'exit 130' HUP INT TERM
workload=$(dirname "$0")/virtqueue-workload.sh
if timeout -k 2 20 dtrace -q \
    -n 'virtqueue::enqueue:result /stringof(arg0) == "vtblk0 request.0" && arg5 == 0/ { @s["SUBMIT", arg1, arg2] = count(); }' \
    -n 'virtqueue::dequeue:complete /stringof(arg0) == "vtblk0 request.0"/ { @c["COMPLETE", arg1, arg2] = count(); }' \
    -c "sh $workload" > "$D/out" 2> "$D/err" &&
    awk -v mode="$mode" '
    NF == 0 { next }
    $0 == "VIRTQUEUE-WORK-DONE" { done++; next }
    NF != 4 || ($1 != "SUBMIT" && $1 != "COMPLETE") ||
        $2 != "0" || $3 !~ /^[01]$/ || $3 != mode ||
        $4 !~ /^[0-9]+$/ || $4 + 0 <= 0 { bad=1; next }
    $1 == "SUBMIT" { submitted += $4 }
    $1 == "COMPLETE" { completed += $4 }
    END { exit (bad || done != 1 || submitted <= 0 || completed <= 0) }
    ' "$D/out"; then
    echo "VIRTQUEUE-LOCAL-OK packed=$mode"
else
    sed 's/^/VIRTQUEUE-OUTPUT /' "$D/out"
    sed 's/^/VIRTQUEUE-ERROR /' "$D/err"
    exit 1
fi
