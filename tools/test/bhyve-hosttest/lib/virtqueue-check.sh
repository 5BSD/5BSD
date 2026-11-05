#!/bin/sh
# Validate the host-filtered aggregates from one HyperTrace session.
set -eu
case "${2:-no}" in
no) expected=0 ;;
yes) expected=1 ;;
*) echo "expected ring mode must be yes or no" >&2; exit 2 ;;
esac
awk -v expected="$expected" '
NF == 0 { next }
NF != 5 || ($1 != "SUBMIT" && $1 != "COMPLETE") ||
    $2 != "ht-trace1" || $3 != "0" || $4 !~ /^[01]$/ ||
    $4 != expected || $5 !~ /^[0-9]+$/ || $5 + 0 <= 0 { bad = 1; next }
{ if (seen && mode != $4) bad = 1; mode = $4; seen = 1 }
$1 == "SUBMIT" { submitted += $5 }
$1 == "COMPLETE" { completed += $5 }
END {
    if (bad || submitted <= 0 || completed <= 0) exit 1
    printf "queue=0 packed=%s submitted=%.0f completed=%.0f\n", mode, submitted, completed
}' "$1"
