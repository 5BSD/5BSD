#!/bin/sh
# Run every container-model proof in sequence and summarize.  Each proof
# rebuilds the image from $VM/guestroot and boots it; expect ~10 minutes each.
#   sh tools/test/capability-containers/run-all.sh [proof ...]
TOP=$(cd "$(dirname "$0")" && pwd); : "${VM:=$HOME/vm}"; : "${WORK:=$VM/work}"; mkdir -p "$WORK"
export VM WORK
ALL="sharedenv labelreuse groupreap pkgflow folderwatch logreap cryptoreap timerreap providerdeath burst"
[ $# -gt 0 ] && ALL="$*"
total_pass=0; total_fail=0
for p in $ALL; do
	echo "===== $p ($(date +%H:%M:%S)) ====="
	sh "$TOP/scripts/$p.sh" > "$WORK/$p.log" 2>&1; rc=$?
	pass=$(grep -cE '_PASS' "$WORK/$p.log"); fail=$(grep -cE '_FAIL|BOOT TIMEOUT|PANIC|IMAGE BUILD FAILED' "$WORK/$p.log")
	total_pass=$((total_pass+pass)); total_fail=$((total_fail+fail))
	echo "$p: rc=$rc pass=$pass fail=$fail"; grep -E '_FAIL|BOOT TIMEOUT|PANIC|IMAGE BUILD FAILED|STAGE1' "$WORK/$p.log" | head -5
done
echo "TOTAL pass=$total_pass fail=$total_fail"
[ "$total_fail" = 0 ]
