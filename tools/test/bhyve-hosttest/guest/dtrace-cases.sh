#!/bin/sh
# Local DTrace execution tests; called on host and in each HyperTrace guest.
# Each case must return successfully AND produce its own positive count.
set -u
D=$(mktemp -d /tmp/ht-dtrace.XXXXXX) || exit 1
trap 'rm -rf "$D"' EXIT
trap 'exit 130' HUP INT TERM
cp /bin/echo "$D/htprobe" || exit 1
failed=0
run_case()
{
 name=$1; shift
 if timeout -k 2 15 dtrace -q "$@" -c "$D/htprobe" > "$D/$name.out" 2> "$D/$name.err" &&
     awk '$1 == "HIT" && $2 ~ /^[0-9]+$/ && $2 > 0 {ok=1} END {exit !ok}' "$D/$name.out"; then
  echo "DTRACE-CASE $name PASS"
 else
  echo "DTRACE-CASE $name FAIL"; failed=1
 fi
 sed "s/^/DTRACE-OUTPUT $name /" "$D/$name.out"
 sed "s/^/DTRACE-ERROR $name /" "$D/$name.err"
}
run_case begin-end -n 'BEGIN { @a["HIT"] = count(); } END { printa(@a); clear(@a); }'
run_case syscall-entry -n 'syscall:::entry /pid == $target/ { @a["HIT"] = count(); }'
run_case syscall-return -n 'syscall:::return /pid == $target/ { @a["HIT"] = count(); }'
run_case syscall-exit -n 'syscall::_exit:entry /pid == $target/ { @a["HIT"] = count(); }'
run_case proc-exec -n 'proc:::exec-success /pid == $target/ { @a["HIT"] = count(); }'
# An invalid program must fail explicitly, not silently yield no samples.
timeout -k 2 5 dtrace -e -n 'BEGIN { this is invalid; }' > "$D/invalid.out" 2> "$D/invalid.err"
invalid_rc=$?
if [ "$invalid_rc" -eq 0 ]; then
 echo 'DTRACE-CASE invalid-program FAIL'; failed=1
elif [ "$invalid_rc" -eq 1 ] && grep -qi 'syntax error' "$D/invalid.err"; then
 echo 'DTRACE-CASE invalid-program PASS'
else
 echo 'DTRACE-CASE invalid-program FAIL'; failed=1
fi
sed 's/^/DTRACE-ERROR invalid-program /' "$D/invalid.err"
exit "$failed"
