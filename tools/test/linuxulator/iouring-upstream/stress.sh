#!/bin/sh
# Native squeue stress, only inside a disposable candidate VM.
set -u
payload=$1
work=$2
mkdir -p "$work"
ulimit -c 0
"$payload/memory-pressure" > "$work/pressure.log" 2>&1 &
pressure=$!
trap 'kill "$pressure" 2>/dev/null; wait "$pressure" 2>/dev/null' EXIT
for attempt in 1 2 3 4 5 6 7 8 9 10; do
 case "$(cat "$work/pressure.log")" in *PRESSURE_READY*) break ;; esac
 sleep 1
done
cat "$work/pressure.log"
case "$(cat "$work/pressure.log")" in *PRESSURE_READY*) ;; *) exit 1 ;; esac
round=1
while [ "$round" -le "${STRESS_ROUNDS:-100}" ]; do
 for name in squeue_stress squeue_fuzz; do
  echo STRESS_BEGIN "$name" "$round"
  timeout -k 5 180 "$payload/$name" "$round" > "$work/$name-$round.log" 2>&1
  rc=$?
  cat "$work/$name-$round.log"
  echo STRESS_RESULT "$name" "$round" "$rc"
 done
 round=$((round + 1))
done
echo STRESS_BEGIN squeue_soak 40000
timeout -k 5 300 "$payload/squeue_soak" 40000
rc=$?
echo STRESS_RESULT squeue_soak 40000 "$rc"
kill -0 "$pressure"
echo PRESSURE_ALIVE "$?"
kill "$pressure"
wait "$pressure"
trap - EXIT
sleep 2
echo STRESS_RESOURCES
sysctl kern.squeue.live_requests kern.squeue.registered_files kern.squeue.issuer_refs kern.squeue.issuer_tokens kern.squeue.wired_pages
echo STRESS_DONE
