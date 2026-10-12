#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
sed -n '/^# BEGIN latency validation/,/^# END latency validation/p' "$root/vm-daemons.sh" > "$work/helpers"
. "$work/helpers"
CALLS=4
r=1
sample='LATENCY service=test op=test variant=fidl n=4 p50_ns=1 p90_ns=2 p99_ns=3 mean_ns=2'
printf '#!/bin/sh\necho "%s"\nexit 0\n' "$sample" > "$work/bench"
chmod +x "$work/bench"
latency_clock_run "$work/bench" "$work/raw" >/dev/null
printf '\n' > "$work/empty"
if latency_clock_valid "$work/empty"; then exit 1; fi
printf '#!/bin/sh\necho "%s"\necho diagnostic >&2\nexit 7\n' "$sample" > "$work/bench"
if latency_clock_run "$work/bench" "$work/raw" > "$work/result"; then exit 1; fi
grep 'status=7' "$work/result" >/dev/null
grep diagnostic "$work/raw" >/dev/null
printf '%s\n%s\n' "$sample" "$sample" > "$work/raw"
if latency_clock_valid "$work/raw"; then exit 1; fi
printf '%s\n' "$sample" | sed 's/n=4/n=3/' > "$work/raw"
if latency_clock_valid "$work/raw"; then exit 1; fi
printf 'DTRACE_COUNT 4\nDTRACE_AVG 2\nDTRACE_EXIT 0 0\n' > "$work/dtrace"
latency_dtrace_valid 0 "$work/dtrace"
if latency_dtrace_valid 1 "$work/dtrace"; then exit 1; fi
if latency_dtrace_valid 0 "$work/empty"; then exit 1; fi
sed 's/EXIT 0 0/EXIT 7 0/' "$work/dtrace" > "$work/bad"
if latency_dtrace_valid 0 "$work/bad"; then exit 1; fi
sed 's/COUNT 4/COUNT 0/' "$work/dtrace" > "$work/bad"
if latency_dtrace_valid 0 "$work/bad"; then exit 1; fi
echo 'PASS clock status, missing/duplicate/incomplete samples, raw diagnostics, DTrace status, missing counts, target failure'
