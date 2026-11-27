#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard

set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
R=$work
export R
# The extra script is a step: the block runs with the guest's phase-bounds
# block before it (stub procstat and geom, the export to a file).
mkdir -p "$work/bin"
printf '#!/bin/sh\necho "STACK-OF $2"\n' > "$work/bin/procstat"
printf '#!/bin/sh\necho "   ident: kyua-results"\n' > "$work/bin/geom"
chmod +x "$work/bin"/*
{ printf 'RUN_DEADLINE=$1\n'
  sed -n '/^# --- phase bounds (/,/^# --- end of the phase bounds$/p' "$root/vm-provider.sh" |
   sed -e "s|/var/log/messages|$work/messages|g" -e "s|/dev/vtbd1|$work/results.tar|g" \
       -e "s|-C /tmp kyua-results|-C $work .|g"
  printf 'printf "%%s %%s\\n" "$RUN_DEADLINE" "$PHASE_RESERVE" > "%s/expected"\n' "$work"
  sed -n '/^if \[ -s \/root\/vm-extra.sh \]; then/,/^fi$/p' "$root/vm-provider.sh" |
   sed "s|/root/vm-extra.sh|$work/extra.sh|g"; } > "$work/extracted.sh"
grep -q '^run_step()' "$work/extracted.sh"
grep -q 'run_step extra sh' "$work/extracted.sh"
: > "$work/messages"
for status in 0 7; do
 printf '#!/bin/sh\nprintf "%%s %%s\\n" "$RUN_DEADLINE" "$PHASE_RESERVE" > "$R/seen"\necho retained-diagnostic >&2\nexit %s\n' "$status" > "$work/extra.sh"
 env -u RUN_DEADLINE -u PHASE_RESERVE PATH="$work/bin:$PATH" PHASE_CONSOLE="$work/phase" \
     sh "$work/extracted.sh" "$(( $(date +%s) + 3600 ))" > "$work/console"
 cmp "$work/expected" "$work/seen"
 grep "PHASE_STEP extra end status=$status " "$work/phase" > /dev/null
 [ "$(cat "$R/extra.exit")" = "$status" ]
 grep retained-diagnostic "$R/extra.out" > /dev/null
 grep "EXTRA_SCRIPT_STATUS=$status" "$work/console" > /dev/null
done
# Exercise the actual added host verdict guard, with successful and failed files.
sed -n '/{ \[ -z "\$extra_script" \] ||/,+1p' "$root/vm-provider.sh" |
 sed 's/; } \&\&$/; }/' > "$work/guard.sh"
mkdir -p "$work/results/kyua-results"
extra_script=present
export work extra_script
for status in 0 7; do
 echo "$status" > "$work/results/kyua-results/extra.exit"
 actual=0
 sh "$work/guard.sh" || actual=$?
 if [ "$status" = 0 ]; then [ "$actual" = 0 ]; else [ "$actual" != 0 ]; fi
done
rm "$work/results/kyua-results/extra.exit"
if sh "$work/guard.sh"; then exit 1; fi
echo 'PASS actual extra step receives measured deadline/reserve, preserves status and diagnostics; host guard rejects failure/missing status'
