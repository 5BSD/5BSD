#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
R=$work
export R
sed -n '/^if \[ -s \/root\/vm-extra.sh \]; then/,/^fi$/p' "$root/vm-provider.sh" |
 sed "s|/root/vm-extra.sh|$work/extra.sh|g" > "$work/extracted.sh"
for status in 0 7; do
 printf '#!/bin/sh\necho retained-diagnostic >&2\nexit %s\n' "$status" > "$work/extra.sh"
 sh "$work/extracted.sh" > "$work/console"
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
echo 'PASS actual guest pipeline retains failure status/raw diagnostics; actual host guard rejects failure/missing status'
