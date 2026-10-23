#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
work=$(mktemp -d /tmp/svm-nested-ledger.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
ledger=$here/svm-nested-live-qualification.tsv
validator=$here/validate-svm-nested-live-ledger.sh
"$validator" "$ledger"

sed '/^HOST-ISOLATION\t/d' "$ledger" > "$work/missing.tsv"
if "$validator" "$work/missing.tsv"; then
	echo "missing mandatory AMD feature group accepted" >&2
	exit 1
fi
sed 's/^NPT-ALIAS-PERMISSIONS\t/NPT-ALIAS-POLICY\t/' "$ledger" \
    > "$work/renamed.tsv"
if "$validator" "$work/renamed.tsv"; then
	echo "renamed mandatory AMD feature group accepted" >&2
	exit 1
fi
sed 's/^ACTIVE-CHECKPOINT\tSVM-LIVE-008\t/ACTIVE-CHECKPOINT\tSVM-LIVE-009\t/' \
    "$ledger" > "$work/duplicate.tsv"
if "$validator" "$work/duplicate.tsv"; then
	echo "duplicate AMD requirement accepted" >&2
	exit 1
fi
echo "PASS nested-svm live ledger validator"
