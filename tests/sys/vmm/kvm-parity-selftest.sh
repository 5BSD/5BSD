#!/bin/sh
# Falsify the KVM-parity validator before trusting its PASS result.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
validator=$here/validate-kvm-parity-requirements.sh
ledger=$here/kvm-parity-requirements.tsv
srctop=${SRCTOP:-$(CDPATH= cd -- "$here/../../.." && pwd)}
work=$(mktemp -d /tmp/kvm-parity-selftest.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM

must_fail()
{
	label=$1
	file=$2
	if sh "$validator" "$file" "$srctop" >"$work/$label.out" 2>&1; then
		echo "validator accepted $label corruption" >&2
		exit 1
	fi
}

sh "$validator" "$ledger" "$srctop" >/dev/null

cp "$ledger" "$work/duplicate.tsv"
sed -n '/^KVM-GEN-001\t/p' "$ledger" >>"$work/duplicate.tsv"
must_fail duplicate "$work/duplicate.tsv"

awk -F '\t' 'BEGIN { OFS = "\t" }
    $1 == "KVM-GEN-001" { $4 = "claimed" }
    { print }' "$ledger" >"$work/disposition.tsv"
must_fail disposition "$work/disposition.tsv"

awk -F '\t' 'BEGIN { OFS = "\t" }
    $1 == "KVM-GEN-003" { $5 = "tests/sys/vmm/does-not-exist.c" }
    { print }' "$ledger" >"$work/evidence.tsv"
must_fail evidence "$work/evidence.tsv"

echo "PASS KVM parity validator self-test"
