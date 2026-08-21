#!/bin/sh
# Validate the KVM-selftests comparison without promoting partial evidence.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ledger=${1:-$here/kvm-parity-requirements.tsv}
srctop=${2:-${SRCTOP:-$(CDPATH= cd -- "$here/../../.." && pwd)}}
tmp=$(mktemp -d /tmp/kvm-parity.XXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

[ -f "$ledger" ] || { echo "missing KVM parity ledger: $ledger" >&2; exit 1; }
[ -d "$srctop/sys" ] || { echo "invalid source tree: $srctop" >&2; exit 1; }

pin=$(sed -n 's/^# linux-commit: //p' "$ledger")
printf '%s\n' "$pin" | grep -Eq '^[0-9a-f]{40}$' || {
	echo "missing or malformed pinned Linux commit" >&2
	exit 1
}

awk -F '\t' '
BEGIN { expected = "id\tkvm_reference\twaspnest_scope\tdisposition\tevidence\trunner\tnotes" }
/^#/ || NF == 0 { next }
NR > 0 && !header {
	header = 1
	if ($0 != expected) { print "invalid header" > "/dev/stderr"; exit 1 }
	next
}
{
	if (NF != 7) { print "wrong field count at " $1 > "/dev/stderr"; exit 1 }
	if ($1 !~ /^KVM-(GEN|X86)-[0-9][0-9][0-9]$/) {
		print "invalid id " $1 > "/dev/stderr"; exit 1
	}
	if (seen[$1]++) { print "duplicate id " $1 > "/dev/stderr"; exit 1 }
	if ($4 !~ /^(covered|partial|gap|not-applicable)$/) {
		print "invalid disposition for " $1 > "/dev/stderr"; exit 1
	}
	if ($4 ~ /^(covered|partial)$/ && $5 == "-") {
		print "evidence required for " $1 > "/dev/stderr"; exit 1
	}
	if ($4 ~ /^(gap|not-applicable)$/ && $5 != "-") {
		print "non-evidence disposition publishes evidence for " $1 > "/dev/stderr"; exit 1
	}
	if ($3 == "kvm-only" && $4 != "not-applicable") {
		print "KVM-only row is not excluded: " $1 > "/dev/stderr"; exit 1
	}
	if ($3 != "kvm-only" && $4 == "not-applicable") {
		print "native scope incorrectly excluded: " $1 > "/dev/stderr"; exit 1
	}
	count[$4]++
}
END {
	total = count["covered"] + count["partial"] + count["gap"] + count["not-applicable"]
	if (!header || total < 40) {
		print "KVM parity inventory is unexpectedly incomplete" > "/dev/stderr"; exit 1
	}
	if (!count["covered"] || !count["partial"] || !count["gap"] ||
	    !count["not-applicable"]) {
		print "ledger must preserve all disposition classes" > "/dev/stderr"; exit 1
	}
}' "$ledger"

awk -F '\t' '
/^#/ || $1 == "id" || NF == 0 { next }
$4 == "covered" || $4 == "partial" {
	n = split($5, path, ";")
	for (i = 1; i <= n; i++) print $1 "\t" path[i]
}' "$ledger" >"$tmp/evidence"
while IFS="$(printf '\t')" read -r id path; do
	[ -e "$srctop/$path" ] || {
		echo "$id references missing evidence: $path" >&2
		exit 1
	}
done <"$tmp/evidence"

awk -F '\t' '$1 == "KVM-GEN-003" && $4 == "covered" &&
    $5 ~ /vmm_kvm_parity_live_test.c/ { found = 1 } END { exit !found }' \
    "$ledger" || { echo "multi-VM coverage row is missing" >&2; exit 1; }
grep -Eq '^ATF_TESTS_C\+=[[:space:]]+vmm_kvm_parity_live_test$' \
    "$srctop/tests/sys/vmm/Makefile" || {
	echo "multi-VM parity test is not registered with Kyua" >&2
	exit 1
}
grep -Eq '^PACKAGE=[[:space:]]*tests$' "$srctop/tests/sys/vmm/Makefile" || {
	echo "VMM parity tests are not owned by the tests package" >&2
	exit 1
}
grep -Eq '^TESTSDIR=[[:space:]]*\$\{TESTSBASE\}/sys/vmm$' \
    "$srctop/tests/sys/vmm/Makefile" || {
	echo "VMM parity tests are not installed below TESTSBASE" >&2
	exit 1
}
for payload in validate-kvm-parity-requirements.sh \
	    kvm-parity-selftest.sh kvm-parity-requirements.tsv \
	    run-vmm-kvm-parity-stress.sh vmm-kvm-parity-stress-selftest.sh; do
	awk -v payload="$payload" '
	    $1 == "${PACKAGE}FILES+=" && $2 == payload { found = 1 }
	    END { exit !found }
	' "$srctop/tests/sys/vmm/Makefile" || {
		echo "tests package omits KVM parity payload: $payload" >&2
		exit 1
	}
done
for token in LIVE_VM_COUNT pthread_create vm_create EEXIST vm_run; do
	grep -Fq "$token" "$srctop/tests/sys/vmm/vmm_kvm_parity_live_test.c" || {
		echo "multi-VM parity test lacks $token" >&2
		exit 1
	}
done

counts=$(awk -F '\t' '/^#/ || $1 == "id" || NF == 0 { next }
    { count[$4]++ } END {
    printf "covered=%d partial=%d gap=%d not-applicable=%d",
    count["covered"], count["partial"], count["gap"], count["not-applicable"]
}' "$ledger")
echo "PASS KVM parity requirements: linux=$pin $counts"
