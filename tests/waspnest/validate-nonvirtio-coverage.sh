#!/bin/sh
set -eu

ledger=${1:-$(dirname "$0")/waspnest-nonvirtio-coverage.tsv}
srctop=${SRCTOP:-/usr/src}
harness=$srctop/tests/sys/kern/vsock_device_harness
manifest=$srctop/tests/sys/kern/vsock_e2e/virtio-lab.yaml

fail()
{
	echo "validate-nonvirtio-coverage: $*" >&2
	exit 1
}

[ -f "$ledger" ] || fail "missing ledger: $ledger"
[ -f "$harness/Makefile" ] || fail "missing device harness: $harness"
[ -f "$manifest" ] || fail "missing live qualification manifest: $manifest"

awk -F '\t' '
BEGIN {
	header = "device\tsource\thost_evidence\tlinux_status\tlinux_case\tfivebsd_status\tfivebsd_case\tcheckpoint_status\tcheckpoint_case\tnotes"
	split("exercised pending driver-gap not-applicable environment-dependent", values, " ")
	for (i in values) allowed[values[i]] = 1
}
NR == 1 { if ($0 != header) exit 10; next }
$0 ~ /^#/ { next }
NF != 10 || seen[$1]++ || !allowed[$4] || !allowed[$6] || !allowed[$8] { exit 11 }
($4 == "exercised" && $5 == "-") || ($6 == "exercised" && $7 == "-") ||
    ($8 == "exercised" && $9 == "-") { exit 14 }
(($4 == "driver-gap" || $4 == "not-applicable") && $5 != "-") ||
    (($6 == "driver-gap" || $6 == "not-applicable") && $7 != "-") ||
    (($8 == "driver-gap" || $8 == "not-applicable") && $9 != "-") { exit 15 }
{ present[$1] = 1; rows++ }
END {
	split("ahci nvme e82545 hda xhci fbuf pci-uart lpc-uart tpm-crb pvpanic hostbridge passthru qemu-fwcfg", required, " ")
	for (i in required) if (!present[required[i]]) exit 12
	if (rows != 13) exit 13
}' "$ledger" || fail "malformed, duplicate, incomplete, or unknown-status row"

# The inventory is also the executable contract: every supported guest gets
# a distinct live case and every snapshot policy gets a case for each guest.
# This prevents a generic boot smoke from being reused for several devices.
while IFS="$(printf '\t')" read -r device source evidence linux_status \
    linux_case fivebsd_status fivebsd_case checkpoint_status checkpoint_case notes; do
	[ "$device" = device ] && continue
	case "$device" in \#*) continue ;; esac
	expected_linux="nonvirtio-alpine-$device-live"
	expected_checkpoint="nonvirtio-alpine-$device-checkpoint"
	if [ "$device" = pvpanic ]; then
		expected_fivebsd=-
	else
		expected_fivebsd="nonvirtio-5bsd-$device-live"
		expected_checkpoint="$expected_checkpoint,nonvirtio-5bsd-$device-checkpoint"
	fi
	[ "$linux_case" = "$expected_linux" ] ||
	    fail "$device has wrong Alpine live case: $linux_case"
	[ "$fivebsd_case" = "$expected_fivebsd" ] ||
	    fail "$device has wrong 5BSD live case: $fivebsd_case"
	[ "$checkpoint_case" = "$expected_checkpoint" ] ||
	    fail "$device has wrong checkpoint cases: $checkpoint_case"
done <"$ledger"

while IFS="$(printf '\t')" read -r device source evidence rest; do
	[ "$device" = device ] && continue
	case "$device" in \#*) continue ;; esac
	[ -f "$srctop/usr.sbin/bhyve/$source" ] ||
	    fail "$device source is absent: usr.sbin/bhyve/$source"
	[ "$evidence" = - ] && continue
	oldifs=$IFS
	IFS=,
	for test_program in $evidence; do
		grep -Eq "ATF_TESTS_C\\+=[[:space:]]*$test_program([[:space:]]|$)" \
		    "$harness/Makefile" ||
		    fail "$device host evidence is not built: $test_program"
	done
	IFS=$oldifs
done <"$ledger"

# Every claimed or scheduled case must be an exact manifest identifier.  A
# prose label cannot stand in for executable evidence.
for column in 5 7 9; do
	awk -F '\t' -v column="$column" 'NR > 1 && $0 !~ /^#/ && $column != "-" {
	    n = split($column, cases, ",")
	    for (i = 1; i <= n; i++) print cases[i]
	}' "$ledger" | while IFS= read -r case_id; do
		case "$case_id" in
		''|*[!A-Za-z0-9_.-]*)
			fail "invalid live case identifier: $case_id"
			;;
		esac
		awk -v case_id="$case_id" '
		    $1 == "-" && $2 == "id:" && $3 == case_id { found = 1 }
		    END { exit !found }
		' "$manifest" ||
		    fail "coverage row references unknown live case: $case_id"
	done
done

# Fail when a new non-VirtIO PCI implementation is registered without an
# inventory row.  pci_emul.c is the deliberate test-only dummy; VirtIO has its
# own normative and activation ledgers.
for source_path in "$srctop"/usr.sbin/bhyve/pci_*.c; do
	source=${source_path##*/}
	case "$source" in pci_virtio_*|pci_emul.c) continue ;; esac
	grep -q 'PCI_EMUL_SET(' "$source_path" || continue
	awk -F '\t' -v source="$source" 'NR > 1 && $2 == source { found = 1 } END { exit !found }' \
	    "$ledger" || fail "unclassified non-VirtIO PCI source: $source"
done

echo "PASS non-VirtIO coverage inventory"
