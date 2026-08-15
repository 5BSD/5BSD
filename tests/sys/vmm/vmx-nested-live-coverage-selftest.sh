#!/bin/sh

set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
validator=$here/validate-vmx-nested-live-coverage.sh
work=$(mktemp -d /tmp/nested-vmx-live-coverage.XXXXXX)
requirements=$work/requirements.tsv
live=$work/live.tsv

cleanup()
{
	trap - EXIT HUP INT TERM
	chmod -R u+rwX "$work" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

write_requirements()
{
	printf '%b\n' \
	    'requirement_id\tauthority\tsection\trequirement\tcode\ttest\tstatus' \
	    'NVMX-TEST-001\tSPEC\t1\tone\tcode_one\ttest_one\texperimental-pending-live' \
	    'NVMX-TEST-002\tSPEC\t2\ttwo\tcode_two\ttest_two\tfoundation-tested-experimental' \
	    > "$requirements"
}

write_live()
{
	ids=$1
	printf '%b\n' \
	    'feature_id\trequirement_ids\tlinux_l2_status\tlinux_l2_evidence\tfivebsd_l2_status\tfivebsd_l2_evidence\thost_evidence\tnotes' \
	    "FEATURE-A\t$ids\tpending\t-\tpending\t-\t-\tselftest" \
	    > "$live"
}

write_requirements
write_live 'NVMX-TEST-001;NVMX-TEST-002'
sh "$validator" "$requirements" "$live"

# The coverage validator is also a public rootless gate.  It must validate
# architectural IDs itself rather than silently depending on a caller having
# run the broader requirements validator first.
sed 's/^NVMX-TEST-001\t/BAD_id\t/' "$requirements" > "$work/bad-requirements.tsv"
if sh "$validator" "$work/bad-requirements.tsv" "$live" \
    >"$work/bad-requirement.out" 2>&1; then
	echo "nested-vmx live coverage selftest: malformed requirement accepted" >&2
	exit 1
fi
grep -q 'invalid or duplicate architectural requirement BAD_id' \
    "$work/bad-requirement.out"

write_live 'NVMX-TEST-002'
if sh "$validator" "$requirements" "$live" >"$work/missing.out" 2>&1; then
	echo "nested-vmx live coverage selftest: missing requirement accepted" >&2
	exit 1
fi
grep -q 'pending-live requirement NVMX-TEST-001 has no hardware feature group' \
    "$work/missing.out"

write_live 'NVMX-TEST-001;NVMX-UNKNOWN-001'
if sh "$validator" "$requirements" "$live" >"$work/unknown.out" 2>&1; then
	echo "nested-vmx live coverage selftest: unknown requirement accepted" >&2
	exit 1
fi
grep -q 'references missing requirement NVMX-UNKNOWN-001' "$work/unknown.out"

printf '%b\n' \
    'feature_id\trequirement_ids\tlinux_l2_status\tlinux_l2_evidence\tfivebsd_l2_status\tfivebsd_l2_evidence\thost_evidence\tnotes' \
    'FEATURE-A\tNVMX-TEST-001\tpending\t-\tpending\t-\t-\tselftest' \
    'FEATURE-B\tNVMX-TEST-001\tpending\t-\tpending\t-\t-\tselftest' \
    > "$live"
if sh "$validator" "$requirements" "$live" >"$work/duplicate.out" 2>&1; then
	echo "nested-vmx live coverage selftest: duplicate coverage accepted" >&2
	exit 1
fi
grep -q 'pending-live requirement NVMX-TEST-001 occurs in 2 hardware feature groups' \
    "$work/duplicate.out"

# The positive ledger is an immutable execution plan.  A duplicated feature
# group, repeated requirement, or pre-populated PASS/evidence field can hide
# a missing execution before the sealed evidence validator runs.
printf '%b\n' \
    'feature_id\trequirement_ids\tlinux_l2_status\tlinux_l2_evidence\tfivebsd_l2_status\tfivebsd_l2_evidence\thost_evidence\tnotes' \
    'FEATURE-A\tNVMX-TEST-001\tpending\t-\tpending\t-\t-\tselftest' \
    'FEATURE-A\tNVMX-TEST-002\tpending\t-\tpending\t-\t-\tselftest' \
    > "$live"
if sh "$validator" "$requirements" "$live" >"$work/duplicate-feature.out" 2>&1; then
	echo "nested-vmx live coverage selftest: duplicate feature accepted" >&2
	exit 1
fi
grep -q 'invalid or duplicate live feature group FEATURE-A' \
    "$work/duplicate-feature.out"

write_live 'NVMX-TEST-001;NVMX-TEST-001'
if sh "$validator" "$requirements" "$live" >"$work/duplicate-id.out" 2>&1; then
	echo "nested-vmx live coverage selftest: repeated requirement accepted" >&2
	exit 1
fi
grep -q 'live feature FEATURE-A repeats or has empty requirement id NVMX-TEST-001' \
    "$work/duplicate-id.out"

printf '%b\n' \
    'feature_id\trequirement_ids\tlinux_l2_status\tlinux_l2_evidence\tfivebsd_l2_status\tfivebsd_l2_evidence\thost_evidence\tnotes' \
    'FEATURE-A\tNVMX-TEST-001\tpassed\tstale\tpending\t-\t-\tselftest' \
    > "$live"
if sh "$validator" "$requirements" "$live" >"$work/stale-evidence.out" 2>&1; then
	echo "nested-vmx live coverage selftest: stale plan evidence accepted" >&2
	exit 1
fi
grep -q 'live feature FEATURE-A has non-plan evidence or status' \
    "$work/stale-evidence.out"

echo "PASS nested-vmx live coverage validator"
