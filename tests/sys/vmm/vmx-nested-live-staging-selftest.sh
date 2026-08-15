#!/bin/sh

set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
validator=$here/validate-vmx-nested-live-staging.sh
work=$(mktemp -d /tmp/nested-vmx-staging.XXXXXX)
ledger=$work/ledger.tsv
manifest=$work/evidence.tsv
artifacts=$work/artifacts

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

write_manifest()
{
	linux=${1:-linux}
	fivebsd=${2:-fivebsd}
	host=${3:-host}
	{
		printf 'feature_id\tlinux_l2_evidence\tfivebsd_l2_evidence\thost_evidence\n'
		printf 'FEATURE\tnested-vmx-live:%s\tnested-vmx-live:%s\tnested-vmx-live:%s\n' \
		    "$linux" "$fivebsd" "$host"
	} > "$manifest"
}

expect_failure()
{
	pattern=$1
	shift
	if NESTED_LIVE_LEDGER=$ledger "$validator" "$manifest" "$artifacts" \
	    >"$work/failure.out" 2>&1; then
		echo "nested-vmx staging selftest: invalid staging was accepted" >&2
		exit 1
	fi
	grep -q "$pattern" "$work/failure.out" || {
		cat "$work/failure.out" >&2
		echo "nested-vmx staging selftest: failed for wrong reason" >&2
		exit 1
	}
}

printf 'feature_id\trequirement_ids\tlinux_l2_status\tlinux_l2_evidence\tfivebsd_l2_status\tfivebsd_l2_evidence\thost_evidence\tnotes\n' > "$ledger"
printf 'FEATURE\tREQ\tpending\t-\tpending\t-\t-\tselftest\n' >> "$ledger"
mkdir "$artifacts"
write_manifest
for name in linux fivebsd host; do
	printf 'proof\n' > "$artifacts/$name.evidence"
done
NESTED_LIVE_LEDGER=$ledger "$validator" "$manifest" "$artifacts" >/dev/null

write_manifest '../outside' fivebsd host
expect_failure 'malformed or incomplete'
write_manifest linux linux host
expect_failure 'malformed or incomplete'
write_manifest

# private-test: unsafe-paths
mv "$artifacts/linux.evidence" "$work/linux.real"
ln -s "$work/linux.real" "$artifacts/linux.evidence"
expect_failure 'non-regular entry'
rm "$artifacts/linux.evidence"
mv "$work/linux.real" "$artifacts/linux.evidence"

rm "$artifacts/fivebsd.evidence"
ln "$artifacts/linux.evidence" "$artifacts/fivebsd.evidence"
expect_failure 'must not have aliases'
rm "$artifacts/fivebsd.evidence"
printf 'proof\n' > "$artifacts/fivebsd.evidence"

printf 'unexpected\n' > "$artifacts/extra.evidence"
expect_failure 'exactly 3 files'
rm "$artifacts/extra.evidence"

rm "$artifacts/host.evidence"
expect_failure 'exactly 3 files'

echo "PASS nested-vmx live staging validator"
