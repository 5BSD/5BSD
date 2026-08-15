#!/bin/sh
#
# Validate the mutable output of the external nested-VMX L1 runner before the
# privileged host wrapper hashes or changes the mode of any artifact.  This is
# intentionally separate from the completed-evidence validator: staging files
# are still writable while completed evidence must already be sealed.
#

set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
ledger=${NESTED_LIVE_LEDGER:-$here/vmx-nested-live-qualification.tsv}
manifest=${1:?usage: validate-vmx-nested-live-staging.sh manifest.tsv artifact-dir}
artifact_dir=${2:?usage: validate-vmx-nested-live-staging.sh manifest.tsv artifact-dir}

fail()
{
	echo "nested-vmx staging: $*" >&2
	exit 1
}

[ -f "$ledger" ] && [ ! -L "$ledger" ] && [ -r "$ledger" ] ||
    fail "live ledger is not a readable regular file: $ledger"
[ -f "$manifest" ] && [ ! -L "$manifest" ] && [ -r "$manifest" ] ||
    fail "manifest is not a readable regular file: $manifest"
[ -d "$artifact_dir" ] && [ ! -L "$artifact_dir" ] ||
    fail "artifact directory is not a real directory: $artifact_dir"

uid=$(id -u)
set -- $(stat -f '%u %l' "$manifest")
[ "$1" -eq "$uid" ] || fail "manifest has the wrong owner: $manifest"
[ "$2" -eq 1 ] || fail "manifest must not have aliases: $manifest"
set -- $(stat -f '%u' "$artifact_dir")
[ "$1" -eq "$uid" ] ||
    fail "artifact directory has the wrong owner: $artifact_dir"

# Validate the complete mapping before expanding even one runner-controlled
# token into a pathname.  In particular, reject slash, dot-prefix, and '..'
# names before chmod(1), sha256(1), or fsync(1) sees them.
awk -F '\t' '
NR == FNR && FNR == 1 {
	if ($0 != "feature_id\trequirement_ids\tlinux_l2_status\tlinux_l2_evidence\tfivebsd_l2_status\tfivebsd_l2_evidence\thost_evidence\tnotes")
		bad = 1
	next
}
NR == FNR {
	if (NF != 8 || $1 !~ /^[A-Z0-9][A-Z0-9-]*$/ || expected[$1]++)
		bad = 1
	next
}
NR != FNR && FNR == 1 {
	if ($0 != "feature_id\tlinux_l2_evidence\tfivebsd_l2_evidence\thost_evidence")
		bad = 1
	next
}
NR != FNR {
	if (NF != 4 || !($1 in expected) || observed[$1]++) {
		bad = 1
		next
	}
	for (i = 2; i <= 4; i++) {
		if ($i !~ /^nested-vmx-live:[a-z0-9][a-z0-9._-]*$/ ||
		    $i ~ /^nested-vmx-live:\./ || $i ~ /\.\./ || token[$i]++)
			bad = 1
	}
}
END {
	for (feature in expected)
		if (observed[feature] != 1)
			bad = 1
	exit bad
}
' "$ledger" "$manifest" || fail "malformed or incomplete artifact manifest"

feature_count=$(awk -F '\t' 'NR > 1 { count++ } END { print count + 0 }' \
    "$ledger")
artifact_count=$((feature_count * 3))
[ "$feature_count" -gt 0 ] || fail "live ledger contains no feature groups"
[ -z "$(find "$artifact_dir" -mindepth 1 -maxdepth 1 ! -type f \
    -print -quit)" ] || fail "artifact directory contains a non-regular entry"
[ "$(find "$artifact_dir" -mindepth 1 -maxdepth 1 -type f -print |
    wc -l | tr -d ' ')" -eq "$artifact_count" ] ||
    fail "artifact directory must contain exactly $artifact_count files"

while IFS='	' read -r feature linux fivebsd host; do
	[ "$feature" = feature_id ] && continue
	for token in "$linux" "$fivebsd" "$host"; do
		name=${token#nested-vmx-live:}
		path=$artifact_dir/$name.evidence
		[ -f "$path" ] && [ ! -L "$path" ] && [ -s "$path" ] ||
		    fail "artifact is not a nonempty regular file: $path"
		set -- $(stat -f '%u %l' "$path")
		[ "$1" -eq "$uid" ] ||
		    fail "artifact has the wrong owner: $path"
		[ "$2" -eq 1 ] ||
		    fail "artifact must not have aliases: $path"
	done
done < "$manifest"

echo "nested-vmx staging: $feature_count feature groups and $artifact_count artifacts validated"
