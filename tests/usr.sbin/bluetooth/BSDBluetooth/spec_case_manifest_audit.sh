#!/bin/sh
#
# Verify an exact, source-controlled traceability record for every Kyua case.
# Wildcard and suite-only records are not accepted by this layer.

set -eu

quiet=false
strict=false
while [ "$#" -gt 0 ]; do
	case "$1" in
	-q) quiet=true; shift ;;
	--strict) strict=true; shift ;;
	--) shift; break ;;
	-*) echo "usage: $0 [-q] [--strict] Kyuafile" >&2; exit 64 ;;
	*) break ;;
	esac
done
if [ "$#" -ne 1 ]; then
	echo "usage: $0 [-q] [--strict] Kyuafile" >&2
	exit 64
fi

kyuafile=$1
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
manifest="$script_dir/spec_test_references.tsv"
if [ ! -f "$kyuafile" ] || [ ! -f "$manifest" ]; then
	echo 'case traceability: missing Kyuafile or spec_test_references.tsv' >&2
	exit 66
fi

case_list=$(mktemp -t bluetooth-cases.XXXXXX)
manifest_list=$(mktemp -t bluetooth-manifest.XXXXXX)
duplicates=$(mktemp -t bluetooth-duplicates.XXXXXX)
trap 'rm -f "$case_list" "$manifest_list" "$duplicates"' EXIT HUP INT TERM

kyua list -k "$kyuafile" | LC_ALL=C sort >"$case_list"

tab=$(printf '\t')
awk -F "$tab" '
BEGIN { errors = 0 }
NR == 1 {
	if ($0 != "test_case\tauthority\texact_reference\trequirement_id\toracle_provenance\tstatus") {
		print "case traceability: invalid manifest header" > "/dev/stderr"
		exit 1
	}
	next
}
NF != 6 {
	print "case traceability: row " NR " does not have six fields" > "/dev/stderr"
	errors++
	next
}
$1 ~ /[*?[]/ {
	print "case traceability: wildcard case ID is forbidden: " $1 > "/dev/stderr"
	errors++
}
$2 != "normative" && $2 != "implementation" && $2 != "mixed" {
	print "case traceability: invalid authority for " $1 ": " $2 > "/dev/stderr"
	errors++
}
($2 == "normative" || $2 == "mixed") &&
    $3 !~ /§|Table|Appendix|Figure/ {
	print "case traceability: normative case lacks narrow locator: " $1 > "/dev/stderr"
	errors++
}
$4 == "" || $5 == "" {
	print "case traceability: missing requirement/provenance for " $1 > "/dev/stderr"
	errors++
}
$6 != "verified" && $6 != "provisional" &&
    $6 != "missing-oracle" && $6 != "environment-blocked" {
	print "case traceability: invalid status for " $1 ": " $6 > "/dev/stderr"
	errors++
}
END { if (errors != 0) exit 1 }
' "$manifest"

awk -F "$tab" 'NR > 1 { print $1 }' "$manifest" | LC_ALL=C sort >"$manifest_list"
uniq -d "$manifest_list" >"$duplicates"
if [ -s "$duplicates" ]; then
	echo 'case traceability: duplicate case records:' >&2
	sed -n '1,20p' "$duplicates" >&2
	exit 1
fi

if ! cmp -s "$case_list" "$manifest_list"; then
	echo 'case traceability: Kyua inventory and manifest differ' >&2
	echo 'missing manifest records:' >&2
	comm -23 "$case_list" "$manifest_list" | sed -n '1,20p' >&2
	echo 'stale manifest records:' >&2
	comm -13 "$case_list" "$manifest_list" | sed -n '1,20p' >&2
	exit 1
fi

total=$(wc -l <"$case_list" | tr -d ' ')
verified=$(awk -F "$tab" 'NR > 1 && $6 == "verified" { n++ } END { print n + 0 }' "$manifest")
provisional=$((total - verified))

if ! $quiet; then
	awk -F "$tab" 'NR > 1 && $6 != "verified" { print $1 "\t" $6 "\t" $3 "\t" $5 }' "$manifest"
fi
echo "case traceability: $verified/$total individually verified; $provisional remaining"

if $strict && [ "$provisional" -ne 0 ]; then
	echo 'case traceability: strict completion blocked by unverified rows' >&2
	exit 1
fi
