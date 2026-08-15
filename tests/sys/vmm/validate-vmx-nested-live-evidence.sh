#!/bin/sh
#
# Validate one completed nested-VMX hardware evidence transaction.
#

set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
ledger=${NESTED_LIVE_LEDGER:-$here/vmx-nested-live-qualification.tsv}
evidence=${1:?usage: validate-vmx-nested-live-evidence.sh evidence.tsv}
artifact_dir=${NESTED_LIVE_ARTIFACT_DIR:?set NESTED_LIVE_ARTIFACT_DIR}
run_id=${NESTED_LIVE_RUN_ID:?set NESTED_LIVE_RUN_ID}

fail()
{
	echo "nested-vmx evidence: $*" >&2
	exit 1
}

valid_utc_timestamp()
{
	# The schema uses a fixed UTC representation.  A shape-only regular
	# expression would accept impossible calendar values such as February 30,
	# which in turn makes the chronological evidence boundary misleading.
	case "$1" in
	????-??-??T??:??:??Z) ;;
	*) return 1 ;;
	esac
	# date(1) deliberately normalizes some out-of-range fields (for example,
	# February 30).  Round-trip through the canonical spelling so normalization
	# is rejected rather than silently accepted as evidence for another day.
	canonical=$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$1" \
	    '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null) || return 1
	[ "$canonical" = "$1" ]
}

[ -f "$ledger" ] && [ -r "$ledger" ] ||
    fail "live ledger is not readable: $ledger"
feature_count=$(awk -F '	' 'NR > 1 { count++ } END { print count + 0 }' \
    "$ledger")
artifact_count=$((feature_count * 3))
[ -f "$evidence" ] && [ ! -L "$evidence" ] && [ -r "$evidence" ] ||
    fail "evidence is not readable: $evidence"
[ -d "$artifact_dir" ] && [ ! -L "$artifact_dir" ] ||
    fail "artifact directory is not a real directory: $artifact_dir"
set -- $(stat -f '%u %Lp %l' "$evidence")
[ "$1" -eq "$(id -u)" ] ||
    fail "evidence manifest has the wrong owner: $evidence"
[ $((0$2 & 0222)) -eq 0 ] ||
    fail "evidence manifest must be read-only: $evidence"
[ "$3" -eq 1 ] ||
    fail "evidence manifest must not have aliases: $evidence"
case "$run_id" in
[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
*) fail "run identifier must be 32 lowercase hexadecimal digits" ;;
esac
[ -z "$(find "$artifact_dir" -mindepth 1 -maxdepth 1 ! -type f \
    -print -quit)" ] ||
    fail "artifact directory contains a non-regular entry"
[ "$feature_count" -gt 0 ] || fail "live ledger contains no feature groups"
[ "$(find "$artifact_dir" -mindepth 1 -maxdepth 1 -type f |
    wc -l | tr -d ' ')" -eq "$artifact_count" ] ||
    fail "artifact directory must contain exactly $artifact_count files"

awk -F '	' -v expected_rows="$feature_count" '
NR == 1 {
	if ($0 != "feature_id\tlinux_l2_evidence\tfivebsd_l2_evidence\thost_evidence")
		bad = 1
	next
}
NF != 4 || $1 !~ /^[A-Z0-9][A-Z0-9-]*$/ || seen[$1]++ ||
    $2 !~ /^nested-vmx-live:[a-z0-9][a-z0-9._-]*$/ ||
    $3 !~ /^nested-vmx-live:[a-z0-9][a-z0-9._-]*$/ ||
    $4 !~ /^nested-vmx-live:[a-z0-9][a-z0-9._-]*$/ ||
    $2 == $3 || $2 == $4 || $3 == $4 ||
    evidence[$2]++ || evidence[$3]++ || evidence[$4]++ {
	bad = 1
}
END {
	if (NR != expected_rows + 1)
		bad = 1
	exit bad
}
' "$evidence" || fail "malformed evidence"

expected=$(awk -F '	' 'NR > 1 { print $1 }' "$ledger" | sort)
actual=$(awk -F '	' 'NR > 1 { print $1 }' "$evidence" | sort)
[ "$actual" = "$expected" ] ||
    fail "evidence does not prove every mandatory live feature group"

validate_artifact()
{
	feature=$1
	role=$2
	token=$3
	requirements=$4
	name=${token#nested-vmx-live:}
	path=$artifact_dir/$name.evidence

	case "$name" in
	""|*[!a-z0-9._-]*|.*|*..*)
		fail "invalid artifact name for $feature/$role: $token"
		;;
	esac
	[ -f "$path" ] && [ ! -L "$path" ] && [ -s "$path" ] ||
	    fail "missing evidence artifact for $feature/$role: $path"
	set -- $(stat -f '%u %Lp %l' "$path")
	[ "$1" -eq "$(id -u)" ] ||
	    fail "evidence artifact has the wrong owner: $path"
	[ $((0$2 & 0222)) -eq 0 ] ||
	    fail "evidence artifact must be read-only: $path"
	[ "$3" -eq 1 ] ||
	    fail "evidence artifact must not have aliases: $path"

	awk -F '	' -v feature="$feature" -v role="$role" \
	    -v expected_run="$run_id" -v requirements="$requirements" '
	BEGIN {
		requirement_count = split(requirements, requirement, ";")
		for (i = 1; i <= requirement_count; i++) {
			if (requirement[i] !~ /^[A-Z0-9][A-Z0-9-]*$/ ||
			    expected[requirement[i]]++)
				bad = 1
		}
	}
	NR == 1 && $0 == "format\tnested-vmx-live-evidence-v3" {
		format++
		next
	}
	$1 == "format" { bad = 1; next }
	$1 == "feature_id" {
		if ($2 != feature || NF != 2)
			bad = 1
		else
			feature_ok++
		next
	}
	$1 == "role" {
		if ($2 != role || NF != 2)
			bad = 1
		else
			role_ok++
		next
	}
	$1 == "result" {
		if ($2 != "PASS" || NF != 2)
			bad = 1
		else
			result++
		next
	}
	$1 == "run_id" {
		if ($2 != expected_run || NF != 2)
			bad = 1
		else
			run++
		next
	}
	$1 == "started_utc" {
		if ($2 !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$/ || NF != 2)
			bad = 1
		else {
			started_value = $2
			started++
		}
		next
	}
	$1 == "finished_utc" {
		if ($2 !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$/ || NF != 2)
			bad = 1
		else {
			finished_value = $2
			finished++
		}
		next
	}
	$1 == "assertion" {
		# Assertions are normative requirement identifiers, not free-form
		# labels.  Proof records bind them to observed execution.
		if (NF != 2 || !($2 in expected) || observed[$2]++)
			bad = 1
		else
			assertion++
		next
	}
	$1 == "proof" {
		if (NF != 5 || !($2 in expected) || proof_observed[$2]++ ||
		    $4 !~ /^[A-Za-z0-9][A-Za-z0-9._:+\/-]*$/ ||
		    $5 !~ /^[1-9][0-9]*$/)
			bad = 1
		else if (role == "host" && $3 != "host-trace")
			bad = 1
		else if (role != "host" && $3 != "guest-test")
			bad = 1
		else
			proof++
		next
	}
	# Completed qualification evidence is a closed schema.  Accepting an
	# unrecognised record would make a producer typo or a schema-version mix-up
	# look like valid current evidence simply because all mandatory records also
	# happened to be present.
	{ bad = 1 }
	END {
		for (id in expected) {
			if (observed[id] != 1 || proof_observed[id] != 1)
				bad = 1
		}
		if (bad || format != 1 || feature_ok != 1 || role_ok != 1 ||
		    result != 1 || run != 1 || started != 1 || finished != 1 ||
		    finished_value < started_value ||
		    assertion != requirement_count || proof != requirement_count)
			exit 1
	}
	' "$path" ||
	    fail "artifact does not prove $feature/$role: $path"
	started=$(awk -F '\t' '$1 == "started_utc" { print $2 }' "$path")
	finished=$(awk -F '\t' '$1 == "finished_utc" { print $2 }' "$path")
	valid_utc_timestamp "$started" && valid_utc_timestamp "$finished" ||
	    fail "artifact has an invalid UTC timestamp for $feature/$role: $path"
}

while IFS='	' read -r feature linux fivebsd host; do
	[ "$feature" = feature_id ] && continue
	requirements=$(awk -F '	' -v feature="$feature" '
	    NR > 1 && $1 == feature {
		if (found++)
			exit 2
		print $2
	    }
	    END { if (found != 1) exit 1 }
	' "$ledger") || fail "live ledger has no unique requirement set for $feature"
	validate_artifact "$feature" linux-l2 "$linux" "$requirements"
	validate_artifact "$feature" fivebsd-l2 "$fivebsd" "$requirements"
	validate_artifact "$feature" host "$host" "$requirements"
done < "$evidence"

echo "nested-vmx evidence: $feature_count live feature groups and $artifact_count artifacts validated"
