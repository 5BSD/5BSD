#!/bin/sh
#
# Cross-check the architectural nested-VMX ledger and the complete positive
# hardware-qualification ledger.  A requirement held specifically at
# pending-live is not allowed to disappear between those two ledgers.  This
# intentionally does not apply to the separate VPID-default-off policy
# ledger: that ledger proves one narrow second-boot policy and is validated by
# validate-vmx-nested-policy-pair.sh.
#

set -eu

requirements=${1:?usage: validate-vmx-nested-live-coverage.sh requirements.tsv positive-live.tsv}
live=${2:?usage: validate-vmx-nested-live-coverage.sh requirements.tsv positive-live.tsv}

[ "$(sed -n '1p' "$requirements")" = "$(printf 'requirement_id\tauthority\tsection\trequirement\tcode\ttest\tstatus')" ] || {
	echo "invalid nested-VMX requirement ledger header" >&2
	exit 1
}
[ "$(sed -n '1p' "$live")" = "$(printf 'feature_id\trequirement_ids\tlinux_l2_status\tlinux_l2_evidence\tfivebsd_l2_status\tfivebsd_l2_evidence\thost_evidence\tnotes')" ] || {
	echo "invalid nested-VMX live ledger header" >&2
	exit 1
}

awk -F '\t' '
NR == FNR && FNR == 1 { next }
NR == FNR {
	if (NF != 7 || $1 !~ /^[A-Z0-9][A-Z0-9-]*$/ || requirement[$1]++) {
		printf "invalid or duplicate architectural requirement %s\n", $1 > "/dev/stderr"
		bad = 1
		next
	}
	status[$1] = $7
}
NR != FNR && FNR == 1 { next }
NR != FNR {
	if (NF != 8 || $1 !~ /^[A-Z0-9][A-Z0-9-]*$/ || feature[$1]++) {
		printf "invalid or duplicate live feature group %s\n", $1 > "/dev/stderr"
		bad = 1
		next
	}
	# This is the immutable plan ledger.  Completed evidence belongs in the
	# separate, sealed evidence transaction, never in a mutable planning row.
	# Otherwise a stale PASS marker can make a root-only run appear to have
	# satisfied a feature it did not execute.
	if ($2 == "" || $2 == "-" || $3 != "pending" || $4 != "-" ||
	    $5 != "pending" || $6 != "-" || $7 != "-") {
		printf "live feature %s has non-plan evidence or status\n", $1 > "/dev/stderr"
		bad = 1
	}
	n = split($2, item, ";")
	for (i = 1; i <= n; i++) {
		if (item[i] == "" || row_item[item[i]]++) {
			printf "live feature %s repeats or has empty requirement id %s\n",
			    $1, item[i] > "/dev/stderr"
			bad = 1
		} else if (!(item[i] in requirement)) {
			printf "live feature %s references missing requirement %s\n",
			    $1, item[i] > "/dev/stderr"
			bad = 1
		}
		covered[item[i]]++
	}
	delete row_item
}
END {
	for (id in status) {
		if (status[id] != "experimental-pending-live")
			continue
		if (covered[id] == 0) {
			printf "pending-live requirement %s has no hardware feature group\n",
			    id > "/dev/stderr"
			bad = 1
		} else if (covered[id] != 1) {
			printf "pending-live requirement %s occurs in %d hardware feature groups\n",
			    id, covered[id] > "/dev/stderr"
			bad = 1
		}
	}
	exit bad
}
' "$requirements" "$live"
