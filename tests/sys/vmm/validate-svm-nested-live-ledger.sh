#!/bin/sh
# Validate the fixed AMD L1/L2 hardware qualification contract.
set -eu
ledger=${1:?usage: validate-svm-nested-live-ledger.sh ledger.tsv}
[ -f "$ledger" ] && [ ! -L "$ledger" ] && [ -r "$ledger" ] ||
    exit 1
awk -F '\t' '
BEGIN {
    split("EXPOSURE-POLICY SVM-INSTRUCTIONS NPT-ALIAS-PERMISSIONS EXIT-REFLECTION INTERRUPT-GIF-VNMI MSR-CR8-APIC STARTUP-OWNER ACTIVE-CHECKPOINT RESTORE-REJECTION CHECKPOINT-PUBLICATION CONCURRENCY-SOAK HOST-ISOLATION", required, " ")
}
NR == 1 {
    if ($0 != "feature_id\trequirement_ids\tlinux_l2_status\tlinux_l2_evidence\tfivebsd_l2_status\tfivebsd_l2_evidence\thost_evidence\tnotes")
        bad = 1
    next
}
{
    if (NF != 8 || $1 != required[count + 1] || seen[$1]++ ||
        $2 != sprintf("SVM-LIVE-%03d", count + 1) || requirement[$2]++ ||
        $3 != "pending" || $4 != "-" || $5 != "pending" ||
        $6 != "-" || $7 != "-" || length($8) < 40)
        bad = 1
    count++
}
END { if (count != 12) bad = 1; exit bad }
' "$ledger"
