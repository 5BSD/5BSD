#!/bin/sh
# Validate the dated diagnostic counts in the WASPNest completion matrix.
# The TSV ledgers remain authoritative; this check prevents the human-facing
# entry point from silently drifting away from them.
set -eu

srctop=${SRCTOP:-/usr/src}
matrix=${1:-"$srctop/docs/waspnest-completion-matrix.md"}
virtio=${2:-"$srctop/tests/sys/kern/vsock_device_harness/virtio-1.4-requirements.tsv"}
activation=${3:-"$srctop/tests/sys/kern/vsock_device_harness/virtio-feature-activation.tsv"}
virtio_private=${4:-"$srctop/tests/sys/kern/vsock_device_harness/virtio-nonstandard-interfaces.tsv"}
nested=${5:-"$srctop/tests/sys/vmm/vmx-nested-requirements.tsv"}
nested_live=${6:-"$srctop/tests/sys/vmm/vmx-nested-live-qualification.tsv"}
nested_default=${7:-"$srctop/tests/sys/vmm/vmx-nested-default-policy-live-qualification.tsv"}
nested_private=${8:-"$srctop/tests/sys/vmm/vmx-nested-nonstandard-interfaces.tsv"}
startup_edges=${9:-"$srctop/tests/sys/vmm/vmx-startup-entry-edge-matrix.tsv"}

for file in "$matrix" "$virtio" "$activation" "$virtio_private" \
    "$nested" "$nested_live" "$nested_default" "$nested_private" \
    "$startup_edges"; do
	test -r "$file" || {
		echo "completion matrix: cannot read $file" >&2
		exit 1
	}
done

rows()
{
	awk -F '\t' 'NR > 1 && $0 !~ /^#/ { n++ } END { print n + 0 }' "$1"
}

field_count()
{
	awk -F '\t' -v field="$2" -v value="$3" \
	    'NR > 1 && $0 !~ /^#/ && $field == value { n++ }
	    END { print n + 0 }' "$1"
}

expect_count()
{
	label=$1
	actual=$2
	line="| $label | $actual |"
	if ! grep -Fqx "$line" "$matrix"; then
		echo "completion matrix: stale or missing count: $line" >&2
		exit 1
	fi
}

expect_count "Requirement rows" "$(rows "$virtio")"
expect_count '`implemented-tested`' \
    "$(field_count "$virtio" 4 implemented-tested)"
expect_count '`not-applicable` and unadvertised' \
    "$(field_count "$virtio" 4 not-applicable)"
expect_count '`unsupported-optional` and unadvertised' \
    "$(field_count "$virtio" 4 unsupported-optional)"
expect_count "Live activation rows" "$(rows "$activation")"
expect_count 'Linux `exercised`' \
    "$(field_count "$activation" 3 exercised)"
expect_count 'Linux `pending`' \
    "$(field_count "$activation" 3 pending)"
expect_count 'Linux `driver-gap`' \
    "$(field_count "$activation" 3 driver-gap)"
expect_count 'Linux `not-applicable`' \
    "$(field_count "$activation" 3 not-applicable)"
expect_count '5BSD `exercised`' \
    "$(field_count "$activation" 5 exercised)"
expect_count '5BSD `pending`' \
    "$(field_count "$activation" 5 pending)"
expect_count '5BSD `driver-gap`' \
    "$(field_count "$activation" 5 driver-gap)"
expect_count '5BSD `not-applicable`' \
    "$(field_count "$activation" 5 not-applicable)"
both_exercised=$(awk -F '\t' \
    'NR > 1 && $3 == "exercised" && $5 == "exercised" { n++ }
    END { print n + 0 }' "$activation")
expect_count "Exercised by both Linux and 5BSD" "$both_exercised"
expect_count "Implementation-defined interface rows" \
    "$(rows "$virtio_private")"

# "Requirement rows" and "Implementation-defined interface rows" occur once
# in each scope.  Match the nested table by checking its whole block after the
# scope-specific values have been calculated.
nested_rows=$(rows "$nested")
nested_foundation=$(field_count "$nested" 7 foundation-tested-experimental)
nested_live_pending=$(field_count "$nested" 7 experimental-pending-live)
nested_pending=$(field_count "$nested" 7 pending)
nested_groups=$(rows "$nested_live")
nested_linux_passed=$(field_count "$nested_live" 3 exercised)
nested_fivebsd_passed=$(field_count "$nested_live" 5 exercised)
nested_default_pending=$(awk -F '\t' \
    'NR > 1 && ($3 == "pending" || $5 == "pending") { n++ }
    END { print n + 0 }' "$nested_default")
nested_private_rows=$(rows "$nested_private")
startup_rows=$(rows "$startup_edges")

for row in \
    "| Requirement rows | $nested_rows |" \
    "| \`foundation-tested-experimental\` | $nested_foundation |" \
    "| \`experimental-pending-live\` | $nested_live_pending |" \
    "| \`pending\` implementation rows | $nested_pending |" \
    "| Live qualification groups | $nested_groups |" \
    "| Linux-L2 groups passed | $nested_linux_passed |" \
    "| 5BSD-L2 groups passed | $nested_fivebsd_passed |" \
    "| Default-off VPID qualification groups pending | $nested_default_pending |" \
    "| Implementation-defined interface rows | $nested_private_rows |" \
    "| Startup-entry edge rows | $startup_rows |"; do
	grep -Fqx "$row" "$matrix" || {
		echo "completion matrix: stale or missing count: $row" >&2
		exit 1
	}
done

echo "PASS completion matrix matches authoritative ledgers"
