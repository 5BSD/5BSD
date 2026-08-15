#!/bin/sh
#
# Exercise the rootless structural boundary of the privileged nested-VMX
# evidence validator.  This does not manufacture hardware qualification; it
# proves that a well-formed bundle is accepted and that filesystem aliases are
# rejected before their contents can be interpreted as independent evidence.
#

set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
validator=$here/validate-vmx-nested-live-evidence.sh
work=$(mktemp -d /tmp/nested-vmx-evidence.XXXXXX)
ledger=$work/ledger.tsv
evidence=$work/evidence.tsv
artifacts=$work/artifacts
run_id=0123456789abcdef0123456789abcdef

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

mkdir "$artifacts"

# private-test: malformed-bundles
printf '%s\n' 'feature_id	requirement_ids	linux_l2_status	linux_l2_evidence	fivebsd_l2_status	fivebsd_l2_evidence	host_evidence	notes' > "$ledger"
printf '%s\n' 'feature_id	linux_l2_evidence	fivebsd_l2_evidence	host_evidence' > "$evidence"

i=1
while [ "$i" -le 10 ]; do
	feature=$(printf 'FEATURE-%02d' "$i")
	linux=$(printf 'linux-%02d' "$i")
	fivebsd=$(printf 'fivebsd-%02d' "$i")
	host=$(printf 'host-%02d' "$i")
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
	    "$feature" "REQ-$i" pending - pending - - selftest >> "$ledger"
	printf '%s\tnested-vmx-live:%s\tnested-vmx-live:%s\tnested-vmx-live:%s\n' \
	    "$feature" "$linux" "$fivebsd" "$host" >> "$evidence"
	for item in "linux-l2:$linux" "fivebsd-l2:$fivebsd" "host:$host"; do
		role=${item%%:*}
		name=${item#*:}
		{
			printf 'format\tnested-vmx-live-evidence-v3\n'
			printf 'feature_id\t%s\n' "$feature"
			printf 'role\t%s\n' "$role"
			printf 'result\tPASS\n'
			printf 'run_id\t%s\n' "$run_id"
			printf 'started_utc\t2026-07-31T00:00:00Z\n'
			printf 'finished_utc\t2026-07-31T00:00:01Z\n'
			printf 'assertion\tREQ-%s\n' "$i"
			if [ "$role" = host ]; then
				printf 'proof\tREQ-%s\thost-trace\tselftest-%s\t1\n' \
				    "$i" "$name"
			else
				printf 'proof\tREQ-%s\tguest-test\tselftest-%s\t1\n' \
				    "$i" "$name"
			fi
		} > "$artifacts/$name.evidence"
		chmod 0444 "$artifacts/$name.evidence"
	done
	i=$((i + 1))
done
chmod 0444 "$evidence"

# A symlink is not a completed manifest object even when its target is a
# regular read-only file owned by the caller.
mv -f "$evidence" "$work/evidence.real"
ln -s "$work/evidence.real" "$evidence"
if NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifacts \
    NESTED_LIVE_RUN_ID=$run_id "$validator" "$evidence" \
    >"$work/symlink-manifest.out" 2>&1; then
	echo "nested-vmx evidence selftest: symlink manifest was accepted" >&2
	exit 1
fi
grep -q 'evidence is not readable' "$work/symlink-manifest.out" || {
	cat "$work/symlink-manifest.out" >&2
	echo "nested-vmx evidence selftest: symlink manifest failed for wrong reason" >&2
	exit 1
}
rm "$evidence"
mv -f "$work/evidence.real" "$evidence"

NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifacts \
NESTED_LIVE_RUN_ID=$run_id "$validator" "$evidence" >/dev/null

# Naming a requirement without one requirement-specific execution
# observation is not evidence.  Schema v3 requires a typed proof for every
# assertion rather than one arbitrary description for an entire group.
chmod 0644 "$artifacts/linux-01.evidence"
sed '/^proof\t/d' "$artifacts/linux-01.evidence" > "$work/missing-proof"
mv -f "$work/missing-proof" "$artifacts/linux-01.evidence"
chmod 0444 "$artifacts/linux-01.evidence"
if NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifacts \
    NESTED_LIVE_RUN_ID=$run_id "$validator" "$evidence" \
    >"$work/missing-proof.out" 2>&1; then
	echo "nested-vmx evidence selftest: missing requirement proof was accepted" >&2
	exit 1
fi
grep -q 'artifact does not prove' "$work/missing-proof.out" || {
	cat "$work/missing-proof.out" >&2
	echo "nested-vmx evidence selftest: missing proof failed for wrong reason" >&2
	exit 1
}
chmod 0644 "$artifacts/linux-01.evidence"
printf 'proof\tREQ-1\tguest-test\tselftest-linux-01\t1\n' \
    >> "$artifacts/linux-01.evidence"
chmod 0444 "$artifacts/linux-01.evidence"

# Timestamp fields must identify real UTC instants, not merely match the
# expected printable shape.
chmod 0644 "$artifacts/linux-01.evidence"
sed 's/^started_utc\t2026-07-31T00:00:00Z$/started_utc\t2026-02-30T00:00:00Z/' \
    "$artifacts/linux-01.evidence" > "$work/impossible-timestamp"
mv -f "$work/impossible-timestamp" "$artifacts/linux-01.evidence"
chmod 0444 "$artifacts/linux-01.evidence"
if NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifacts \
    NESTED_LIVE_RUN_ID=$run_id "$validator" "$evidence" \
    >"$work/impossible-timestamp.out" 2>&1; then
	echo "nested-vmx evidence selftest: impossible timestamp was accepted" >&2
	exit 1
fi
grep -q 'invalid UTC timestamp' "$work/impossible-timestamp.out" || {
	cat "$work/impossible-timestamp.out" >&2
	echo "nested-vmx evidence selftest: impossible timestamp failed for wrong reason" >&2
	exit 1
}
chmod 0644 "$artifacts/linux-01.evidence"
sed 's/^started_utc\t2026-02-30T00:00:00Z$/started_utc\t2026-07-31T00:00:00Z/' \
    "$artifacts/linux-01.evidence" > "$work/valid-timestamp"
mv -f "$work/valid-timestamp" "$artifacts/linux-01.evidence"
chmod 0444 "$artifacts/linux-01.evidence"

# A completed artifact is a closed schema: an unrecognised record must not be
# ignored merely because the mandatory proof records are present.
chmod 0644 "$artifacts/linux-01.evidence"
printf 'unexpected_record\tvalue\n' >> "$artifacts/linux-01.evidence"
chmod 0444 "$artifacts/linux-01.evidence"
if NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifacts \
    NESTED_LIVE_RUN_ID=$run_id "$validator" "$evidence" \
    >"$work/unknown-record.out" 2>&1; then
	echo "nested-vmx evidence selftest: unknown artifact record was accepted" >&2
	exit 1
fi
grep -q 'artifact does not prove' "$work/unknown-record.out" || {
	cat "$work/unknown-record.out" >&2
	echo "nested-vmx evidence selftest: unknown record failed for wrong reason" >&2
	exit 1
}
chmod 0644 "$artifacts/linux-01.evidence"
sed '/^unexpected_record\t/d' "$artifacts/linux-01.evidence" > \
    "$work/known-records"
mv -f "$work/known-records" "$artifacts/linux-01.evidence"
chmod 0444 "$artifacts/linux-01.evidence"

# A named test which reports zero observations must not satisfy a live
# requirement.
chmod 0644 "$artifacts/linux-01.evidence"
sed 's/\tselftest-linux-01\t1$/\tselftest-linux-01\t0/' \
    "$artifacts/linux-01.evidence" > "$work/zero-proof"
mv -f "$work/zero-proof" "$artifacts/linux-01.evidence"
chmod 0444 "$artifacts/linux-01.evidence"
if NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifacts \
    NESTED_LIVE_RUN_ID=$run_id "$validator" "$evidence" \
    >"$work/zero-proof.out" 2>&1; then
	echo "nested-vmx evidence selftest: zero-count proof was accepted" >&2
	exit 1
fi
grep -q 'artifact does not prove' "$work/zero-proof.out" || {
	cat "$work/zero-proof.out" >&2
	echo "nested-vmx evidence selftest: zero proof failed for wrong reason" >&2
	exit 1
}
sed 's/\tselftest-linux-01\t0$/\tselftest-linux-01\t1/' \
    "$artifacts/linux-01.evidence" > "$work/restored-proof"
mv -f "$work/restored-proof" "$artifacts/linux-01.evidence"
chmod 0444 "$artifacts/linux-01.evidence"

# A host trace cannot stand in for execution inside either L2 guest.  Keeping
# proof kinds role-specific prevents a single host-side observation from being
# replicated across all three evidence columns.
chmod 0644 "$artifacts/linux-01.evidence"
sed 's/\tguest-test\tselftest-linux-01\t1$/\thost-trace\tselftest-linux-01\t1/' \
    "$artifacts/linux-01.evidence" > "$work/wrong-role-proof"
mv -f "$work/wrong-role-proof" "$artifacts/linux-01.evidence"
chmod 0444 "$artifacts/linux-01.evidence"
if NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifacts \
    NESTED_LIVE_RUN_ID=$run_id "$validator" "$evidence" \
    >"$work/wrong-role-proof.out" 2>&1; then
	echo "nested-vmx evidence selftest: cross-role proof was accepted" >&2
	exit 1
fi
grep -q 'artifact does not prove' "$work/wrong-role-proof.out" || {
	cat "$work/wrong-role-proof.out" >&2
	echo "nested-vmx evidence selftest: cross-role proof failed for wrong reason" >&2
	exit 1
}
sed 's/\thost-trace\tselftest-linux-01\t1$/\tguest-test\tselftest-linux-01\t1/' \
    "$artifacts/linux-01.evidence" > "$work/restored-role-proof"
mv -f "$work/restored-role-proof" "$artifacts/linux-01.evidence"
chmod 0444 "$artifacts/linux-01.evidence"

# A completed artifact must not remain writable even by its owner.  Read-only
# content is an explicit evidence boundary rather than a convention left to
# the producer.
chmod 0644 "$artifacts/linux-01.evidence"
if NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifacts \
    NESTED_LIVE_RUN_ID=$run_id "$validator" "$evidence" \
    >"$work/writable.out" 2>&1; then
	echo "nested-vmx evidence selftest: writable bundle was accepted" >&2
	exit 1
fi
grep -q 'must be read-only' "$work/writable.out" || {
	cat "$work/writable.out" >&2
	echo "nested-vmx evidence selftest: writable artifact failed for wrong reason" >&2
	exit 1
}
chmod 0444 "$artifacts/linux-01.evidence"

# The manifest is part of the same completed transaction.  Accepting a
# writable manifest would let the artifact mapping change between validation
# passes even when every artifact is immutable.
chmod 0644 "$evidence"
if NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifacts \
    NESTED_LIVE_RUN_ID=$run_id "$validator" "$evidence" \
    >"$work/writable-manifest.out" 2>&1; then
	echo "nested-vmx evidence selftest: writable manifest was accepted" >&2
	exit 1
fi
grep -q 'manifest must be read-only' "$work/writable-manifest.out" || {
	cat "$work/writable-manifest.out" >&2
	echo "nested-vmx evidence selftest: writable manifest failed for wrong reason" >&2
	exit 1
}
chmod 0444 "$evidence"

# Replace one otherwise required path with a hard link.  Its link count makes
# the bundle invalid even if a producer attempts to rewrite the shared inode
# between per-role validation passes.
rm -f "$artifacts/fivebsd-01.evidence"
ln "$artifacts/linux-01.evidence" "$artifacts/fivebsd-01.evidence"
if NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifacts \
    NESTED_LIVE_RUN_ID=$run_id "$validator" "$evidence" \
    >"$work/alias.out" 2>&1; then
	echo "nested-vmx evidence selftest: aliased bundle was accepted" >&2
	exit 1
fi
grep -q 'must not have aliases' "$work/alias.out" || {
	cat "$work/alias.out" >&2
	echo "nested-vmx evidence selftest: alias failed for wrong reason" >&2
	exit 1
}

echo "PASS nested-vmx evidence validator"
