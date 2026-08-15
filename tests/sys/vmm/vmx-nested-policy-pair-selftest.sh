#!/bin/sh
# Rootless structural tests for the two-boot nested policy result verifier.

set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
verifier=$here/validate-vmx-nested-policy-pair.sh
positive_ledger=$here/vmx-nested-live-qualification.tsv
default_ledger=$here/vmx-nested-default-policy-live-qualification.tsv
work=$(mktemp -d /tmp/nested-vmx-policy-pair.XXXXXX)

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

make_result()
{
	result=$1
	ledger=$2
	run_id=$3
	vpid=$4
	artifacts=$result/artifacts
	evidence=$result/evidence.tsv

	mkdir -m 0700 "$result" "$artifacts"
	printf '%s\n' \
	    'feature_id	linux_l2_evidence	fivebsd_l2_evidence	host_evidence' \
	    > "$evidence"
	number=0
	while IFS='	' read -r feature requirements rest; do
		[ "$feature" = feature_id ] && continue
		number=$((number + 1))
		printf '%s\tnested-vmx-live:linux-%s\tnested-vmx-live:fivebsd-%s\tnested-vmx-live:host-%s\n' \
		    "$feature" "$number" "$number" "$number" >> "$evidence"
		for role in linux-l2 fivebsd-l2 host; do
			case "$role" in
			linux-l2) name=linux-$number; kind=guest-test ;;
			fivebsd-l2) name=fivebsd-$number; kind=guest-test ;;
			host) name=host-$number; kind=host-trace ;;
			esac
			{
				printf 'format\tnested-vmx-live-evidence-v3\n'
				printf 'feature_id\t%s\n' "$feature"
				printf 'role\t%s\n' "$role"
				printf 'result\tPASS\n'
				printf 'run_id\t%s\n' "$run_id"
				printf 'started_utc\t2026-08-01T00:00:00Z\n'
				printf 'finished_utc\t2026-08-01T00:00:01Z\n'
				printf '%s\n' "$requirements" | tr ';' '\n' |
				while read -r requirement; do
					printf 'assertion\t%s\n' "$requirement"
					printf 'proof\t%s\t%s\tselftest-%s\t1\n' \
					    "$requirement" "$kind" "$name"
				done
			} > "$artifacts/$name.evidence"
			chmod 0400 "$artifacts/$name.evidence"
		done
	done < "$ledger"
	{
		printf 'format\tnested-vmx-host-policy-v2\n'
		printf 'vmx_initialized\t1\n'
		printf 'nested_vmx\t1\n'
		printf 'nested_vpid_qualification\t%s\n' "$vpid"
		printf 'kern_osreldate\t1500048\n'
		printf 'kernel_version_sha256\t%s\n' \
		    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
		printf 'vmm_module_size\t348740\n'
		printf 'vmm_module_sha256\t%s\n' \
		    bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
	} > "$result/host-policy.tsv"
	for item in runner l1-image linux-l2-image fivebsd-l2-image bhyve \
	    ledger requirements evidence-validator staging-validator; do
		printf '%s  /immutable/%s\n' \
		    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
		    "$item"
	done > "$result/inputs.sha256"
	(
		cd "$artifacts"
		for file in *.evidence; do
			printf '%s  %s\n' "$(sha256 -q "$file")" "$file"
		done
	) > "$result/artifacts.sha256"
	chmod 0400 "$evidence" "$result/host-policy.tsv" \
	    "$result/inputs.sha256" "$result/artifacts.sha256"
	chmod 0500 "$artifacts" "$result"
}

make_result "$work/positive" "$positive_ledger" \
    11111111111111111111111111111111 1
make_result "$work/default" "$default_ledger" \
    22222222222222222222222222222222 0
"$verifier" "$work/positive" "$work/default" >/dev/null

chmod 0700 "$work/default"
chmod 0600 "$work/default/host-policy.tsv"
sed -i '' 's/nested_vpid_qualification	0/nested_vpid_qualification	1/' \
    "$work/default/host-policy.tsv"
chmod 0400 "$work/default/host-policy.tsv"
chmod 0500 "$work/default"
if "$verifier" "$work/positive" "$work/default" \
    >"$work/bad.out" 2>"$work/bad.err"; then
	echo "nested-vmx policy pair selftest: policy mismatch accepted" >&2
	exit 1
fi
grep -q 'invalid host policy' "$work/bad.err"

chmod 0700 "$work/default"
chmod 0600 "$work/default/host-policy.tsv"
sed -i '' \
    -e 's/nested_vpid_qualification\t1/nested_vpid_qualification\t0/' \
    -e 's/vmm_module_sha256\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/vmm_module_sha256\tcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/' \
    "$work/default/host-policy.tsv"
chmod 0400 "$work/default/host-policy.tsv"
chmod 0500 "$work/default"
if "$verifier" "$work/positive" "$work/default" \
    >"$work/build.out" 2>"$work/build.err"; then
	echo "nested-vmx policy pair selftest: module mismatch accepted" >&2
	exit 1
fi
grep -q 'kernel or vmm module identity differs' "$work/build.err"

# A policy pair must not accept an opaque or incomplete input hash list.  The
# result directory and every other artifact remain sealed, so this exercises
# the input-provenance validator rather than a generic permission rejection.
chmod 0700 "$work/default"
chmod 0600 "$work/default/inputs.sha256"
sed '1s/^[0-9a-f]*/bad/' "$work/default/inputs.sha256" \
    > "$work/default/inputs.bad"
mv -f "$work/default/inputs.bad" "$work/default/inputs.sha256"
chmod 0400 "$work/default/inputs.sha256"
chmod 0500 "$work/default"
if "$verifier" "$work/positive" "$work/default" \
    >"$work/input.out" 2>"$work/input.err"; then
	echo "nested-vmx policy pair selftest: malformed inputs were accepted" >&2
	exit 1
fi
grep -q 'invalid qualification input manifest' "$work/input.err"

echo "PASS nested-vmx policy pair verifier"
