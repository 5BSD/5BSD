#!/bin/sh
#
# Validate the two immutable nested-VMX qualification transactions required
# by the loader-only VPID policy.  Neither boot is sufficient by itself.
#

set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
positive=${1:?usage: validate-vmx-nested-policy-pair.sh positive-result default-off-result}
default_off=${2:?usage: validate-vmx-nested-policy-pair.sh positive-result default-off-result}
validator=$here/validate-vmx-nested-live-evidence.sh
positive_ledger=$here/vmx-nested-live-qualification.tsv
default_ledger=$here/vmx-nested-default-policy-live-qualification.tsv
scratch=$(mktemp -d /tmp/nested-vmx-policy-pair-verify.XXXXXX)

cleanup()
{
	trap - EXIT HUP INT TERM
	rm -rf "$scratch"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail()
{
	echo "nested-vmx policy pair: $*" >&2
	exit 1
}

require_sealed_file()
{
	path=$1
	[ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] ||
	    fail "missing result file: $path"
	set -- $(stat -f '%u %Lp %l' "$path")
	[ "$1" -eq "$(id -u)" ] && [ $((0$2 & 0222)) -eq 0 ] &&
	    [ "$3" -eq 1 ] || fail "result file is not sealed: $path"
}

validate_inputs()
{
	path=$1

	# Both policy boots bind evidence to the runner, guest images, bhyve,
	# live ledger, and reviewed validators.  A sealed but opaque list is not
	# sufficient provenance for a hardware qualification result.
	awk '
	NF != 2 || $1 !~ /^[0-9a-f]{64}$/ || $2 !~ /^\// || seen[$2]++ {
		bad = 1
	}
	END { exit !(NR == 9 && !bad) }
	' "$path" || fail "invalid qualification input manifest: $path"
}

validate_policy()
{
	result=$1
	expected_vpid=$2
	policy=$result/host-policy.tsv

	require_sealed_file "$policy"
	awk -F '\t' -v expected="$expected_vpid" '
	NR == 1 { good = $0 == "format\tnested-vmx-host-policy-v2"; next }
	NR == 2 { good = good && $1 == "vmx_initialized" && $2 == "1"; next }
	NR == 3 { good = good && $1 == "nested_vmx" && $2 == "1"; next }
	NR == 4 { good = good && $1 == "nested_vpid_qualification" && $2 == expected; next }
	NR == 5 { good = good && $1 == "kern_osreldate" && $2 ~ /^[0-9]+$/; next }
	NR == 6 { good = good && $1 == "kernel_version_sha256" &&
	    $2 ~ /^[0-9a-f]{64}$/; next }
	NR == 7 { good = good && $1 == "vmm_module_size" &&
	    $2 ~ /^[0-9a-f]+$/; next }
	NR == 8 { good = good && $1 == "vmm_module_sha256" &&
	    $2 ~ /^[0-9a-f]{64}$/; next }
	{ good = 0 }
	END { exit !(good && NR == 8) }
	' "$policy" || fail "invalid host policy: $policy"
}

validate_result()
{
	result=$1
	ledger=$2
	expected_vpid=$3
	evidence=$result/evidence.tsv
	artifacts=$result/artifacts
	hashes=$result/artifacts.sha256
	inputs=$result/inputs.sha256

	[ -d "$result" ] && [ ! -L "$result" ] ||
	    fail "result is not a real directory: $result"
	[ -d "$artifacts" ] && [ ! -L "$artifacts" ] ||
	    fail "artifact directory is invalid: $artifacts"
	set -- $(stat -f '%u %Lp' "$result")
	[ "$1" -eq "$(id -u)" ] && [ $((0$2 & 0222)) -eq 0 ] ||
	    fail "result directory is not sealed: $result"
	set -- $(stat -f '%u %Lp' "$artifacts")
	[ "$1" -eq "$(id -u)" ] && [ $((0$2 & 0222)) -eq 0 ] ||
	    fail "artifact directory is not sealed: $artifacts"
	for file in "$evidence" "$hashes" "$inputs"; do
		require_sealed_file "$file"
	done
	validate_inputs "$inputs"
	validate_policy "$result" "$expected_vpid"
	run_ids=$(awk -F '\t' '$1 == "run_id" { print $2 }' \
	    "$artifacts"/*.evidence | sort -u)
	[ "$(printf '%s\n' "$run_ids" | sed '/^$/d' | wc -l | tr -d ' ')" -eq 1 ] ||
	    fail "artifacts do not share one run identifier: $result"
	run_id=$run_ids
	case "$run_id" in
	[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
	*) fail "invalid run identifier: $result" ;;
	esac
	canonical_hashes=$(mktemp "$scratch/artifact-hashes.XXXXXX")
	(
		cd "$artifacts"
		find . -mindepth 1 -maxdepth 1 -type f -name '*.evidence' \
		    -exec basename {} \; | sort |
		while read -r file; do
			printf '%s  %s\n' "$(sha256 -q "$file")" "$file"
		done
	) > "$canonical_hashes"
	if ! cmp -s "$canonical_hashes" "$hashes"; then
		fail "artifact hash manifest is not canonical: $result"
	fi
	NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifacts \
	    NESTED_LIVE_RUN_ID=$run_id "$validator" "$evidence" >/dev/null
	printf '%s\n' "$run_id"
}

[ "$(stat -f '%d:%i' "$positive")" != "$(stat -f '%d:%i' "$default_off")" ] ||
    fail "positive and default-off results must be distinct directories"
positive_run=$(validate_result "$positive" "$positive_ledger" 1)
default_run=$(validate_result "$default_off" "$default_ledger" 0)
[ "$positive_run" != "$default_run" ] ||
    fail "positive and default-off transactions must have distinct run identifiers"
cmp -s "$positive/inputs.sha256" "$default_off/inputs.sha256" ||
    fail "qualification inputs differ between policy boots"
awk -F '\t' '$1 != "nested_vpid_qualification"' \
    "$positive/host-policy.tsv" > "$scratch/positive-policy"
awk -F '\t' '$1 != "nested_vpid_qualification"' \
    "$default_off/host-policy.tsv" > "$scratch/default-policy"
cmp -s "$scratch/positive-policy" "$scratch/default-policy" ||
    fail "kernel or vmm module identity differs between policy boots"
positive_abi=$(awk -F '\t' '$1 == "kern_osreldate" { print $2 }' \
    "$positive/host-policy.tsv")

echo "PASS nested-vmx policy pair positive=$positive_run default-off=$default_run kernel-abi=$positive_abi"
