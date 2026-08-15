#!/bin/sh
#
# Orchestrate the hardware-only nested-VMX qualification contract.
#
# The L1 image is intentionally not provisioned by this script.  Its runner
# is part of the immutable qualification input because it installs and boots
# the pinned Linux/KVM L1 and both L2 guests.  This host wrapper owns the
# safety checks, evidence schema, and all-or-nothing result publication.
#

set -eu

# This wrapper executes validation tools and the reviewed L1 driver as root.
# Do not inherit a caller-controlled helper search path or permissive creation
# mask into that authority boundary.
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077

: "${WORKDIR:?set WORKDIR to a new per-attempt directory}"
: "${NESTED_L1_RUNNER:?set NESTED_L1_RUNNER to the reviewed L1 driver}"
: "${NESTED_L1_IMAGE:?set NESTED_L1_IMAGE to the Linux/KVM L1 image}"
: "${NESTED_LINUX_L2_IMAGE:?set NESTED_LINUX_L2_IMAGE to the Linux L2 image}"
: "${NESTED_FIVEBSD_L2_IMAGE:?set NESTED_FIVEBSD_L2_IMAGE to the 5BSD L2 image}"

# Hardware evidence must be interpreted by the same reviewed source corpus
# that supplied the kernel and bhyve binary under qualification.  In
# particular, do not execute a caller-selected SRCTOP validator as root.
# The installed test layout is retained as a safe fallback; each selected
# ledger and validator is subsequently subjected to the privileged wrapper's
# ownership, mode, hierarchy, and identity checks.
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
src=/usr/src
if [ -f "$src/tests/sys/vmm/vmx-nested-live-qualification.tsv" ]; then
	testdir=$src/tests/sys/vmm
else
	testdir=$here
fi
vpid_qualification=${NESTED_VPID_QUALIFICATION:-1}
case "$vpid_qualification" in
0)
	ledger=$testdir/vmx-nested-default-policy-live-qualification.tsv
	;;
1)
	ledger=$testdir/vmx-nested-live-qualification.tsv
	;;
*)
	echo "nested-vmx live: NESTED_VPID_QUALIFICATION must be 0 or 1" >&2
	exit 1
	;;
esac
requirements=$testdir/validate-vmx-nested-requirements.sh
evidence_validator=$testdir/validate-vmx-nested-live-evidence.sh
staging_validator=$testdir/validate-vmx-nested-live-staging.sh
result=$WORKDIR/vmx-nested-live-result
staged_result=$result.new
evidence=$result/evidence.tsv
staged=$staged_result/evidence.tsv
artifact_dir=$staged_result/artifacts
artifact_hashes=$staged_result/artifacts.sha256
artifact_hashes_before=$artifact_hashes.before
artifact_hashes_after=$artifact_hashes.after
input_before=$staged_result/inputs.sha256
input_after=$staged_result/inputs.sha256.after
host_policy=$staged_result/host-policy.tsv
host_policy_after=$staged_result/host-policy.tsv.after
# Assigned only after WORKDIR has passed the root-owned, mode-0700 hierarchy
# checks below.  It is deliberately per invocation: failed qualification runs
# must be retryable in the same WORKDIR without reusing or colliding with an
# interrupted external runner's scratch files.
runner_tmp=
workdir_trusted=0
if [ -x /usr/obj/usr/src/amd64.amd64/usr.sbin/bhyve/bhyve ]; then
	default_bhyve=/usr/obj/usr/src/amd64.amd64/usr.sbin/bhyve/bhyve
else
	default_bhyve=/usr/sbin/bhyve
fi
bhyve=${BHYVE:-$default_bhyve}
live_timeout=${NESTED_LIVE_TIMEOUT:-14400}
snapshot_session_timeout=${NESTED_SNAPSHOT_SESSION_TIMEOUT:-120}
if [ -z "${NESTED_SNAPSHOT_SESSION_TEST:-}" ]; then
	if [ -x /usr/obj/usr/src/amd64.amd64/tests/sys/vmm/vmm_snapshot_session_live_test ]; then
		NESTED_SNAPSHOT_SESSION_TEST=/usr/obj/usr/src/amd64.amd64/tests/sys/vmm/vmm_snapshot_session_live_test
	else
		NESTED_SNAPSHOT_SESSION_TEST=/usr/tests/sys/vmm/vmm_snapshot_session_live_test
	fi
fi
if [ -z "${NESTED_STARTUP_STAGING_TEST:-}" ]; then
	if [ -x /usr/obj/usr/src/amd64.amd64/tests/sys/vmm/vmm_startup_staging_live_test ]; then
		NESTED_STARTUP_STAGING_TEST=/usr/obj/usr/src/amd64.amd64/tests/sys/vmm/vmm_startup_staging_live_test
	else
		NESTED_STARTUP_STAGING_TEST=/usr/tests/sys/vmm/vmm_startup_staging_live_test
	fi
fi

cleanup()
{
	status=$?
	trap - EXIT HUP INT TERM
	if [ -n "$runner_tmp" ] && [ -d "$runner_tmp" ] &&
	    [ ! -L "$runner_tmp" ]; then
		# runner_tmp is created by mktemp(1) below under the trusted, private
		# WORKDIR.  Do not recurse through a caller-selected pathname and do
		# not chmod its contents: an interrupted runner may have left symlinks
		# or hard links there.  rm(1) unlinks those directory entries without
		# following a final symlink.
		rm -rf -- "$runner_tmp"
	fi
	if [ "$status" -ne 0 ] && [ "$workdir_trusted" -eq 1 ] &&
	    [ -d "$staged_result" ] &&
	    [ ! -L "$staged_result" ]; then
		# Evidence is made read-only before its final validation.  A failed
		# validator must still leave the attempt retryable without allowing
		# cleanup to reach outside the exact unpublished staging directory.
		# Do not recursively chmod files: an interrupted external runner can
		# leave a symlink or hard link in staging, and cleanup must not alter
		# the target of either.  Only directories need write/search permission
		# for rm(1) to unlink their children; find(1) does not follow symlinks.
		find -x "$staged_result" -type d -exec chmod u+rwx {} + \
		    2>/dev/null || true
		rm -rf -- "$staged_result"
	fi
	exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail()
{
	echo "nested-vmx live: $*" >&2
	exit 1
}

regular_readable()
{
	[ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] ||
	    fail "$2 must be a readable regular file: $1"
}

trusted_path_hierarchy()
{
	path=$1
	label=$2
	trusted_path=$(/bin/realpath "$path") ||
	    fail "$label cannot be resolved"
	case "$trusted_path" in
	/*) ;;
	*) fail "$label did not resolve to an absolute path" ;;
	esac
	component=$trusted_path
	while :; do
		set -- $(stat -f '%u %Lp %l' "$component") ||
		    fail "$label has an unreadable path component: $component"
		[ "$1" -eq 0 ] ||
		    fail "$label path component is not owned by root: $component"
		[ $((0$2 & 0022)) -eq 0 ] ||
		    fail "$label path component is writable by group or other: $component"
		if [ "$component" = / ]; then
			break
		fi
		component=${component%/*}
		[ -n "$component" ] || component=/
	done
}

trusted_workdir_hierarchy()
{
	path=$1
	label=$2
	trusted_path=$(/bin/realpath "$path") ||
	    fail "$label cannot be resolved"
	case "$trusted_path" in
	/*) ;;
	*) fail "$label did not resolve to an absolute path" ;;
	esac
	component=$trusted_path
	while :; do
		set -- $(stat -f '%u %p' "$component") ||
		    fail "$label has an unreadable path component: $component"
		if [ "$1" -ne 0 ]; then
			fail "$label path component is not owned by root: $component"
		fi
		if [ $((0$2 & 0022)) -ne 0 ]; then
			# A root-owned sticky directory, notably /tmp, prevents an
			# unprivileged caller from renaming or unlinking the root-owned
			# child created below it.  Do not extend this exception to an
			# executable path or to the final work directory.
			[ -d "$component" ] && [ $((0$2 & 01000)) -ne 0 ] ||
			    fail "$label path component is writable by group or other: $component"
		fi
		if [ "$component" = / ]; then
			break
		fi
		component=${component%/*}
		[ -n "$component" ] || component=/
	done
}

trusted_executable()
{
	path=$1
	label=$2
	regular_readable "$path" "$label"
	[ -x "$path" ] || fail "$label is not executable"
	# Validate and retain the canonical path we will actually execute.  A
	# root-owned immutable file in a caller-writable directory is still
	# replaceable by rename after this check; every component of the resolved
	# pathname must therefore be protected as well.  Executing the resolved
	# path also prevents a later intermediate symlink substitution.
	trusted_path_hierarchy "$path" "$label"
	trusted_executable_path=$trusted_path
	set -- $(stat -f '%u %Lp %l' "$trusted_executable_path")
	[ "$1" -eq 0 ] || fail "$label must be owned by root"
	[ $((0$2 & 0022)) -eq 0 ] ||
	    fail "$label must not be writable by group or other"
	[ "$3" -eq 1 ] || fail "$label must not have hard-link aliases"
}

trusted_regular_input()
{
	path=$1
	label=$2

	# The L1 runner receives these paths while running with root authority.
	# A before/after digest detects a changed image after the fact, but cannot
	# prevent an untrusted pathname component from being replaced between that
	# digest and the runner's open(2).  Resolve the exact object once and apply
	# the same protected-hierarchy rule as executable inputs.  The images are
	# qualification corpus, not ordinary caller-owned VM disks.
	regular_readable "$path" "$label"
	trusted_path_hierarchy "$path" "$label"
	trusted_regular_input_path=$trusted_path
	set -- $(stat -f '%u %Lp' "$trusted_regular_input_path")
	[ "$1" -eq 0 ] || fail "$label must be owned by root"
	[ $((0$2 & 0022)) -eq 0 ] ||
	    fail "$label must not be writable by group or other"
}

write_host_policy()
{
	output=$1
	initialized=$(sysctl -n hw.vmm.vmx.initialized 2>/dev/null || echo 0)
	nested=$(sysctl -n hw.vmm.vmx.nested 2>/dev/null || echo 0)
	vpid=$(sysctl -n hw.vmm.vmx.nested_vpid 2>/dev/null || echo 0)
	osreldate=$(sysctl -n kern.osreldate 2>/dev/null || echo unknown)
	kernel_version_sha256=$(sysctl -n kern.version | sha256 -q)
	vmm_module_size=$(kldstat -n vmm.ko | awk 'NR == 2 { print $4 }')
	vmm_module_path=$(kldstat -v | awk '$5 == "vmm.ko" {
		start = index($0, "(")
		if (start == 0 || substr($0, length($0), 1) != ")")
			exit 1
		print substr($0, start + 1, length($0) - start - 1)
		exit
	}')
	[ -n "$vmm_module_size" ] ||
	    fail "cannot identify the loaded vmm.ko size"
	[ -n "$vmm_module_path" ] ||
	    fail "cannot identify the loaded vmm.ko path"
	regular_readable "$vmm_module_path" "loaded vmm.ko image"
	vmm_module_sha256=$(sha256 -q "$vmm_module_path")
	{
		printf 'format\tnested-vmx-host-policy-v2\n'
		printf 'vmx_initialized\t%s\n' "$initialized"
		printf 'nested_vmx\t%s\n' "$nested"
		printf 'nested_vpid_qualification\t%s\n' "$vpid"
		printf 'kern_osreldate\t%s\n' "$osreldate"
		printf 'kernel_version_sha256\t%s\n' "$kernel_version_sha256"
		printf 'vmm_module_size\t%s\n' "$vmm_module_size"
		printf 'vmm_module_sha256\t%s\n' "$vmm_module_sha256"
	} > "$output"
}

hash_artifacts()
{
	output=$1

	: > "$output"
	while IFS='	' read -r feature linux fivebsd host; do
		[ "$feature" = feature_id ] && continue
		for token in "$linux" "$fivebsd" "$host"; do
			name=${token#nested-vmx-live:}.evidence
			printf '%s  %s\n' \
			    "$(sha256 -q "$artifact_dir/$name")" "$name" \
			    >> "$output"
		done
	done < "$staged"
}

seal_artifacts()
{
	while IFS='	' read -r feature linux fivebsd host; do
		[ "$feature" = feature_id ] && continue
		for token in "$linux" "$fivebsd" "$host"; do
			name=${token#nested-vmx-live:}.evidence
			chmod 0400 "$artifact_dir/$name"
			fsync "$artifact_dir/$name"
		done
	done < "$staged"
	chmod 0400 "$staged"
	fsync "$staged"
}

[ "$(id -u)" -eq 0 ] || fail "hardware qualification requires root"
case "$live_timeout" in
''|*[!0-9]*) fail "NESTED_LIVE_TIMEOUT must be a positive integer" ;;
esac
[ "$live_timeout" -gt 0 ] ||
    fail "NESTED_LIVE_TIMEOUT must be a positive integer"
case "$snapshot_session_timeout" in
''|*[!0-9]*) fail "NESTED_SNAPSHOT_SESSION_TIMEOUT must be a positive integer" ;;
esac
[ "$snapshot_session_timeout" -gt 0 ] ||
    fail "NESTED_SNAPSHOT_SESSION_TIMEOUT must be a positive integer"
command -v timeout >/dev/null 2>&1 ||
    fail "timeout is required to bound the external L1 runner"
[ "$(sysctl -n hw.machine_arch)" = amd64 ] ||
    fail "hardware qualification requires an amd64 host"
[ "$(sysctl -n hw.vmm.vmx.initialized 2>/dev/null || echo 0)" = 1 ] ||
    fail "hardware qualification requires the initialized Intel VMX backend"
[ "$(sysctl -n hw.vmm.vmx.nested 2>/dev/null || echo 0)" = 1 ] ||
    fail "set hw.vmm.vmx.nested=1 at boot"
[ "$(sysctl -n hw.vmm.vmx.nested_vpid 2>/dev/null || echo 0)" =
    "$vpid_qualification" ] ||
    fail "hw.vmm.vmx.nested_vpid does not match qualification mode $vpid_qualification"
[ -d /dev/vmm ] || fail "vmm is not loaded"

trusted_regular_input "$ledger" "live qualification ledger"
ledger=$trusted_regular_input_path
feature_count=$(awk -F '	' 'NR > 1 { count++ } END { print count + 0 }' \
    "$ledger")
artifact_count=$((feature_count * 3))
[ "$feature_count" -gt 0 ] || fail "live qualification ledger is empty"
trusted_executable "$requirements" "nested requirement validator"
requirements=$trusted_executable_path
trusted_executable "$evidence_validator" "nested evidence validator"
evidence_validator=$trusted_executable_path
trusted_executable "$staging_validator" "nested staging validator"
staging_validator=$trusted_executable_path
"$requirements"

trusted_executable "$NESTED_L1_RUNNER" "L1 runner"
runner=$trusted_executable_path

trusted_regular_input "$NESTED_L1_IMAGE" "L1 image"
NESTED_L1_IMAGE=$trusted_regular_input_path
trusted_regular_input "$NESTED_LINUX_L2_IMAGE" "Linux L2 image"
NESTED_LINUX_L2_IMAGE=$trusted_regular_input_path
trusted_regular_input "$NESTED_FIVEBSD_L2_IMAGE" "5BSD L2 image"
NESTED_FIVEBSD_L2_IMAGE=$trusted_regular_input_path
trusted_executable "$bhyve" "bhyve"
bhyve=$trusted_executable_path
trusted_executable "$NESTED_SNAPSHOT_SESSION_TEST" \
    "snapshot-session live test"
snapshot_session_test=$trusted_executable_path
trusted_executable "$NESTED_STARTUP_STAGING_TEST" \
    "startup-staging live test"
startup_staging_test=$trusted_executable_path

identities=
for input in "$runner" "$NESTED_L1_IMAGE" \
	"$NESTED_LINUX_L2_IMAGE" "$NESTED_FIVEBSD_L2_IMAGE" "$bhyve" \
	"$snapshot_session_test" "$startup_staging_test" "$ledger" "$requirements" "$evidence_validator" \
	"$staging_validator"; do
	identity=$(stat -f '%d:%i' "$input")
	case " $identities " in
	*" $identity "*) fail "qualification inputs must be distinct files" ;;
	esac
	identities="$identities $identity"
done

case "$WORKDIR" in
/*) ;;
*) fail "WORKDIR must be an absolute path" ;;
esac
case "$WORKDIR" in
/|*/) fail "WORKDIR must name a directory without a trailing slash" ;;
esac
if [ -e "$WORKDIR" ]; then
	[ -d "$WORKDIR" ] && [ ! -L "$WORKDIR" ] ||
	    fail "WORKDIR must be a real directory"
	trusted_workdir_hierarchy "$WORKDIR" "WORKDIR"
	WORKDIR=$trusted_path
else
	workdir_name=${WORKDIR##*/}
	workdir_parent=${WORKDIR%/*}
	[ -n "$workdir_parent" ] || workdir_parent=/
	trusted_workdir_hierarchy "$workdir_parent" "WORKDIR parent"
	WORKDIR=$trusted_path/$workdir_name
	mkdir -m 0700 "$WORKDIR"
	trusted_workdir_hierarchy "$WORKDIR" "WORKDIR"
	WORKDIR=$trusted_path
fi
set -- $(stat -f '%u %Lp' "$WORKDIR")
[ "$1" -eq 0 ] && [ "$2" = 700 ] ||
    fail "WORKDIR must be root-owned mode 0700"
workdir_trusted=1
result=$WORKDIR/vmx-nested-live-result
staged_result=$result.new
evidence=$result/evidence.tsv
staged=$staged_result/evidence.tsv
artifact_dir=$staged_result/artifacts
artifact_hashes=$staged_result/artifacts.sha256
artifact_hashes_before=$artifact_hashes.before
artifact_hashes_after=$artifact_hashes.after
input_before=$staged_result/inputs.sha256
input_after=$staged_result/inputs.sha256.after
host_policy=$staged_result/host-policy.tsv
host_policy_after=$staged_result/host-policy.tsv.after
[ ! -e "$result" ] ||
    fail "published result already exists: $result"
[ ! -e "$staged_result" ] ||
    fail "staged result already exists: $staged_result"
mkdir -m 0700 "$staged_result"
mkdir -m 0700 "$artifact_dir"
runner_tmp=$(mktemp -d "$WORKDIR/runner-tmp.XXXXXX") ||
    fail "cannot create per-attempt runner scratch directory"
chmod 0700 "$runner_tmp"

export NESTED_EVIDENCE_FILE=$staged
export NESTED_LIVE_LEDGER=$ledger
export NESTED_LIVE_ARTIFACT_DIR=$artifact_dir
export NESTED_VMX_BHYVE=$bhyve
export NESTED_VPID_QUALIFICATION=$vpid_qualification

# These tests open /dev/vmm and therefore cannot be part of the rootless model
# gate.  Run them here, before L1 execution, so every hardware nested-VMX
# qualification proves both the snapshot-session descriptor/ownership contract
# and the fail-closed startup-management ABI.  Their immutable executables are
# included in the input identity and digest records below.
run_root_vmm_preflight()
{
	label=$1
	test_program=$2
	case_log=$runner_tmp/${label}-cases.log
	if ! "$test_program" -l >"$case_log" 2>&1; then
		cat "$case_log" >&2
		fail "$label live test case discovery failed"
	fi
	cases=$(awk '$1 == "ident:" { print $2 }' "$case_log")
	[ -n "$cases" ] ||
	    fail "$label live test declares no ATF cases"
	count=0
	for test_case in $cases; do
		log=$runner_tmp/${label}-${test_case}.log
		if ! timeout -k 30 "$snapshot_session_timeout" \
		    "$test_program" -r /dev/stdout "$test_case" \
		    >"$log" 2>&1 || ! tail -n 1 "$log" | grep -qx passed; then
			cat "$log" >&2
			fail "$label live preflight failed: $test_case"
		fi
		count=$((count + 1))
	done
	echo "nested-vmx live: $label preflight cases=$count"
}

# Bind every guest assertion and host trace to this invocation.  The external
# L1 runner must copy this opaque identifier into each artifact; accepting an
# otherwise well-formed bundle from an earlier run would turn qualification
# into a cache hit rather than evidence of current hardware execution.
command -v uuidgen >/dev/null 2>&1 ||
    fail "uuidgen is required to bind evidence to this qualification run"
NESTED_LIVE_RUN_ID=$(uuidgen | tr -d '-' | tr '[:upper:]' '[:lower:]')
case "$NESTED_LIVE_RUN_ID" in
????????????????????????????????) ;;
*) fail "could not create a qualification run identifier" ;;
esac
export NESTED_LIVE_RUN_ID

for input in "$runner" "$NESTED_L1_IMAGE" \
	"$NESTED_LINUX_L2_IMAGE" "$NESTED_FIVEBSD_L2_IMAGE" "$bhyve" \
	"$snapshot_session_test" "$startup_staging_test" "$ledger" "$requirements" "$evidence_validator" \
	"$staging_validator"; do
	printf '%s  %s\n' "$(sha256 -q "$input")" "$input"
done > "$input_before"
write_host_policy "$host_policy"
run_root_vmm_preflight snapshot-session "$snapshot_session_test"
run_root_vmm_preflight startup-staging "$startup_staging_test"

# The external L1 driver is an immutable qualification input, but it is still
# a separate program executed with root authority.  Give it only the reviewed
# contract below; in particular, do not let caller-provided loader, language,
# build, or helper-selection variables change its behavior.
if env -i \
    PATH="$PATH" \
    HOME=/root \
    LANG=C \
    TMPDIR="$runner_tmp" \
    WORKDIR="$WORKDIR" \
    NESTED_L1_IMAGE="$NESTED_L1_IMAGE" \
    NESTED_LINUX_L2_IMAGE="$NESTED_LINUX_L2_IMAGE" \
    NESTED_FIVEBSD_L2_IMAGE="$NESTED_FIVEBSD_L2_IMAGE" \
    NESTED_EVIDENCE_FILE="$staged" \
    NESTED_LIVE_LEDGER="$ledger" \
    NESTED_LIVE_ARTIFACT_DIR="$artifact_dir" \
    NESTED_VMX_BHYVE="$bhyve" \
    NESTED_VPID_QUALIFICATION="$vpid_qualification" \
    NESTED_LIVE_RUN_ID="$NESTED_LIVE_RUN_ID" \
    NESTED_LIVE_TIMEOUT="$live_timeout" \
    timeout -k 30 "$live_timeout" "$runner"; then
	:
else
	status=$?
	fail "L1 runner failed or exceeded ${live_timeout}s (status $status)"
fi

for input in "$runner" "$NESTED_L1_IMAGE" \
	"$NESTED_LINUX_L2_IMAGE" "$NESTED_FIVEBSD_L2_IMAGE" "$bhyve" \
	"$snapshot_session_test" "$startup_staging_test" "$ledger" "$requirements" "$evidence_validator" \
	"$staging_validator"; do
	printf '%s  %s\n' "$(sha256 -q "$input")" "$input"
done > "$input_after"
cmp -s "$input_before" "$input_after" ||
    fail "qualification input changed during execution"
rm -f "$input_after"
write_host_policy "$host_policy_after"
cmp -s "$host_policy" "$host_policy_after" ||
    fail "host nested-VMX policy changed during execution"
rm -f "$host_policy_after"

regular_readable "$staged" "staged evidence"
NESTED_LIVE_LEDGER=$ledger "$staging_validator" "$staged" "$artifact_dir"
hash_artifacts "$artifact_hashes_before"
seal_artifacts
NESTED_LIVE_LEDGER=$ledger NESTED_LIVE_ARTIFACT_DIR=$artifact_dir \
    NESTED_LIVE_RUN_ID=$NESTED_LIVE_RUN_ID \
    "$evidence_validator" "$staged"
hash_artifacts "$artifact_hashes_after"
cmp -s "$artifact_hashes_before" "$artifact_hashes_after" ||
    fail "evidence artifact changed during validation"

mv "$artifact_hashes_after" "$artifact_hashes"
rm -f "$artifact_hashes_before"
chmod 0400 "$staged" "$artifact_hashes" "$input_before" "$host_policy"
fsync "$staged" "$artifact_hashes" "$input_before" "$host_policy"
chmod 0500 "$artifact_dir"
fsync "$artifact_dir"
chmod 0500 "$staged_result"
fsync "$staged_result"
mv "$staged_result" "$result"
fsync "$WORKDIR"
echo "PASS nested-vmx live feature-groups=$feature_count artifacts=$artifact_count evidence=$evidence hashes=$result/artifacts.sha256"
