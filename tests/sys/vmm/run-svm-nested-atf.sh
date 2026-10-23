#!/bin/sh
# Run the AMD nested-SVM ATF gate against installed, root-owned inputs.
# Run POLICY_ONLY=1 on a separate boot with hw.vmm.svm.nested=0.

set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077

: "${WORKDIR:?set WORKDIR to an existing private root-owned directory}"
POLICY_ONLY=${POLICY_ONLY:-0}
MODULE=${MODULE:-/boot/kernel/vmm.ko}
KERNEL=${KERNEL:-/boot/kernel/kernel}
KYUAFILE=${KYUAFILE:-/usr/tests/sys/vmm/Kyuafile}

fail()
{
	echo "nested-svm ATF: $*" >&2
	exit 1
}

trusted_input()
{
	[ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] ||
	    fail "missing regular $2: $1"
	resolved=$(/bin/realpath "$1") || fail "cannot resolve $2"
	component=$resolved
	while :; do
		set -- $(stat -f '%u %Lp %l' "$component") ||
		    fail "cannot inspect $2 path component: $component"
		[ "$1" -eq 0 ] && [ $((0$2 & 0022)) -eq 0 ] ||
		    fail "$2 path is not root-owned and protected: $component"
		[ "$component" = / ] && break
		component=${component%/*}
		[ -n "$component" ] || component=/
	done
	set -- $(stat -f '%u %Lp %l' "$resolved")
	[ "$3" -eq 1 ] || fail "$2 has hard-link aliases: $resolved"
	trusted_input_path=$resolved
}

trusted_workdir()
{
	[ -d "$1" ] && [ ! -L "$1" ] ||
	    fail "WORKDIR is not a directory: $1"
	resolved=$(/bin/realpath "$1") || fail "cannot resolve WORKDIR"
	component=$resolved
	set -- $(stat -f '%u %Lp' "$component")
	[ "$1" -eq 0 ] && [ "$2" = 700 ] ||
	    fail "WORKDIR must be root-owned mode 0700"
	while :; do
		set -- $(stat -f '%u %Lp' "$component") ||
		    fail "cannot inspect WORKDIR ancestor: $component"
		[ "$1" -eq 0 ] || fail "WORKDIR ancestor is not root-owned"
		if [ $((0$2 & 0022)) -ne 0 ]; then
			[ -d "$component" ] &&
			    [ $((0$2 & 01000)) -ne 0 ] ||
			    fail "WORKDIR ancestor is writable without sticky protection"
		fi
		[ "$component" = / ] && break
		component=${component%/*}
		[ -n "$component" ] || component=/
	done
	workdir_path=$resolved
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"
case "$POLICY_ONLY" in
0|1) ;;
*) fail "POLICY_ONLY must be 0 or 1" ;;
esac
trusted_workdir "$WORKDIR"
trusted_input "$MODULE" "vmm module"
module_path=$trusted_input_path
trusted_input "$KERNEL" "kernel"
kernel_path=$trusted_input_path
trusted_input "$KYUAFILE" "Kyuafile"
kyuafile_path=$trusted_input_path
test_binary=${kyuafile_path%/*}/vmm_run_live_test
trusted_input "$test_binary" "live test binary"
[ -x "$trusted_input_path" ] || fail "live test binary is not executable"
test_binary=$trusted_input_path
case_ledger=${kyuafile_path%/*}/svm-nested-atf-cases.tsv
trusted_input "$case_ledger" "nested-SVM case ledger"
case_ledger=$trusted_input_path

running_id=$(sysctl -n kern.build_id) || fail "cannot read kernel build ID"
kernel_id=$(readelf -n "$kernel_path" |
    awk '/Build ID:/ { print $3; exit }') ||
    fail "cannot read kernel image build ID"
[ -n "$running_id" ] && [ "$running_id" = "$kernel_id" ] ||
    fail "running kernel does not match $kernel_path"
kldstat -q -m vmm || fail "vmm is not loaded"
kldstat -v | grep -F "vmm.ko ($module_path)" >/dev/null ||
    fail "loaded vmm does not match $module_path"
[ -c /dev/vmmctl ] || fail "/dev/vmmctl is unavailable"
for node in /dev/vmm/*; do
	[ "$node" = /dev/vmm/ctl ] && continue
	[ ! -c "$node" ] || fail "active VM blocks qualification: $node"
done

nested=$(sysctl -n hw.vmm.svm.nested 2>/dev/null) ||
    fail "AMD nested-SVM policy is unavailable"
features=$(sysctl -n hw.vmm.svm.features 2>/dev/null) ||
    fail "AMD SVM feature mask is unavailable"
case "$features" in
''|*[!0-9]*) fail "invalid AMD SVM feature mask: $features" ;;
esac
if [ "$POLICY_ONLY" -eq 1 ]; then
	[ "$nested" = 0 ] || fail "default-off policy boot requires nested=0"
else
	[ "$nested" = 1 ] || fail "enabled boot requires nested=1"
	[ $((features & 128)) -ne 0 ] ||
	    fail "AMD DecodeAssists is required"
fi

attempt=$(mktemp -d "$workdir_path/svm-nested-atf.XXXXXXXX") ||
    fail "cannot create private attempt directory"
inventory=$attempt/inventory.txt
kyua list -k "$kyuafile_path" > "$inventory" ||
    fail "cannot list installed live tests; evidence: $attempt"
[ "$(sed -n '1p' "$case_ledger")" = "$(printf 'case_id\tfeature')" ] ||
    fail "invalid nested-SVM case ledger header; evidence: $attempt"
awk -F '\t' '
NR == 1 { next }
{
	if (NF != 2 || $1 !~ /^vmm_run_live_test:svm_[a-z0-9_]+$/ ||
	    ($2 != "policy" && $2 != "core" && $2 != "virtual-nmi") ||
	    seen[$1]++) {
		print "invalid nested-SVM case ledger row " NR > "/dev/stderr"
		bad = 1
	}
	n++
}
END { if (n == 0) bad = 1; exit bad }
' "$case_ledger" || fail "invalid nested-SVM case ledger; evidence: $attempt"
ledger_count=$(awk 'END { print NR - 1 }' "$case_ledger")
inventory_count=$(awk '/^vmm_run_live_test:svm_[a-z0-9_]+$/ {
    n++ } END { print n + 0 }' "$inventory")
[ "$ledger_count" -eq "$inventory_count" ] ||
    fail "nested-SVM case ledger does not cover installed inventory; evidence: $attempt"
set --
tab=$(printf '\t')
while IFS="$tab" read -r test_case feature; do
	[ "$test_case" = case_id ] && continue
	grep -qx "$test_case" "$inventory" ||
	    fail "ledger case missing from installed binary: $test_case; evidence: $attempt"
	if [ "$POLICY_ONLY" -eq 1 ]; then
		[ "$feature" = policy ] || continue
	elif [ "$feature" = virtual-nmi ] &&
	    [ $((features & 33554432)) -eq 0 ]; then
		printf '%s\n' "$test_case" >> "$attempt/optional-pending.txt"
		continue
	fi
	set -- "$@" "$test_case"
done < "$case_ledger"
[ "$#" -gt 0 ] || fail "no nested-SVM live cases in Kyuafile"
for test_case do
	printf '%s\n' "$test_case" >> "$attempt/selected.txt"
done
if [ "$POLICY_ONLY" -eq 0 ]; then
	grep -qx vmm_run_live_test:svm_l2_npt12_readonly_alias \
	    "$attempt/selected.txt" ||
	    fail "read-only alias case is missing; evidence: $attempt"
	grep -qx vmm_run_live_test:svm_l2_checkpoint \
	    "$attempt/selected.txt" ||
	    fail "active-L2 checkpoint case is missing; evidence: $attempt"
fi

kernel_hash=$(sha256 -q "$kernel_path") ||
    fail "cannot hash kernel; evidence: $attempt"
module_hash=$(sha256 -q "$module_path") ||
    fail "cannot hash module; evidence: $attempt"
test_hash=$(sha256 -q "$test_binary") ||
    fail "cannot hash live test binary; evidence: $attempt"
kyuafile_hash=$(sha256 -q "$kyuafile_path") ||
    fail "cannot hash Kyuafile; evidence: $attempt"
ledger_hash=$(sha256 -q "$case_ledger") ||
    fail "cannot hash case ledger; evidence: $attempt"
{
	printf 'policy_only=%s\n' "$POLICY_ONLY"
	printf 'nested=%s\nfeatures=%s\n' "$nested" "$features"
	printf 'kernel_build_id=%s\n' "$running_id"
	printf 'kernel=%s sha256=%s\n' "$kernel_path" "$kernel_hash"
	printf 'module=%s sha256=%s\n' "$module_path" "$module_hash"
	printf 'test=%s sha256=%s\n' "$test_binary" "$test_hash"
	printf 'kyuafile=%s sha256=%s\n' "$kyuafile_path" \
	    "$kyuafile_hash"
	printf 'case_ledger=%s sha256=%s\n' "$case_ledger" "$ledger_hash"
} > "$attempt/host.txt"
test_status=0
kyua test -k "$kyuafile_path" -r "$attempt/results.db" "$@" \
    > "$attempt/test.log" 2>&1 || test_status=$?
kyua report -r "$attempt/results.db" > "$attempt/report.txt" ||
    fail "cannot read Kyua report; evidence: $attempt"
cat "$attempt/report.txt"
[ "$test_status" -eq 0 ] ||
    fail "nested-SVM live tests failed; evidence: $attempt"
grep -Eq "Test cases: $# total, 0 skipped, 0 expected failures, 0 broken, 0 failed" \
    "$attempt/report.txt" ||
    fail "selected cases did not all pass; evidence: $attempt"
[ "$(sha256 -q "$kernel_path")" = "$kernel_hash" ] &&
    [ "$(sha256 -q "$module_path")" = "$module_hash" ] &&
    [ "$(sha256 -q "$test_binary")" = "$test_hash" ] &&
    [ "$(sha256 -q "$kyuafile_path")" = "$kyuafile_hash" ] &&
    [ "$(sha256 -q "$case_ledger")" = "$ledger_hash" ] ||
    fail "qualification input changed during test; evidence: $attempt"
[ "$(sysctl -n kern.build_id)" = "$running_id" ] &&
    kldstat -v | grep -F "vmm.ko ($module_path)" >/dev/null ||
    fail "running kernel or module changed during test; evidence: $attempt"
for node in /dev/vmm/*; do
	[ "$node" = /dev/vmm/ctl ] && continue
	[ ! -c "$node" ] || fail "live test leaked VM: $node; evidence: $attempt"
done
echo "nested-SVM ATF passed; evidence: $attempt"
