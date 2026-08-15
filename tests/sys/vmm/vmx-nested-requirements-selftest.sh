#!/bin/sh

set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
src=${SRCTOP:-/usr/src}
validator=$here/validate-vmx-nested-requirements.sh
max_cases=${VMX_NESTED_REQUIREMENTS_SELFTEST_MAX_CASES:-0}
completed_cases=0

case "$max_cases" in
''|*[!0-9]*)
	echo "VMX_NESTED_REQUIREMENTS_SELFTEST_MAX_CASES must be a non-negative integer" >&2
	exit 2
	;;
esac

work=$(mktemp -d /tmp/nested-vmx-requirements.XXXXXX)
bad_vmx=$work/vmx.c
bad_vmx_extra_call=$work/vmx-extra-call.c
bad_bitmap_vmx=$work/vmx-bitmap-host-page.c
bad_model=$work/run-vmx-nested-model.sh
bad_completion_order_model=$work/run-vmx-nested-model-late-completion.sh
bad_result_start_model=$work/run-vmx-nested-model-no-result-start.sh
bad_result_configuration_model=$work/run-vmx-nested-model-late-result-start.sh
configuration_result=$work/nested-model-configuration.result
bad_sanitizer_model=$work/run-vmx-nested-model-no-snapshot.sh
bad_coverage_model=$work/run-vmx-nested-model-no-live-coverage.sh
bad_header_model=$work/run-vmx-nested-model-no-public-headers.sh
bad_atf_result_model=$work/run-vmx-nested-model-no-atf-result-check.sh
bad_atf_discovery_model=$work/run-vmx-nested-model-no-atf-discovery-check.sh
bad_atf_cleanup_model=$work/run-vmx-nested-model-no-atf-cleanup.sh
bad_vmfree_model=$work/run-vmx-nested-model-implicit-live.sh
bad_live_runner=$work/run-vmx-nested-live-ambient-env.sh
bad_live_foreground_runner=$work/run-vmx-nested-live-foreground.sh
bad_live_discovery_runner=$work/run-vmx-nested-live-no-atf-discovery.sh

case_passed()
{
	echo "nested-vmx requirements selftest: $1 passed"
	completed_cases=$((completed_cases + 1))
	if [ "$max_cases" -ne 0 ] && [ "$completed_cases" -ge "$max_cases" ]; then
		echo "PASS nested-vmx requirements validator partial cases=$completed_cases"
		exit 0
	fi
}

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

if [ ! -r "$src/sys/amd64/vmm/intel/vmx.c" ] || [ ! -f "$validator" ]; then
	echo "nested-vmx requirements selftest: source or validator unavailable" >&2
	exit 1
fi

cp "$src/sys/amd64/vmm/intel/vmx.c" "$bad_vmx"

# Move the private action publication before its inverse operation.  The
# fixture remains valid C; the requirement validator must reject the unsafe
# source ordering rather than depending on a compiler diagnostic.
awk '
/^\tswitch \(action\) \{/ && !inserted {
	print "\tif (actionp != NULL)"
	print "\t\t*actionp = action;"
	inserted = 1
}
/^\tif \(actionp != NULL\)$/ {
	print
	if (getline > 0) {
		if ($0 == "\t\t*actionp = action;") {
			print "\t\t(void)actionp;"
			replaced = 1
			next
		}
		print
	}
	next
}
{ print }
END {
	if (!inserted || !replaced)
		exit 1
}
' "$src/sys/amd64/vmm/intel/vmx.c" > "$bad_vmx"

echo "nested-vmx requirements selftest: unsafe unwind publication"
set +e
env SRCTOP="$src" VMX_NESTED_VMX_SOURCE="$bad_vmx" \
    sh "$validator" >"$work/unsafe-order.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: unsafe unwind publication accepted" >&2
	exit 1
fi
grep -q 'nested unwind action is not selected and published only after cleanup' \
    "$work/unsafe-order.out"
case_passed "unsafe unwind publication"

# The final exposure-policy check only proves the safety of one known route.
# Add an otherwise unreachable but valid second call to the static nested run
# helper; the validator must reject a future bypass before hardware entry can
# be accidentally made reachable by a stage-mask change.
awk '
/^\t\treturn \(vmx_run_nested\(vcpu, rip, pmap, evinfo,/ && !inserted {
	print
	if (getline <= 0)
		exit 1
	print
	print "\t\tif (false)"
	print "\t\t\treturn (vmx_run_nested(vcpu, rip, pmap, evinfo,"
	print "\t\t\t    nested_target, entry_owner));"
	inserted = 1
	next
}
{ print }
END { if (!inserted) exit 1 }
' "$src/sys/amd64/vmm/intel/vmx.c" > "$bad_vmx_extra_call"
echo "nested-vmx requirements selftest: nested execution single-caller fence"
set +e
env SRCTOP="$src" VMX_NESTED_VMX_SOURCE="$bad_vmx_extra_call" \
    sh "$validator" >"$work/extra-nested-call.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: additional nested execution route accepted" >&2
	exit 1
fi
grep -q 'nested VMX execution helper has an unexpected source reference count' \
    "$work/extra-nested-call.out"
case_passed "nested execution single-caller fence"

# VMX bitmap pages have an architectural size.  Reintroduce host PAGE_SIZE
# for every MSR staging allocation and clear in an otherwise valid temporary
# VMX source; the source validator must reject that portability regression.
sed 's/VMX_NESTED_MSR_BITMAP_SIZE/PAGE_SIZE/g' \
    "$src/sys/amd64/vmm/intel/vmx.c" > "$bad_bitmap_vmx"
echo "nested-vmx requirements selftest: architectural bitmap size"
set +e
env SRCTOP="$src" VMX_NESTED_VMX_SOURCE="$bad_bitmap_vmx" \
    sh "$validator" >"$work/bitmap-host-page.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: host-sized bitmap staging accepted" >&2
	exit 1
fi
grep -q 'nested MSR bitmap staging depends on host PAGE_SIZE' \
    "$work/bitmap-host-page.out"
case_passed "architectural bitmap size"

# A rootless run cannot execute the two installed-kernel liveness tests, but
# it must still compile them against the same private libvmmapi object tree.
# Remove one target from a temporary runner and require the source validator
# to reject the coverage loss rather than relying on a later privileged run.
sed 's/vmm_snapshot_session_live_test/vmm_snapshot_session_live_omitted_test/g' \
    "$src/tests/sys/vmm/run-vmx-nested-model.sh" > "$bad_model"
echo "nested-vmx requirements selftest: required live-ABI build coverage"
set +e
env SRCTOP="$src" VMX_NESTED_MODEL_RUNNER="$bad_model" \
    sh "$validator" >"$work/missing-live-build.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: live ABI build omission accepted" >&2
	exit 1
fi
grep -q \
    'rootless nested model omits required ABI or snapshot coverage: vmm_snapshot_session_live_test' \
    "$work/missing-live-build.out"
case_passed "required live-ABI build coverage"

# A root-launched VM-free profile must not acquire VM_CREATE/VM_ACTIVATE work
# merely because /dev/vmm exists.  Delete the explicit opt-in token in a
# temporary runner and require the validator to reject that scope expansion.
sed 's/VMX_NESTED_MODEL_LIVE_ATF:-no/VMX_NESTED_MODEL_LIVE_ATF_IMPLICIT:-no/g' \
    "$src/tests/sys/vmm/run-vmx-nested-model.sh" > "$bad_vmfree_model"
echo "nested-vmx requirements selftest: VM-free live-test opt-in"
set +e
env SRCTOP="$src" VMX_NESTED_MODEL_RUNNER="$bad_vmfree_model" \
    sh "$validator" >"$work/implicit-live-model.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: implicit live model accepted" >&2
	exit 1
fi
grep -q 'rootless nested model may run live VMM tests without an explicit opt-in' \
    "$work/implicit-live-model.out"
case_passed "VM-free live-test opt-in"

# RESULT_FILE is the detached executor's terminal contract.  Move its one
# durable PASS record after cosmetic stdout in a source-only mutation; the
# requirements validator must reject that ordering even though the text still
# contains both forms of PASS output.
sed "/printf 'PASS nested-vmx cases=%s workdir=%s/d" \
    "$src/tests/sys/vmm/run-vmx-nested-model.sh" \
    > "$bad_completion_order_model"
printf "\nprintf 'PASS nested-vmx cases=%%s workdir=%%s\\n'\n" \
    >> "$bad_completion_order_model"
echo "nested-vmx requirements selftest: durable completion ordering"
set +e
env SRCTOP="$src" VMX_NESTED_MODEL_RUNNER="$bad_completion_order_model" \
    sh "$validator" >"$work/late-completion.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: late durable completion accepted" >&2
	exit 1
fi
grep -q 'rootless durable aggregate PASS follows cosmetic stdout PASS' \
    "$work/late-completion.out"
case_passed "durable completion ordering"

# The terminal PASS ordering guard is not sufficient on its own: detached
# callers need an atomic nonterminal record that names the active worker.
# Remove exactly that publication and require the source validator to reject
# the otherwise unchanged model runner.
sed "/printf 'RUNNING nested-vmx pid=%s workdir=%s phase=%s/d" \
    "$src/tests/sys/vmm/run-vmx-nested-model.sh" > "$bad_result_start_model"
echo "nested-vmx requirements selftest: durable RUNNING record"
set +e
env SRCTOP="$src" VMX_NESTED_MODEL_RUNNER="$bad_result_start_model" \
    sh "$validator" >"$work/missing-result-start.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: missing RUNNING record accepted" >&2
	exit 1
fi
grep -Fq 'rootless model RESULT_FILE contract is missing: printf '\''RUNNING nested-vmx pid=%s workdir=%s phase=%s\n'\'' "$$"' \
    "$work/missing-result-start.out"
case_passed "durable RUNNING record"

# Exercise the runner rather than relying exclusively on source inspection:
# an invalid deprecated option must still leave the detached supervisor a
# terminal record, and must preserve the documented exit status.  This path
# exits before any object-tree build so it remains a cheap, rootless check.
rm -f "$configuration_result"
echo "nested-vmx requirements selftest: configuration failure result record"
set +e
RESULT_FILE="$configuration_result" SANITIZE=1 \
    sh "$src/tests/sys/vmm/run-vmx-nested-model.sh" \
    >"$work/configuration-result.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || {
	echo "nested-vmx requirements selftest: configuration failure exit was $status" >&2
	exit 1
}
grep -q '^FAIL nested-vmx exit=2 workdir=none$' "$configuration_result"
grep -q 'use SANITIZERS, not SANITIZE' "$work/configuration-result.out"
case_passed "configuration failure result record"

# Configuration failures are terminal model failures too.  Moving the state
# transition behind option validation would again make a detached executor
# infer failure from silence, so make the structural ordering non-regressible.
sed '/^[[:space:]]*result_started=1$/d' \
    "$src/tests/sys/vmm/run-vmx-nested-model.sh" \
    > "$bad_result_configuration_model"
printf '\nresult_started=1\n' >> "$bad_result_configuration_model"
echo "nested-vmx requirements selftest: durable configuration failure"
set +e
env SRCTOP="$src" VMX_NESTED_MODEL_RUNNER="$bad_result_configuration_model" \
    sh "$validator" >"$work/late-result-start.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: early configuration failure accepted" >&2
	exit 1
fi
grep -q 'rootless model validates build jobs before RESULT_FILE is live' \
    "$work/late-result-start.out"
case_passed "durable configuration failure"

# The sanitizer path must build the private libvmmapi archive with the
# snapshot ABI enabled.  Removing this define leaves an ABI-incomplete
# library even though the surrounding model binaries still carry sanitizer
# flags; the source validator must reject that weaker build.
sed '/CFLAGS+=-DWITH_VMMAPI_SNAPSHOT/d' \
    "$src/tests/sys/vmm/run-vmx-nested-model.sh" > "$bad_sanitizer_model"
echo "nested-vmx requirements selftest: sanitized snapshot ABI build"
set +e
env SRCTOP="$src" VMX_NESTED_MODEL_RUNNER="$bad_sanitizer_model" \
    sh "$validator" >"$work/missing-sanitizer-library.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: sanitizer library omission accepted" >&2
	exit 1
fi
grep -q \
    'sanitized libvmmapi build omits required contract: CFLAGS+=-DWITH_VMMAPI_SNAPSHOT' \
    "$work/missing-sanitizer-library.out"
case_passed "sanitized snapshot ABI build"

# The aggregate rootless result is only meaningful when it also runs the
# evidence-to-qualification coverage validator.  Removing the invocation must
# be caught by the requirements validator instead of waiting for a privileged
# evidence import to expose the gap.
sed 's/^"\$live_coverage_selftest"$/:/' \
    "$src/tests/sys/vmm/run-vmx-nested-model.sh" > "$bad_coverage_model"
echo "nested-vmx requirements selftest: live-evidence coverage invocation"
set +e
env SRCTOP="$src" VMX_NESTED_MODEL_RUNNER="$bad_coverage_model" \
    sh "$validator" >"$work/missing-live-coverage.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: live-coverage selftest omission accepted" >&2
	exit 1
fi
grep -q \
    'rootless model no longer executes the live-coverage validator selftest' \
    "$work/missing-live-coverage.out"
case_passed "live-evidence coverage invocation"

# Every public nested header is a model ABI boundary.  The rootless aggregate
# must run the standalone-header compiler gate rather than relying on the
# broader include closure of the main state test.
sed 's/^env SRCTOP="\$src" "\$public_header_validator"$/:/' \
    "$src/tests/sys/vmm/run-vmx-nested-model.sh" > "$bad_header_model"
echo "nested-vmx requirements selftest: public-header validation invocation"
set +e
env SRCTOP="$src" VMX_NESTED_MODEL_RUNNER="$bad_header_model" \
    sh "$validator" >"$work/missing-public-headers.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: public-header validation omitted" >&2
	exit 1
fi
grep -q 'rootless model no longer executes the public-header validator' \
    "$work/missing-public-headers.out"
case_passed "public-header validation invocation"

# The ATF test-program exit status only reports whether the protocol was
# handled.  A body-level failure is represented by its result record, so the
# rootless aggregate must reject a runner that stops checking for `passed`.
sed 's/tail -n 1 "\$case_log" | grep -qx passed/: # result check removed/' \
    "$src/tests/sys/vmm/run-vmx-nested-model.sh" > "$bad_atf_result_model"
echo "nested-vmx requirements selftest: ATF result-record enforcement"
set +e
env SRCTOP="$src" VMX_NESTED_MODEL_RUNNER="$bad_atf_result_model" \
    sh "$validator" >"$work/missing-atf-result-check.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: ATF result check omission accepted" >&2
	exit 1
fi
grep -q \
    'rootless nested model omits required ABI or snapshot coverage: tail -n 1 "\$case_log" | grep -qx passed' \
    "$work/missing-atf-result-check.out"
case_passed "ATF result-record enforcement"

# Listing failures are distinct from failed test bodies: POSIX pipeline status
# would otherwise be supplied by awk, not the test binary.  The aggregate
# runner must retain the direct listing check for every ATF program.
sed 's/"\$program" -l >"\$case_log" 2>\&1/: # discovery check removed/' \
    "$src/tests/sys/vmm/run-vmx-nested-model.sh" > "$bad_atf_discovery_model"
echo "nested-vmx requirements selftest: ATF case-discovery enforcement"
set +e
env SRCTOP="$src" VMX_NESTED_MODEL_RUNNER="$bad_atf_discovery_model" \
    sh "$validator" >"$work/missing-atf-discovery-check.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: case discovery omission accepted" >&2
	exit 1
fi
grep -q \
    'rootless nested model omits required ABI or snapshot coverage: "\$program" -l >"\$case_log" 2>&1' \
    "$work/missing-atf-discovery-check.out"
case_passed "ATF case-discovery enforcement"

# A failing later ATF group must clean up the shared captured-output file.  A
# runner that only had a first-group cleanup trap leaks an unbounded number of
# diagnostics in repeated qualification runs.
sed 's/rm -f "\$case_log" 2>\/dev\/null || :/: # case log cleanup removed/' \
    "$src/tests/sys/vmm/run-vmx-nested-model.sh" > "$bad_atf_cleanup_model"
echo "nested-vmx requirements selftest: ATF temporary-output cleanup"
set +e
env SRCTOP="$src" VMX_NESTED_MODEL_RUNNER="$bad_atf_cleanup_model" \
    sh "$validator" >"$work/missing-atf-cleanup.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: case-log cleanup omission accepted" >&2
	exit 1
fi
grep -q \
    'rootless nested model omits required ABI or snapshot coverage: rm -f "\$case_log" 2>/dev/null || :' \
    "$work/missing-atf-cleanup.out"
case_passed "ATF temporary-output cleanup"

# The hardware-only runner crosses a root authority boundary.  Its reviewed
# L1 input must receive an explicit environment rather than the invoking
# user's ambient loader, interpreter, or helper-selection variables.
sed 's/^if env -i \\/if \\/' \
    "$src/tests/sys/vmm/run-vmx-nested-live.sh" > "$bad_live_runner"
chmod +x "$bad_live_runner"
echo "nested-vmx requirements selftest: sanitized live-runner environment"
set +e
env SRCTOP="$src" VMX_NESTED_LIVE_RUNNER="$bad_live_runner" \
    sh "$validator" >"$work/ambient-live-env.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: ambient live-runner environment accepted" >&2
	exit 1
fi
grep -q 'privileged nested live runner trust boundary omits: env -i' \
    "$work/ambient-live-env.out"
case_passed "sanitized live-runner environment"

# timeout(1) normally supervises the reviewed L1 runner's descendants.  The
# foreground option changes that contract and can leave a bhyve child behind
# after a qualification timeout, so the source gate must reject it.
sed 's/timeout -k 30/timeout -f -k 30/' \
    "$src/tests/sys/vmm/run-vmx-nested-live.sh" > "$bad_live_foreground_runner"
chmod +x "$bad_live_foreground_runner"
echo "nested-vmx requirements selftest: descendant timeout supervision"
set +e
env SRCTOP="$src" VMX_NESTED_LIVE_RUNNER="$bad_live_foreground_runner" \
    sh "$validator" >"$work/foreground-live-runner.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: foreground timeout accepted" >&2
	exit 1
fi
grep -q 'privileged nested live runner must not use timeout foreground mode' \
    "$work/foreground-live-runner.out"
case_passed "descendant timeout supervision"

# Preflight test discovery runs with root authority.  Do not let a failed
# test-program listing be hidden by the status of its downstream parser.
sed 's/if ! "\$test_program" -l >"\$case_log" 2>\&1; then/: # discovery check removed/' \
    "$src/tests/sys/vmm/run-vmx-nested-live.sh" > "$bad_live_discovery_runner"
chmod +x "$bad_live_discovery_runner"
echo "nested-vmx requirements selftest: live ATF case-discovery enforcement"
set +e
env SRCTOP="$src" VMX_NESTED_LIVE_RUNNER="$bad_live_discovery_runner" \
    sh "$validator" >"$work/missing-live-atf-discovery.out" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
	echo "nested-vmx requirements selftest: live case discovery omission accepted" >&2
	exit 1
fi
grep -q \
    'privileged nested live runner trust boundary omits: if ! "\$test_program" -l >"\$case_log" 2>&1; then' \
    "$work/missing-live-atf-discovery.out"
case_passed "live ATF case-discovery enforcement"

echo "PASS nested-vmx requirements validator"
