#!/bin/sh
#
# Run every rootless nested-VMX architectural model case.  Source-tree runs
# use a private object tree by default so installed tests and another caller's
# build do not race on generated interfaces or module artifacts.  A caller may
# explicitly provide MAKEOBJDIRPREFIX when intentional object reuse is wanted.
# VMX_NESTED_BUILD_JOBS selects the positive parallel build width (default 2);
# it changes only compilation parallelism, never the required test inventory.

set -eu

src=${SRCTOP:-/usr/src}
sanitizers=${SANITIZERS:-}
jobs=${VMX_NESTED_BUILD_JOBS:-2}
work=
objprefix=
result_file=${RESULT_FILE:-}
result_started=0
case_log=
phase=initializing

publish_running()
{
	[ -n "$result_file" ] || return 0
	result_tmp="${result_file}.tmp.$$"
	( printf 'RUNNING nested-vmx pid=%s workdir=%s phase=%s\n' "$$" \
	    "${work:-${objprefix:-pending}}" "$phase" \
	    > "$result_tmp" && mv -f "$result_tmp" "$result_file" ) || {
		echo "nested-vmx model: cannot update RESULT_FILE $result_file" >&2
		return 1
	}
	return 0
}

# RESULT_FILE is consumed by detached orchestration.  Keep its update atomic,
# but also identify the currently bounded operation: a private kernel build
# and a mutation self-test can otherwise both look like an unexplained long
# running model.  Phase names are diagnostics only; they do not participate
# in pass/fail semantics or alter the test inventory.
set_phase()
{
	phase=$1
	echo "nested-vmx model: phase=$phase" >&2
	publish_running
}

cleanup()
{
	status=${1:-$?}
	trap - EXIT HUP INT TERM
	# Case output is intentionally kept in a single private temporary file.
	# Remove it on *every* exit path, not just after the first ATF group; a
	# later discovery or body failure must not leak a file into /tmp.
	if [ -n "$case_log" ]; then
		rm -f "$case_log" 2>/dev/null || :
	fi
	# Publish non-success atomically so detached supervisors can distinguish a
	# failed model gate from one whose captured stdout has not arrived yet.
	# This is strictly diagnostic: publication failure must not hide the test or
	# build failure that selected this cleanup path.
	if [ -n "$result_file" ] && [ "$result_started" -eq 1 ] &&
	    [ "$status" -ne 0 ]; then
		result_tmp="${result_file}.tmp.$$"
		( printf 'FAIL nested-vmx exit=%s workdir=%s\n' "$status" \
		    "${work:-${objprefix:-none}}" > "$result_tmp" &&
		    mv -f "$result_tmp" "$result_file" ) ||
		    rm -f "$result_tmp" 2>/dev/null || :
	fi
	if [ "${KEEP_WORK:-no}" = yes ]; then
		if [ -n "$work" ]; then
			echo "nested-vmx model: preserving workdir $work" >&2
		fi
	elif [ -n "$work" ] && [ -d "$work" ]; then
		rm -rf "$work"
	fi
	exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

if [ -n "$result_file" ]; then
	publish_running || exit 1
	result_started=1
fi

# Validate caller-controlled configuration only after the RESULT_FILE state
# machine is live.  A detached supervisor that supplied RESULT_FILE must see
# a terminal FAIL record for configuration errors as well as for build and
# test failures; otherwise an early typo is indistinguishable from a worker
# that never started.
case "$jobs" in
''|*[!0-9]*|0)
	echo "nested-vmx model: VMX_NESTED_BUILD_JOBS must be a positive integer" >&2
	exit 2
	;;
esac

if [ -n "${SANITIZE:-}" ]; then
	echo "nested-vmx model: use SANITIZERS, not SANITIZE" >&2
	exit 2
fi

if [ -n "$sanitizers" ]; then
	[ -f "$src/tests/sys/vmm/vmx_nested_state_test.c" ] || {
		echo "nested-vmx model: sanitized build requires SRCTOP" >&2
		exit 1
	}
	work=$(mktemp -d /tmp/vmx-nested-model.XXXXXX)
	objprefix=$work
	set_phase build-libvmmapi-sanitized
	# Several ABI/liveness tests link libvmmapi.  Build that dependency in the
	# same private object tree first; otherwise an old archive can make the
	# focused runner disagree with a clean tests/sys/vmm build.
	env MAKEOBJDIRPREFIX="$work" make -C "$src/lib/libvmmapi" -j"$jobs" \
	    "CFLAGS+=-I$src/lib/libvmmapi" \
	    "CFLAGS+=-I$src/sys" \
	    "CFLAGS+=-I$src/sys/amd64/include" \
	    "CFLAGS+=-DWITH_VMMAPI_SNAPSHOT" \
	    "CFLAGS+=-fsanitize=$sanitizers" \
	    "CFLAGS+=-fno-omit-frame-pointer" \
	    "LDFLAGS+=-fsanitize=$sanitizers"
	set_phase build-model-tests-sanitized
	env MAKEOBJDIRPREFIX="$work" make -C "$src/tests/sys/vmm" -j"$jobs" \
	    vmx_nested_state_test vmm_dirty_log_test vmm_dirty_log_map_test \
	    vmm_dirty_log_owner_test vmm_dirty_log_collector_test \
	    vmm_exception_test \
	    vmm_snapshot_op_test \
	    vmm_snapshot_session_abi_test vmm_snapshot_session_live_test \
	    vmm_startup_staging_live_test vmm_event_ingress_test \
	    vmm_snapshot_envelope_test \
	    vmm_startup_event_test vmm_event_checkpoint_test \
	    vmm_event_state_test \
	    vmm_startup_mode_test vmm_startup_entry_owner_test \
	    vmm_startup_handshake_test \
	    vmm_startup_controller_test vmm_startup_request_test \
	    vmm_startup_run_request_test \
	    vmm_startup_management_abi_test \
	    vmm_event_wait_test \
	    vmm_x86_startup_state_test vmm_x86_startup_transaction_test \
	    vmm_x86_startup_machine_test vmm_x86_startup_vmreg_test \
	    vmm_x86_startup_backend_test vmm_x86_startup_finalizer_test \
	    "CFLAGS+=-I$src/sys" \
	    "CFLAGS+=-I$src/sys/amd64/include" \
	    "CFLAGS+=-I$src/lib/libvmmapi" \
	    "CFLAGS+=-fsanitize=$sanitizers" \
	    "CFLAGS+=-fno-omit-frame-pointer" \
	    "LDFLAGS+=-fsanitize=$sanitizers"
	obj=$(env MAKEOBJDIRPREFIX="$work" make -C "$src/tests/sys/vmm" \
	    -V .OBJDIR)
	test_program=$obj/vmx_nested_state_test
	dirty_log_test_program=$obj/vmm_dirty_log_test
	dirty_log_map_test_program=$obj/vmm_dirty_log_map_test
	dirty_log_owner_test_program=$obj/vmm_dirty_log_owner_test
	dirty_log_collector_test_program=$obj/vmm_dirty_log_collector_test
	exception_test_program=$obj/vmm_exception_test
	snapshot_test_program=$obj/vmm_snapshot_op_test
	snapshot_session_abi_test_program=$obj/vmm_snapshot_session_abi_test
	snapshot_session_live_test_program=$obj/vmm_snapshot_session_live_test
	startup_staging_live_test_program=$obj/vmm_startup_staging_live_test
	envelope_test_program=$obj/vmm_snapshot_envelope_test
	ingress_test_program=$obj/vmm_event_ingress_test
	startup_test_program=$obj/vmm_startup_event_test
	startup_mode_test_program=$obj/vmm_startup_mode_test
	startup_entry_owner_test_program=$obj/vmm_startup_entry_owner_test
	startup_handshake_test_program=$obj/vmm_startup_handshake_test
	startup_controller_test_program=$obj/vmm_startup_controller_test
	startup_request_test_program=$obj/vmm_startup_request_test
	startup_run_request_test_program=$obj/vmm_startup_run_request_test
	startup_management_abi_test_program=$obj/vmm_startup_management_abi_test
	startup_state_test_program=$obj/vmm_x86_startup_state_test
	startup_transaction_test_program=$obj/vmm_x86_startup_transaction_test
	startup_machine_test_program=$obj/vmm_x86_startup_machine_test
	startup_vmreg_test_program=$obj/vmm_x86_startup_vmreg_test
	startup_backend_test_program=$obj/vmm_x86_startup_backend_test
	startup_finalizer_test_program=$obj/vmm_x86_startup_finalizer_test
	checkpoint_test_program=$obj/vmm_event_checkpoint_test
	event_state_test_program=$obj/vmm_event_state_test
	wait_test_program=$obj/vmm_event_wait_test
	: "${ASAN_OPTIONS:=detect_leaks=0:halt_on_error=1:abort_on_error=1}"
	: "${UBSAN_OPTIONS:=halt_on_error=1:abort_on_error=1:print_stacktrace=1}"
	export ASAN_OPTIONS UBSAN_OPTIONS
elif [ -f "$src/tests/sys/vmm/vmx_nested_state_test.c" ]; then
	# A fixed default object tree allows two rootless model invocations to
	# clobber generated interfaces and module artifacts.  Keep an explicitly
	# requested tree for developers who want reuse; otherwise isolate this run
	# exactly as the sanitizer path does.
	if [ -n "${MAKEOBJDIRPREFIX:-}" ]; then
		objprefix=$MAKEOBJDIRPREFIX
	else
		work=$(mktemp -d /tmp/vmx-nested-model.XXXXXX)
		objprefix=$work
	fi
	set_phase build-libvmmapi
	env MAKEOBJDIRPREFIX="$objprefix" \
	    make -C "$src/lib/libvmmapi" -j"$jobs"
	set_phase build-model-tests
	env MAKEOBJDIRPREFIX="$objprefix" \
	    make -C "$src/tests/sys/vmm" -j"$jobs" vmx_nested_state_test vmm_dirty_log_test \
	    vmm_dirty_log_map_test vmm_dirty_log_owner_test \
	    vmm_dirty_log_collector_test \
	    vmm_exception_test vmm_snapshot_op_test vmm_snapshot_session_abi_test \
	    vmm_snapshot_session_live_test vmm_startup_staging_live_test \
	    vmm_event_ingress_test \
	    vmm_snapshot_envelope_test \
	    vmm_startup_event_test vmm_event_checkpoint_test \
	    vmm_event_state_test \
	    vmm_startup_mode_test vmm_startup_entry_owner_test \
	    vmm_startup_handshake_test \
	    vmm_startup_controller_test vmm_startup_request_test \
	    vmm_startup_run_request_test \
	    vmm_startup_management_abi_test \
	    vmm_event_wait_test \
	    vmm_x86_startup_state_test vmm_x86_startup_transaction_test \
	    vmm_x86_startup_machine_test vmm_x86_startup_vmreg_test \
	    vmm_x86_startup_backend_test vmm_x86_startup_finalizer_test
	obj=$(env MAKEOBJDIRPREFIX="$objprefix" \
	    make -C "$src/tests/sys/vmm" -V .OBJDIR)
	test_program=$obj/vmx_nested_state_test
	dirty_log_test_program=$obj/vmm_dirty_log_test
	dirty_log_map_test_program=$obj/vmm_dirty_log_map_test
	dirty_log_owner_test_program=$obj/vmm_dirty_log_owner_test
	dirty_log_collector_test_program=$obj/vmm_dirty_log_collector_test
	exception_test_program=$obj/vmm_exception_test
	snapshot_test_program=$obj/vmm_snapshot_op_test
	snapshot_session_abi_test_program=$obj/vmm_snapshot_session_abi_test
	snapshot_session_live_test_program=$obj/vmm_snapshot_session_live_test
	startup_staging_live_test_program=$obj/vmm_startup_staging_live_test
	envelope_test_program=$obj/vmm_snapshot_envelope_test
	ingress_test_program=$obj/vmm_event_ingress_test
	startup_test_program=$obj/vmm_startup_event_test
	startup_mode_test_program=$obj/vmm_startup_mode_test
	startup_entry_owner_test_program=$obj/vmm_startup_entry_owner_test
	startup_handshake_test_program=$obj/vmm_startup_handshake_test
	startup_controller_test_program=$obj/vmm_startup_controller_test
	startup_request_test_program=$obj/vmm_startup_request_test
	startup_run_request_test_program=$obj/vmm_startup_run_request_test
	startup_management_abi_test_program=$obj/vmm_startup_management_abi_test
	startup_state_test_program=$obj/vmm_x86_startup_state_test
	startup_transaction_test_program=$obj/vmm_x86_startup_transaction_test
	startup_machine_test_program=$obj/vmm_x86_startup_machine_test
	startup_vmreg_test_program=$obj/vmm_x86_startup_vmreg_test
	startup_backend_test_program=$obj/vmm_x86_startup_backend_test
	startup_finalizer_test_program=$obj/vmm_x86_startup_finalizer_test
	checkpoint_test_program=$obj/vmm_event_checkpoint_test
	event_state_test_program=$obj/vmm_event_state_test
	wait_test_program=$obj/vmm_event_wait_test
elif [ -x /usr/tests/sys/vmm/vmx_nested_state_test ]; then
	test_program=/usr/tests/sys/vmm/vmx_nested_state_test
	dirty_log_test_program=/usr/tests/sys/vmm/vmm_dirty_log_test
	dirty_log_map_test_program=/usr/tests/sys/vmm/vmm_dirty_log_map_test
	dirty_log_owner_test_program=/usr/tests/sys/vmm/vmm_dirty_log_owner_test
	dirty_log_collector_test_program=/usr/tests/sys/vmm/vmm_dirty_log_collector_test
	exception_test_program=/usr/tests/sys/vmm/vmm_exception_test
	snapshot_test_program=/usr/tests/sys/vmm/vmm_snapshot_op_test
	snapshot_session_abi_test_program=/usr/tests/sys/vmm/vmm_snapshot_session_abi_test
	snapshot_session_live_test_program=/usr/tests/sys/vmm/vmm_snapshot_session_live_test
	startup_staging_live_test_program=/usr/tests/sys/vmm/vmm_startup_staging_live_test
	envelope_test_program=/usr/tests/sys/vmm/vmm_snapshot_envelope_test
	ingress_test_program=/usr/tests/sys/vmm/vmm_event_ingress_test
	startup_test_program=/usr/tests/sys/vmm/vmm_startup_event_test
	startup_mode_test_program=/usr/tests/sys/vmm/vmm_startup_mode_test
	startup_entry_owner_test_program=/usr/tests/sys/vmm/vmm_startup_entry_owner_test
	startup_handshake_test_program=/usr/tests/sys/vmm/vmm_startup_handshake_test
	startup_controller_test_program=/usr/tests/sys/vmm/vmm_startup_controller_test
	startup_request_test_program=/usr/tests/sys/vmm/vmm_startup_request_test
	startup_run_request_test_program=/usr/tests/sys/vmm/vmm_startup_run_request_test
	startup_management_abi_test_program=/usr/tests/sys/vmm/vmm_startup_management_abi_test
	startup_state_test_program=/usr/tests/sys/vmm/vmm_x86_startup_state_test
	startup_transaction_test_program=/usr/tests/sys/vmm/vmm_x86_startup_transaction_test
	startup_machine_test_program=/usr/tests/sys/vmm/vmm_x86_startup_machine_test
	startup_vmreg_test_program=/usr/tests/sys/vmm/vmm_x86_startup_vmreg_test
	startup_backend_test_program=/usr/tests/sys/vmm/vmm_x86_startup_backend_test
	startup_finalizer_test_program=/usr/tests/sys/vmm/vmm_x86_startup_finalizer_test
	checkpoint_test_program=/usr/tests/sys/vmm/vmm_event_checkpoint_test
	event_state_test_program=/usr/tests/sys/vmm/vmm_event_state_test
	wait_test_program=/usr/tests/sys/vmm/vmm_event_wait_test
else
	echo "nested-vmx model: test is neither installed nor in SRCTOP" >&2
	exit 1
fi

# Installed-test runs have no source-tree build branch to refresh the initial
# status, but still publish a concrete (none) workspace before test discovery.
set_phase discover-tests

[ -x "$test_program" ] || {
	echo "nested-vmx model: missing executable $test_program" >&2
	exit 1
}
[ -x "$dirty_log_test_program" ] || {
	echo "nested-vmx model: missing executable $dirty_log_test_program" >&2
	exit 1
}
[ -x "$dirty_log_map_test_program" ] || {
	echo "nested-vmx model: missing executable $dirty_log_map_test_program" >&2
	exit 1
}
[ -x "$dirty_log_owner_test_program" ] || {
	echo "nested-vmx model: missing executable $dirty_log_owner_test_program" >&2
	exit 1
}
[ -x "$dirty_log_collector_test_program" ] || {
	echo "nested-vmx model: missing executable $dirty_log_collector_test_program" >&2
	exit 1
}
[ -x "$exception_test_program" ] || {
	echo "nested-vmx model: missing executable $exception_test_program" >&2
	exit 1
}
[ -x "$snapshot_test_program" ] || {
	echo "nested-vmx model: missing executable $snapshot_test_program" >&2
	exit 1
}
[ -x "$snapshot_session_abi_test_program" ] || {
	echo "nested-vmx model: missing executable $snapshot_session_abi_test_program" >&2
	exit 1
}
[ -x "$snapshot_session_live_test_program" ] || {
	echo "nested-vmx model: missing executable $snapshot_session_live_test_program" >&2
	exit 1
}
[ -x "$startup_staging_live_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_staging_live_test_program" >&2
	exit 1
}
[ -x "$envelope_test_program" ] || {
	echo "nested-vmx model: missing executable $envelope_test_program" >&2
	exit 1
}
[ -x "$ingress_test_program" ] || {
	echo "nested-vmx model: missing executable $ingress_test_program" >&2
	exit 1
}
[ -x "$startup_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_test_program" >&2
	exit 1
}
[ -x "$startup_mode_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_mode_test_program" >&2
	exit 1
}
[ -x "$startup_entry_owner_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_entry_owner_test_program" >&2
	exit 1
}
[ -x "$startup_handshake_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_handshake_test_program" >&2
	exit 1
}
[ -x "$startup_controller_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_controller_test_program" >&2
	exit 1
}
[ -x "$startup_request_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_request_test_program" >&2
	exit 1
}
[ -x "$startup_run_request_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_run_request_test_program" >&2
	exit 1
}
[ -x "$startup_management_abi_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_management_abi_test_program" >&2
	exit 1
}
[ -x "$startup_state_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_state_test_program" >&2
	exit 1
}
[ -x "$startup_transaction_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_transaction_test_program" >&2
	exit 1
}
[ -x "$startup_machine_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_machine_test_program" >&2
	exit 1
}
[ -x "$startup_vmreg_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_vmreg_test_program" >&2
	exit 1
}
[ -x "$startup_backend_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_backend_test_program" >&2
	exit 1
}
[ -x "$startup_finalizer_test_program" ] || {
	echo "nested-vmx model: missing executable $startup_finalizer_test_program" >&2
	exit 1
}
[ -x "$checkpoint_test_program" ] || {
	echo "nested-vmx model: missing executable $checkpoint_test_program" >&2
	exit 1
}
[ -x "$event_state_test_program" ] || {
	echo "nested-vmx model: missing executable $event_state_test_program" >&2
	exit 1
}
[ -x "$wait_test_program" ] || {
	echo "nested-vmx model: missing executable $wait_test_program" >&2
	exit 1
}

case_log=$(mktemp /tmp/vmx-nested-model-case.XXXXXX)

# Do not use a discovery pipeline here.  POSIX sh reports the status of the
# final awk stage, which could turn a crashed test program into a misleading
# empty (or partial) test list.  Capture and validate the program's listing
# before deriving any cases from it.
list_atf_cases()
{
	program=$1
	label=$2

	if ! "$program" -l >"$case_log" 2>&1; then
		echo "FAIL $label case discovery" >&2
		cat "$case_log" >&2
		return 1
	fi
	awk '$1 == "ident:" { print $2 }' "$case_log"
}

set_phase run-architectural-atf
echo "nested-vmx model: running architectural and lifecycle ATF cases"
cases=$(list_atf_cases "$test_program" nested-vmx)
[ -n "$cases" ] || {
	echo "nested-vmx model: no ATF cases found" >&2
	exit 1
}

# A direct ATF invocation reports the test result in its result stream.  Do
# not use its process status alone as proof of success: a test body can report
# a failed result while the test-program protocol itself was handled correctly.
run_atf_case()
{
	program=$1
	test_case=$2
	label=$3

	if ! "$program" -r /dev/stdout "$test_case" >"$case_log" 2>&1 ||
	    ! tail -n 1 "$case_log" | grep -qx passed; then
		echo "FAIL $label $test_case" >&2
		cat "$case_log" >&2
		exit 1
	fi
}

count=0
for test_case in $cases; do
	run_atf_case "$test_program" "$test_case" nested-vmx
	count=$((count + 1))
done
rm -f "$case_log"

set_phase run-dirty-log-atf
dirty_log_cases=$(list_atf_cases "$dirty_log_test_program" dirty-log)
[ -n "$dirty_log_cases" ] || {
	echo "nested-vmx model: no dirty-log cases found" >&2
	exit 1
}
for test_case in $dirty_log_cases; do
	run_atf_case "$dirty_log_test_program" "$test_case" dirty-log
	count=$((count + 1))
done
rm -f "$case_log"

dirty_log_map_cases=$(list_atf_cases "$dirty_log_map_test_program" dirty-log-map)
[ -n "$dirty_log_map_cases" ] || {
	echo "nested-vmx model: no dirty-log-map cases found" >&2
	exit 1
}
for test_case in $dirty_log_map_cases; do
	run_atf_case "$dirty_log_map_test_program" "$test_case" dirty-log-map
	count=$((count + 1))
done
rm -f "$case_log"

dirty_log_owner_cases=$(list_atf_cases "$dirty_log_owner_test_program" dirty-log-owner)
[ -n "$dirty_log_owner_cases" ] || {
	echo "nested-vmx model: no dirty-log-owner cases found" >&2
	exit 1
}
for test_case in $dirty_log_owner_cases; do
	run_atf_case "$dirty_log_owner_test_program" "$test_case" dirty-log-owner
	count=$((count + 1))
done
rm -f "$case_log"

dirty_log_collector_cases=$(list_atf_cases "$dirty_log_collector_test_program" dirty-log-collector)
[ -n "$dirty_log_collector_cases" ] || {
	echo "nested-vmx model: no dirty-log-collector cases found" >&2
	exit 1
}
for test_case in $dirty_log_collector_cases; do
	run_atf_case "$dirty_log_collector_test_program" "$test_case" dirty-log-collector
	count=$((count + 1))
done
rm -f "$case_log"

set_phase run-exception-and-snapshot-atf
exception_cases=$(list_atf_cases "$exception_test_program" exception-model)
[ -n "$exception_cases" ] || {
	echo "nested-vmx model: no exception-model cases found" >&2
	exit 1
}
for test_case in $exception_cases; do
	run_atf_case "$exception_test_program" "$test_case" exception-model
	count=$((count + 1))
done
rm -f "$case_log"

run_atf_case "$snapshot_test_program" kernel_snapshot_operation_boundary nested-vmx
rm -f "$case_log"
count=$((count + 1))

snapshot_session_abi_cases=$(list_atf_cases "$snapshot_session_abi_test_program" snapshot-session-abi)
[ -n "$snapshot_session_abi_cases" ] || {
	echo "nested-vmx model: no snapshot-session ABI cases found" >&2
	exit 1
}
for test_case in $snapshot_session_abi_cases; do
	run_atf_case "$snapshot_session_abi_test_program" "$test_case" snapshot-session-abi
	count=$((count + 1))
done
rm -f "$case_log"

# This program performs real VM_CREATE/VM_ACTIVATE operations.  Its ATF
# metadata correctly requires root, but direct ATF invocation does not enforce
# that metadata.  This runner is a VM-free source/model gate even when a
# developer launches it as root on a host which happens to expose /dev/vmm;
# silently changing its scope would make its case count and safety properties
# depend on the caller's machine.  The reviewed privileged live wrapper owns
# normal liveness qualification.  Keep an explicit diagnostic opt-in for a
# developer who is deliberately investigating this runner in that environment.
if [ "${VMX_NESTED_MODEL_LIVE_ATF:-no}" = yes ] && [ "$(id -u)" -eq 0 ] &&
    [ -c /dev/vmm ]; then
snapshot_session_live_cases=$(list_atf_cases "$snapshot_session_live_test_program" snapshot-session-live)
	[ -n "$snapshot_session_live_cases" ] || {
		echo "nested-vmx model: no live snapshot-session cases found" >&2
		exit 1
	}
	for test_case in $snapshot_session_live_cases; do
		run_atf_case "$snapshot_session_live_test_program" "$test_case" \
		    snapshot-session-live
		count=$((count + 1))
	done
	rm -f "$case_log"
startup_staging_live_cases=$(list_atf_cases "$startup_staging_live_test_program" startup-staging-live)
	[ -n "$startup_staging_live_cases" ] || {
		echo "nested-vmx model: no live startup-staging cases found" >&2
		exit 1
	}
	for test_case in $startup_staging_live_cases; do
		run_atf_case "$startup_staging_live_test_program" "$test_case" \
		    startup-staging-live
		count=$((count + 1))
	done
	rm -f "$case_log"
else
	echo "nested-vmx model: SKIP live snapshot-session and startup-staging cases (set VMX_NESTED_MODEL_LIVE_ATF=yes as root with /dev/vmm)"
fi

set_phase run-startup-and-event-atf
envelope_cases=$(list_atf_cases "$envelope_test_program" snapshot-envelope)
[ -n "$envelope_cases" ] || {
	echo "nested-vmx model: no snapshot-envelope cases found" >&2
	exit 1
}
for test_case in $envelope_cases; do
	run_atf_case "$envelope_test_program" "$test_case" snapshot-envelope
	count=$((count + 1))
done
rm -f "$case_log"

ingress_cases=$(list_atf_cases "$ingress_test_program" event-ingress)
[ -n "$ingress_cases" ] || {
	echo "nested-vmx model: no event-ingress cases found" >&2
	exit 1
}
for test_case in $ingress_cases; do
	run_atf_case "$ingress_test_program" "$test_case" event-ingress
	count=$((count + 1))
done
rm -f "$case_log"

startup_cases=$(list_atf_cases "$startup_test_program" startup-event)
[ -n "$startup_cases" ] || {
	echo "nested-vmx model: no startup-event cases found" >&2
	exit 1
}
for test_case in $startup_cases; do
	run_atf_case "$startup_test_program" "$test_case" startup-event
	count=$((count + 1))
done
rm -f "$case_log"

startup_state_cases=$(list_atf_cases "$startup_state_test_program" x86-startup-state)
[ -n "$startup_state_cases" ] || {
	echo "nested-vmx model: no x86 startup-state cases found" >&2
	exit 1
}
for test_case in $startup_state_cases; do
	run_atf_case "$startup_state_test_program" "$test_case" x86-startup-state
	count=$((count + 1))
done
rm -f "$case_log"

startup_transaction_cases=$(list_atf_cases "$startup_transaction_test_program" x86-startup-transaction)
[ -n "$startup_transaction_cases" ] || {
	echo "nested-vmx model: no x86 startup-transaction cases found" >&2
	exit 1
}
for test_case in $startup_transaction_cases; do
	run_atf_case "$startup_transaction_test_program" "$test_case" x86-startup-transaction
	count=$((count + 1))
done
rm -f "$case_log"

startup_machine_cases=$(list_atf_cases "$startup_machine_test_program" x86-startup-machine)
[ -n "$startup_machine_cases" ] || {
	echo "nested-vmx model: no x86 startup-machine cases found" >&2
	exit 1
}
for test_case in $startup_machine_cases; do
	run_atf_case "$startup_machine_test_program" "$test_case" x86-startup-machine
	count=$((count + 1))
done
rm -f "$case_log"

startup_vmreg_cases=$(list_atf_cases "$startup_vmreg_test_program" x86-startup-vmreg)
[ -n "$startup_vmreg_cases" ] || {
	echo "nested-vmx model: no x86 startup-vmreg cases found" >&2
	exit 1
}
for test_case in $startup_vmreg_cases; do
	run_atf_case "$startup_vmreg_test_program" "$test_case" x86-startup-vmreg
	count=$((count + 1))
done
rm -f "$case_log"

startup_backend_cases=$(list_atf_cases "$startup_backend_test_program" x86-startup-backend)
[ -n "$startup_backend_cases" ] || {
	echo "nested-vmx model: no x86 startup-backend cases found" >&2
	exit 1
}
for test_case in $startup_backend_cases; do
	run_atf_case "$startup_backend_test_program" "$test_case" x86-startup-backend
	count=$((count + 1))
done
rm -f "$case_log"

startup_finalizer_cases=$(list_atf_cases "$startup_finalizer_test_program" x86-startup-finalizer)
[ -n "$startup_finalizer_cases" ] || {
	echo "nested-vmx model: no x86 startup-finalizer cases found" >&2
	exit 1
}
for test_case in $startup_finalizer_cases; do
	run_atf_case "$startup_finalizer_test_program" "$test_case" x86-startup-finalizer
	count=$((count + 1))
done
rm -f "$case_log"

startup_mode_cases=$(list_atf_cases "$startup_mode_test_program" startup-mode)
[ -n "$startup_mode_cases" ] || {
	echo "nested-vmx model: no startup-mode cases found" >&2
	exit 1
}
for test_case in $startup_mode_cases; do
	run_atf_case "$startup_mode_test_program" "$test_case" startup-mode
	count=$((count + 1))
done
rm -f "$case_log"

startup_entry_owner_cases=$(list_atf_cases "$startup_entry_owner_test_program" startup-entry-owner)
[ -n "$startup_entry_owner_cases" ] || {
	echo "nested-vmx model: no startup-entry-owner cases found" >&2
	exit 1
}
for test_case in $startup_entry_owner_cases; do
	run_atf_case "$startup_entry_owner_test_program" "$test_case" startup-entry-owner
	count=$((count + 1))
done
rm -f "$case_log"

startup_handshake_cases=$(list_atf_cases "$startup_handshake_test_program" startup-handshake)
[ -n "$startup_handshake_cases" ] || {
	echo "nested-vmx model: no startup-handshake cases found" >&2
	exit 1
}
for test_case in $startup_handshake_cases; do
	run_atf_case "$startup_handshake_test_program" "$test_case" startup-handshake
	count=$((count + 1))
done
rm -f "$case_log"

checkpoint_cases=$(list_atf_cases "$checkpoint_test_program" event-checkpoint)
[ -n "$checkpoint_cases" ] || {
	echo "nested-vmx model: no event-checkpoint cases found" >&2
	exit 1
}
for test_case in $checkpoint_cases; do
	run_atf_case "$checkpoint_test_program" "$test_case" event-checkpoint
	count=$((count + 1))
done
rm -f "$case_log"

event_state_cases=$(list_atf_cases "$event_state_test_program" event-state)
[ -n "$event_state_cases" ] || {
	echo "nested-vmx model: no event-state cases found" >&2
	exit 1
}
for test_case in $event_state_cases; do
	run_atf_case "$event_state_test_program" "$test_case" event-state
	count=$((count + 1))
done
rm -f "$case_log"

startup_controller_cases=$(list_atf_cases "$startup_controller_test_program" startup-controller)
[ -n "$startup_controller_cases" ] || {
	echo "nested-vmx model: no startup-controller cases found" >&2
	exit 1
}
for test_case in $startup_controller_cases; do
	run_atf_case "$startup_controller_test_program" "$test_case" startup-controller
	count=$((count + 1))
done
rm -f "$case_log"

startup_request_cases=$(list_atf_cases "$startup_request_test_program" startup-request)
[ -n "$startup_request_cases" ] || {
	echo "nested-vmx model: no startup-request cases found" >&2
	exit 1
}
for test_case in $startup_request_cases; do
	run_atf_case "$startup_request_test_program" "$test_case" startup-request
	count=$((count + 1))
done
rm -f "$case_log"

startup_run_request_cases=$(list_atf_cases "$startup_run_request_test_program" startup-run-request)
[ -n "$startup_run_request_cases" ] || {
	echo "nested-vmx model: no startup-run-request cases found" >&2
	exit 1
}
for test_case in $startup_run_request_cases; do
	run_atf_case "$startup_run_request_test_program" "$test_case" startup-run-request
	count=$((count + 1))
done
rm -f "$case_log"

startup_management_abi_cases=$(list_atf_cases "$startup_management_abi_test_program" startup-management-abi)
[ -n "$startup_management_abi_cases" ] || {
	echo "nested-vmx model: no startup-management ABI cases found" >&2
	exit 1
}
for test_case in $startup_management_abi_cases; do
	run_atf_case "$startup_management_abi_test_program" "$test_case" startup-management-abi
	count=$((count + 1))
done
rm -f "$case_log"

wait_cases=$(list_atf_cases "$wait_test_program" event-wait)
[ -n "$wait_cases" ] || {
	echo "nested-vmx model: no event-wait cases found" >&2
	exit 1
}
for test_case in $wait_cases; do
	run_atf_case "$wait_test_program" "$test_case" event-wait
	count=$((count + 1))
done
rm -f "$case_log"

set_phase validate-requirements
echo "nested-vmx model: running requirements and evidence validators"
requirements_validator=$src/tests/sys/vmm/validate-vmx-nested-requirements.sh
if [ ! -f "$requirements_validator" ]; then
	echo "nested-vmx model: requirements validator is unavailable" >&2
	exit 1
fi
env SRCTOP="$src" sh "$requirements_validator"

if [ -x "$src/tests/sys/vmm/validate-vmx-nested-public-headers.sh" ]; then
	public_header_validator=$src/tests/sys/vmm/validate-vmx-nested-public-headers.sh
elif [ -x /usr/tests/sys/vmm/validate-vmx-nested-public-headers.sh ]; then
	public_header_validator=/usr/tests/sys/vmm/validate-vmx-nested-public-headers.sh
else
	echo "nested-vmx model: public-header validator is unavailable" >&2
	exit 1
fi
echo "nested-vmx model: validating standalone public headers"
set_phase validate-public-headers
env SRCTOP="$src" "$public_header_validator"

# The owner-outcome adapter is part of the Intel production transaction.
# Source review of the module Makefile is necessary but not sufficient: build
# the local module and verify that the expected adapter symbols are present.
# This is an amd64 implementation detail; non-amd64 architectures do not
# build the Intel VMX module and remain covered by their common-state tests.
if [ -f "$src/sys/modules/vmm/Makefile" ] &&
    [ "$(uname -m)" = "amd64" ]; then
	set_phase build-and-inspect-vmm-module
	echo "nested-vmx model: checking production owner-adapter symbols in vmm.ko"
	module_obj=$(env MAKEOBJDIRPREFIX="$objprefix" \
	    make -C "$src/sys/modules/vmm" -V .OBJDIR)
	env MAKEOBJDIRPREFIX="$objprefix" make -C "$src/sys/modules/vmm" -j"$jobs" vmm.ko
	module_ko=$module_obj/vmm.ko
	[ -f "$module_ko" ] || {
		echo "nested-vmx model: missing built module $module_ko" >&2
		exit 1
	}
	if ! module_symbols=$(nm -a "$module_ko"); then
		echo "nested-vmx model: cannot inspect symbols in $module_ko" >&2
		exit 1
	fi
	if ! printf '%s\n' "$module_symbols" | awk '
	    $3 ~ /^vmx_nested_owner_(attempt_outcome|initial_attempt_outcome|resumed_attempt_outcome|postentry_transition)/ {
	        found = 1
	    }
	    END { exit !found }
	'; then
		echo "nested-vmx model: production owner adapter missing from vmm.ko" >&2
		exit 1
	fi
fi

if [ -x "$src/tests/sys/vmm/vmx-nested-requirements-selftest.sh" ]; then
	requirements_selftest=$src/tests/sys/vmm/vmx-nested-requirements-selftest.sh
elif [ -x /usr/tests/sys/vmm/vmx-nested-requirements-selftest.sh ]; then
	requirements_selftest=/usr/tests/sys/vmm/vmx-nested-requirements-selftest.sh
else
	echo "nested-vmx model: requirements validator selftest is unavailable" >&2
	exit 1
fi
echo "nested-vmx model: running requirements validator self-test"
set_phase selftest-requirements-validator
env SRCTOP="$src" "$requirements_selftest"

if [ -x "$src/tests/sys/vmm/vmx-nested-live-evidence-selftest.sh" ]; then
	evidence_selftest=$src/tests/sys/vmm/vmx-nested-live-evidence-selftest.sh
elif [ -x /usr/tests/sys/vmm/vmx-nested-live-evidence-selftest.sh ]; then
	evidence_selftest=/usr/tests/sys/vmm/vmx-nested-live-evidence-selftest.sh
else
	echo "nested-vmx model: evidence validator selftest is unavailable" >&2
	exit 1
fi
echo "nested-vmx model: running live-evidence validator self-test"
set_phase selftest-evidence-validator
"$evidence_selftest"

if [ -x "$src/tests/sys/vmm/vmx-nested-live-staging-selftest.sh" ]; then
	staging_selftest=$src/tests/sys/vmm/vmx-nested-live-staging-selftest.sh
elif [ -x /usr/tests/sys/vmm/vmx-nested-live-staging-selftest.sh ]; then
	staging_selftest=/usr/tests/sys/vmm/vmx-nested-live-staging-selftest.sh
else
	echo "nested-vmx model: staging validator selftest is unavailable" >&2
	exit 1
fi
echo "nested-vmx model: running live-staging validator self-test"
set_phase selftest-staging-validator
"$staging_selftest"

if [ -x "$src/tests/sys/vmm/vmx-nested-policy-pair-selftest.sh" ]; then
	policy_pair_selftest=$src/tests/sys/vmm/vmx-nested-policy-pair-selftest.sh
elif [ -x /usr/tests/sys/vmm/vmx-nested-policy-pair-selftest.sh ]; then
	policy_pair_selftest=/usr/tests/sys/vmm/vmx-nested-policy-pair-selftest.sh
else
	echo "nested-vmx model: policy-pair selftest is unavailable" >&2
	exit 1
fi
echo "nested-vmx model: running policy-pair validator self-test"
set_phase selftest-policy-validator
"$policy_pair_selftest"

if [ -x "$src/tests/sys/vmm/vmx-nested-live-coverage-selftest.sh" ]; then
	live_coverage_selftest=$src/tests/sys/vmm/vmx-nested-live-coverage-selftest.sh
elif [ -x /usr/tests/sys/vmm/vmx-nested-live-coverage-selftest.sh ]; then
	live_coverage_selftest=/usr/tests/sys/vmm/vmx-nested-live-coverage-selftest.sh
else
	echo "nested-vmx model: live-coverage validator selftest is unavailable" >&2
	exit 1
fi
echo "nested-vmx model: running live-coverage validator self-test"
set_phase selftest-live-coverage-validator
"$live_coverage_selftest"

# Publish the durable terminal state before the cosmetic stdout marker.  A
# detached supervisor may reap the worker immediately after the final model
# test exits, at which point all test lanes have succeeded even if stdout is
# no longer captured.
if [ -n "$result_file" ]; then
	result_tmp="${result_file}.tmp.$$"
	( printf 'PASS nested-vmx cases=%s workdir=%s\n' "$count" \
	    "${work:-${objprefix:-none}}" > "$result_tmp" &&
	    mv -f "$result_tmp" "$result_file" ) || {
		echo "nested-vmx model: cannot publish RESULT_FILE $result_file" >&2
		exit 1
	}
fi
if [ -n "$sanitizers" ]; then
	echo "PASS nested-vmx cases=$count sanitizers=$sanitizers"
else
	echo "PASS nested-vmx cases=$count"
fi
