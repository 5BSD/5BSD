#!/bin/sh
#
# Build and run the rootless architecture-neutral bhyve checkpoint model
# tests.  This deliberately uses the ATF test-program protocol directly: the
# source tree may be available before kyua(1) is installed, and each case is
# still enumerated from the program rather than duplicated in this script.

set -eu

src=${SRCTOP:-/usr/src}
testdir=$src/tests/sys/kern/vsock_device_harness
tests='checkpoint_compat_test checkpoint_machine_test pci_checkpoint_test
snapshot_identity_test snapshot_portable_test snapshot_manifest_test'
sanitizers=${SANITIZERS:-}
work=
case_log=
result_file=${RESULT_FILE:-}
result_started=0

cleanup()
{
	status=${1:-$?}
	trap - EXIT HUP INT TERM
	# A detached supervisor must never mistake a stale RUNNING record for a
	# successful snapshot-model run.  The record is diagnostic only: preserve
	# the original test status even if its parent directory disappears while
	# cleanup is running.
	if [ "$result_started" -eq 1 ] && [ "$status" -ne 0 ]; then
		result_tmp="${result_file}.tmp.$$"
		( printf 'FAIL virtio-snapshot-model exit=%s\n' "$status" > "$result_tmp" &&
		    mv -f "$result_tmp" "$result_file" ) 2>/dev/null ||
		    rm -f "$result_tmp" 2>/dev/null || :
	fi
	if [ -n "$case_log" ]; then
		rm -f "$case_log" 2>/dev/null || :
	fi
	if [ -n "$work" ] && [ -d "$work" ]; then
		rm -rf "$work"
	fi
	exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

if [ -n "$result_file" ]; then
	result_tmp="${result_file}.tmp.$$"
	( printf 'RUNNING virtio-snapshot-model pid=%s\n' "$$" > "$result_tmp" &&
	    mv -f "$result_tmp" "$result_file" ) || {
		echo "virtio snapshot model: cannot update RESULT_FILE $result_file" >&2
		rm -f "$result_tmp" 2>/dev/null || :
		exit 1
	}
	result_started=1
fi

if [ -n "${SANITIZE:-}" ]; then
	echo "virtio snapshot model: use SANITIZERS, not SANITIZE" >&2
	exit 2
fi

[ -d "$testdir" ] || {
	echo "virtio snapshot model: source tree not found at $src" >&2
	exit 1
}

if [ -n "$sanitizers" ]; then
	work=$(mktemp -d /tmp/virtio-snapshot-model.XXXXXX)
	#
	# The tests include the device-under-test sources with quote includes.
	# A normal in-tree build may already have those generated copies in its
	# object directory, but an isolated sanitizer object directory starts
	# empty.  Materialize the exact DUT set first, rather than accidentally
	# compiling a different source-path or falling back to an unsanitized
	# binary.
	env MAKEOBJDIRPREFIX="$work" make -C "$testdir" \
	    checkpoint_compat.c checkpoint_machine.c checkpoint_manifest.c \
	    snapshot_identity.h >/dev/null
	# Keep the Makefile's per-program CFLAGS (notably its include paths and
	# linker wrappers) intact.  Supplying CFLAGS on make(1)'s command line
	# would override those program-specific settings; an environment value is
	# combined with them by bsd.prog.mk.
	CFLAGS="${CFLAGS:-} -fsanitize=$sanitizers -fno-omit-frame-pointer"
	export CFLAGS
	env MAKEOBJDIRPREFIX="$work" make -C "$testdir" $tests >/dev/null
	obj=$(env MAKEOBJDIRPREFIX="$work" make -C "$testdir" -V .OBJDIR)
	: "${ASAN_OPTIONS:=detect_leaks=0:halt_on_error=1:abort_on_error=1}"
	: "${UBSAN_OPTIONS:=halt_on_error=1:abort_on_error=1:print_stacktrace=1}"
	export ASAN_OPTIONS UBSAN_OPTIONS
else
	make -C "$testdir" $tests >/dev/null
	obj=$(make -C "$testdir" -V .OBJDIR)
fi
passed=0
case_log=$(mktemp /tmp/virtio-snapshot-model-case.XXXXXX)

# Do not discover test cases through a pipeline.  In POSIX sh the status of
# `program -l | awk` is awk's status, so a crashed test program can otherwise
# look like an empty or partial suite.  Keep the protocol transcript for the
# associated diagnostic and validate the producer before parsing it.
list_atf_cases()
{
	program=$1

	if ! "$program" -l >"$case_log" 2>&1; then
		echo "FAIL virtio-snapshot case discovery: $program" >&2
		cat "$case_log" >&2
		return 1
	fi
	awk '/^ident: / { print $2 }' "$case_log"
}

# The ATF executable's process status confirms protocol handling, not a test
# body's result.  Require the final result record as well, without retaining
# arbitrary test output in a shell variable.
run_atf_case()
{
	program=$1
	test_case=$2

	if ! "$program" -r /dev/stdout "$test_case" >"$case_log" 2>&1 ||
	    ! tail -n 1 "$case_log" | grep -qx passed; then
		cat "$case_log" >&2
		echo "FAIL virtio-snapshot $program:$test_case" >&2
		return 1
	fi
}

for test in $tests; do
	program=$obj/$test
	[ -x "$program" ] || {
		echo "virtio snapshot model: missing executable $program" >&2
		exit 1
	}
	case_list=$(list_atf_cases "$program")
	[ -n "$case_list" ] || {
		echo "virtio snapshot model: no cases in $test" >&2
		exit 1
	}
	for test_case in $case_list; do
		if ! run_atf_case "$program" "$test_case"; then
			exit 1
		fi
		passed=$((passed + 1))
	done
done

if [ -n "$result_file" ]; then
	result_tmp="${result_file}.tmp.$$"
	( printf 'PASS virtio-snapshot-model cases=%s\n' "$passed" > "$result_tmp" &&
	    mv -f "$result_tmp" "$result_file" ) || {
		echo "virtio snapshot model: cannot publish RESULT_FILE $result_file" >&2
		rm -f "$result_tmp" 2>/dev/null || :
		exit 1
	}
fi
echo "PASS virtio-snapshot-model cases=$passed"
