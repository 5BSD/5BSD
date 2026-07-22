#!/bin/sh
# Run all vsock ATF tests and write results to a file.
# Usage: ./run_vsock_tests.sh [output_file]
#
# Must be run as root: the vsock module may need loading, and several cases
# write kern.vsock.* sysctls or bind privileged ports (they carry
# require.user=root and will SKIP under an unprivileged run rather than fail).

_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
_arch=$(uname -p)
if [ -f "${_script_dir}/Makefile" ]; then
	_srctop=${SRCTOP:-$(CDPATH= cd -- "${_script_dir}/../../.." && pwd)}
else
	_srctop=${SRCTOP:-/usr/src}
fi
_objtop=${OBJTOP:-/usr/obj${_srctop}/${_arch}.${_arch}}
if [ -x "${_script_dir}/vsock_test" ]; then
	_objdir=${KERN_TEST_DIR:-${_script_dir}}
	_mac_objdir=${MAC_TEST_DIR:-${_script_dir}/../mac_capability}
else
	_objdir=${KERN_TEST_DIR:-${_objtop}/tests/sys/kern}
	_mac_objdir=${MAC_TEST_DIR:-${_objtop}/tests/sys/mac_capability}
fi
OUT="${1:-/tmp/vsock_test_results.txt}"

# Test binaries to run, in order.  BINARY optionally overrides the path to the
# primary functional suite (e.g. to point at a locally built binary); the
# wire/iov/device/RX ABI suites are added from their actual subdirectories.
BINARY="${BINARY:-${_objdir}/vsock_test}"
BINARIES="$BINARY ${_objdir}/vsock_wire_test ${_objdir}/vsock_iov_test \
    ${_objdir}/vsock_device_harness/vsock_device_test \
    ${_objdir}/vsock_device_harness/virtio_modern_test \
    ${_objdir}/vsock_device_harness/virtio_input_test \
    ${_objdir}/vsock_device_harness/virtio_rnd_test \
    ${_objdir}/vsock_device_harness/virtio_rnd_interrupt_test \
    ${_objdir}/vsock_device_harness/virtio_core_test \
    ${_objdir}/vsock_device_harness/iov_test \
    ${_objdir}/vsock_device_harness/virtio_console_test \
    ${_objdir}/vsock_device_harness/virtio_9p_test \
    ${_objdir}/vsock_device_harness/virtio_block_test \
    ${_objdir}/vsock_device_harness/virtio_net_test \
    ${_objdir}/vsock_device_harness/virtio_scsi_test \
    ${_objdir}/vsock_rx_harness/vsock_rx_test \
    ${_objdir}/vsock_rx_harness/virtio_vsock_transport_test"

MAC_BINARY="${MAC_BINARY:-${_mac_objdir}/mac_capability_isolation_test}"
for _bin in $BINARIES "$MAC_BINARY"; do
	if [ ! -x "$_bin" ]; then
		echo "ERROR: $_bin not found or not executable" >&2
		echo "Build the vsock-tests, tests, and mac-capability-tests suites first" >&2
		exit 1
	fi
done

if [ "$(id -u)" -ne 0 ]; then
	echo "WARNING: not running as root; privileged cases will SKIP or fail" >&2
fi

PASS=0
FAIL=0
SKIP=0

echo "vsock test results — $(date)" > "$OUT"
echo "Kernel: $(uname -r) $(uname -v | head -1)" >> "$OUT"
echo "========================================" >> "$OUT"

run_case() {
	# $1 = binary, $2 = test-case ident, $3 = optional ATF srcdir
	_bin=$1
	_tc=$2
	_srcdir=${3:-}
	if [ -n "$_srcdir" ]; then
		output=$("$_bin" -v "srcdir=$_srcdir" "$_tc" 2>&1)
	else
		output=$("$_bin" "$_tc" 2>&1)
	fi
	# Find the ATF result token robustly instead of trusting the last line
	# (trailing warnings on stderr would otherwise be misread as failures).
	result=$(printf '%s\n' "$output" | \
	    grep -E '^(passed|skipped|failed)' | tail -1)
	case "$result" in
	passed*)
		PASS=$((PASS+1))
		echo "PASS  ${_tc}" >> "$OUT"
		;;
	skipped*)
		SKIP=$((SKIP+1))
		reason=$(printf '%s' "$result" | sed 's/^skipped: *//')
		echo "SKIP  ${_tc} — ${reason}" >> "$OUT"
		;;
	*)
		FAIL=$((FAIL+1))
		echo "FAIL  ${_tc}" >> "$OUT"
		printf '%s\n' "$output" | grep -v WARNING >> "$OUT"
		echo "" >> "$OUT"
		;;
	esac
}

TOTAL=0
for bin in $BINARIES; do
	echo "" >> "$OUT"
	echo "### $(basename "$bin")" >> "$OUT"
	tests=$("$bin" -l 2>/dev/null | grep 'ident:' | sed 's/ident: //')
	for tc in $tests; do
		TOTAL=$((TOTAL+1))
		run_case "$bin" "$tc"
	done
done

# The isolation suite is broader than vsock, so include only its AF_VSOCK
# ownership cases here.  An explicit srcdir lets exec'd helper tests find the
# companion binary when this script is run from another directory.
echo "" >> "$OUT"
echo "### $(basename "$MAC_BINARY") (vsock cases)" >> "$OUT"
tests=$("$MAC_BINARY" -l 2>/dev/null | sed -n 's/^ident: \(vsock_[^ ]*\)$/\1/p')
for tc in $tests; do
	TOTAL=$((TOTAL+1))
	run_case "$MAC_BINARY" "$tc" "$_mac_objdir"
done

echo "========================================" >> "$OUT"
echo "TOTAL: $PASS passed, $FAIL failed, $SKIP skipped (of $TOTAL)" >> "$OUT"

echo ""
echo "Results written to $OUT"
echo "TOTAL: $PASS passed, $FAIL failed, $SKIP skipped (of $TOTAL)"

# Non-zero exit if any case failed, so callers/CI can gate on it.
[ "$FAIL" -eq 0 ]
