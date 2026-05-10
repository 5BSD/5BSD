#!/bin/sh
#
# cap_rt test runner.  Loads service modules, runs ATF tests.
# Must be run as root.
#
# Core CAP_RT must be loaded at boot via loader.conf:
#   echo 'cap_rt_load="YES"' >> /boot/loader.conf
#

set -e

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P)

CORE_MODULE="cap_rt"
BOOT_MODULES="cap_rt_capprotect cap_rt_isolation"
SERVICE_MODULES="cap_rt_test_kernelstore cap_rt_test_keystore cap_rt_pair cap_rt_identity cap_rt_node cap_rt_accounting"

CAP_RT_TEST_BIN="${SCRIPT_DIR}/cap_rt_test"
die() { echo "FAIL: $1" >&2; exit 1; }
info() { echo "=== $1 ==="; }

expected_services=0
for _service in $SERVICE_MODULES; do
	expected_services=$((expected_services + 1))
done

# Check root
[ "$(id -u)" -eq 0 ] || die "must be root"

# Verify test binary exists
[ -x "$CAP_RT_TEST_BIN" ] || die "cap_rt_test not found at $CAP_RT_TEST_BIN"

# Unload any stale service modules (reverse order)
info "Unloading stale modules"
for m in cap_rt_accounting cap_rt_node cap_rt_identity cap_rt_pair cap_rt_test_keystore cap_rt_test_kernelstore; do
	kldunload "$m" 2>/dev/null || true
done

# Core CAP_RT and capprotect must be loaded at boot (NOTLATE MAC policies).
info "Verifying boot modules"
if ! kldstat -m "$CORE_MODULE" >/dev/null 2>&1; then
	echo ""
	echo "CAP_RT core module not loaded."
	echo "Add to /boot/loader.conf and reboot:"
	echo "  echo 'cap_rt_load=\"YES\"' >> /boot/loader.conf"
	die "$CORE_MODULE not loaded (requires loader.conf)"
fi
for m in $BOOT_MODULES; do
	if ! kldstat -m "$m" >/dev/null 2>&1; then
		echo ""
		echo "$m not loaded at boot."
		echo "Add to /boot/loader.conf and reboot:"
		echo "  echo '${m}_load=\"YES\"' >> /boot/loader.conf"
		die "$m not loaded (requires loader.conf)"
	fi
done

# Load service modules — try system path first, then local
info "Loading service modules"
for m in $SERVICE_MODULES; do
	kldload "$m" 2>/dev/null || kldload "./${m}.ko" 2>/dev/null ||
	    die "kldload $m"
done

# Verify all modules loaded
info "Verifying modules"
kldstat -m "$CORE_MODULE" >/dev/null || die "$CORE_MODULE not loaded"
for m in $SERVICE_MODULES; do
	kldstat -m "$m" >/dev/null || die "$m not loaded"
done

# Verify /dev/cap_rt exists
[ -c /dev/cap_rt ] || die "/dev/cap_rt not found"

# Verify sysctls
info "Checking sysctls"
sysctl kern.cap_rt.services >/dev/null || die "sysctl services missing"
sysctl kern.cap_rt.instances >/dev/null || die "sysctl instances missing"
services=$(sysctl -n kern.cap_rt.services)
[ "$services" -ge "$expected_services" ] ||
    die "expected >= $expected_services services, got $services"

# Run ATF tests
info "Running ATF tests"
cd "$SCRIPT_DIR"
export TESTSDIR="$SCRIPT_DIR"
if command -v kyua >/dev/null 2>&1; then
	kyua test || die "kyua test failed"
	kyua report
else
	# Fallback: enumerate tests from all test binaries.
	ATF_TEST_BINS="cap_rt_test cap_rt_coalition_test cap_rt_isolation_test cap_rt_identity_test cap_rt_node_test cap_rt_accounting_test cap_rt_procdesc_test"
	for testbin in $ATF_TEST_BINS; do
		testbin_path="${SCRIPT_DIR}/${testbin}"
		[ -x "$testbin_path" ] || continue
		testcases=$("$testbin_path" -l | awk '/^ident: / { print $2 }')
		for testcase in $testcases; do
			info "ATF ${testbin}:${testcase}"
			"$testbin_path" -s "$SCRIPT_DIR" "$testcase" ||
			    die "ATF test failed: ${testbin}:${testcase}"
		done
	done
fi

# Verify clean service module unload
# Core CAP_RT stays loaded (boot-time NOTLATE MAC policy)
info "Testing service module unload"
for m in cap_rt_accounting cap_rt_node cap_rt_identity cap_rt_pair cap_rt_test_keystore cap_rt_test_kernelstore; do
	kldunload "$m" || die "unload $m"
done

# /dev/cap_rt and capprotect stay loaded (boot-time NOTLATE MAC policies)
[ -c /dev/cap_rt ] || die "/dev/cap_rt missing after service unload"

info "All tests passed"
