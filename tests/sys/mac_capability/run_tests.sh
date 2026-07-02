#!/bin/sh
#
# mac_capability test runner.  Loads service modules, runs ATF tests.
# Must be run as root.
#
# Core MAC_CAPABILITY must be loaded at boot via loader.conf:
#   echo 'mac_capability_load="YES"' >> /boot/loader.conf
#

set -e

SCRIPT_DIR=${TESTSDIR:-$(CDPATH= cd "$(dirname "$0")" && pwd -P)}

CORE_MODULE="mac_capability"
BOOT_MODULES="mac_capability_capprotect mac_capability_isolation"
SERVICE_MODULES="mac_capability_test_kernelstore mac_capability_test_keystore mac_capability_channel mac_capability_identity mac_capability_node mac_capability_accounting mac_capability_mount mac_capability_system mac_capability_coalition"

MAC_CAPABILITY_TEST_BIN="${SCRIPT_DIR}/mac_capability_test"
die() { echo "FAIL: $1" >&2; exit 1; }
info() { echo "=== $1 ==="; }

expected_services=0
for _service in $SERVICE_MODULES; do
	expected_services=$((expected_services + 1))
done

# Check root
[ "$(id -u)" -eq 0 ] || die "must be root"

# Verify test binary exists
[ -x "$MAC_CAPABILITY_TEST_BIN" ] || die "mac_capability_test not found at $MAC_CAPABILITY_TEST_BIN"

# Unload any stale service modules (reverse order)
info "Unloading stale modules"
for m in mac_capability_coalition mac_capability_system mac_capability_mount mac_capability_accounting mac_capability_node mac_capability_identity mac_capability_channel mac_capability_test_keystore mac_capability_test_kernelstore; do
	kldunload "$m" 2>/dev/null || true
done

# Core MAC_CAPABILITY and capprotect must be loaded at boot (NOTLATE MAC policies).
info "Verifying boot modules"
if ! kldstat -m "$CORE_MODULE" >/dev/null 2>&1; then
	echo ""
	echo "MAC_CAPABILITY core module not loaded."
	echo "Add to /boot/loader.conf and reboot:"
	echo "  echo 'mac_capability_load=\"YES\"' >> /boot/loader.conf"
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

# Verify /dev/mac_capability exists
[ -c /dev/mac_capability ] || die "/dev/mac_capability not found"

# Verify sysctls
info "Checking sysctls"
sysctl kern.mac_capability.services >/dev/null || die "sysctl services missing"
sysctl kern.mac_capability.instances >/dev/null || die "sysctl instances missing"
services=$(sysctl -n kern.mac_capability.services)
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
	ATF_TEST_BINS="mac_capability_test mac_capability_coalition_test mac_capability_isolation_test mac_capability_identity_test mac_capability_node_test mac_capability_accounting_test mac_capability_procdesc_test mac_capability_mount_test mac_capability_system_test"
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
# Core MAC_CAPABILITY stays loaded (boot-time NOTLATE MAC policy)
info "Testing service module unload"
for m in mac_capability_coalition mac_capability_system mac_capability_mount mac_capability_accounting mac_capability_node mac_capability_identity mac_capability_channel mac_capability_test_keystore mac_capability_test_kernelstore; do
	kldunload "$m" || die "unload $m"
done

# /dev/mac_capability and capprotect stay loaded (boot-time NOTLATE MAC policies)
[ -c /dev/mac_capability ] || die "/dev/mac_capability missing after service unload"

info "All tests passed"
