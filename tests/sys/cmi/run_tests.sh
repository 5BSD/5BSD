#!/bin/sh
#
# cmi test runner.  Loads service modules, runs ATF tests.
# Must be run as root.
#
# Core CMI must be loaded at boot via loader.conf:
#   echo 'cmi_load="YES"' >> /boot/loader.conf
#

set -e

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P)

CORE_MODULE="cmi"
BOOT_MODULES="cmi_capprotect"
SERVICE_MODULES="cmi_kernelstore cmi_keystore cmi_pair cmi_namespace cmi_token"

CMI_TEST_BIN="${SCRIPT_DIR}/cmi_test"
die() { echo "FAIL: $1" >&2; exit 1; }
info() { echo "=== $1 ==="; }

expected_services=0
for _service in $SERVICE_MODULES; do
	expected_services=$((expected_services + 1))
done

# Check root
[ "$(id -u)" -eq 0 ] || die "must be root"

# Verify test binary exists
[ -x "$CMI_TEST_BIN" ] || die "cmi_test not found at $CMI_TEST_BIN"

# Unload any stale service modules (reverse order)
info "Unloading stale modules"
for m in cmi_token cmi_namespace cmi_pair cmi_keystore cmi_kernelstore; do
	kldunload "$m" 2>/dev/null || true
done

# Core CMI and capprotect must be loaded at boot (NOTLATE MAC policies).
info "Verifying boot modules"
if ! kldstat -m "$CORE_MODULE" >/dev/null 2>&1; then
	echo ""
	echo "CMI core module not loaded."
	echo "Add to /boot/loader.conf and reboot:"
	echo "  echo 'cmi_load=\"YES\"' >> /boot/loader.conf"
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

# Verify /dev/cmi exists
[ -c /dev/cmi ] || die "/dev/cmi not found"

# Verify sysctls
info "Checking sysctls"
sysctl kern.cmi.services >/dev/null || die "sysctl services missing"
sysctl kern.cmi.instances >/dev/null || die "sysctl instances missing"
services=$(sysctl -n kern.cmi.services)
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
	# Fallback: enumerate tests and run them one at a time.
	testcases=$("$CMI_TEST_BIN" -l | awk '/^ident: / { print $2 }')
	[ -n "$testcases" ] || die "no ATF test cases discovered"

	for testcase in $testcases; do
		info "ATF $testcase"
		"$CMI_TEST_BIN" -s "$SCRIPT_DIR" "$testcase" ||
		    die "ATF test failed: $testcase"
	done
fi

# Verify clean service module unload
# Core CMI stays loaded (boot-time NOTLATE MAC policy)
info "Testing service module unload"
for m in cmi_token cmi_namespace cmi_pair cmi_keystore cmi_kernelstore; do
	kldunload "$m" || die "unload $m"
done

# /dev/cmi and capprotect stay loaded (boot-time NOTLATE MAC policies)
[ -c /dev/cmi ] || die "/dev/cmi missing after service unload"

info "All tests passed"
