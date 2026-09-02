#!/bin/sh
#
# mac_capability test runner.  Loads service modules, runs ATF tests.
# Must be run as root.
#
# Core MAC_CAPABILITY must be loaded at boot via loader.conf:
#   echo 'mac_capability_load="YES"' >> /boot/loader.conf
#
# These are kernel-integration tests: each opens /dev/mac_capability and
# drives the module directly.  They must run PLANE-FREE -- on a normal
# capability-plane boot, capsule is PID 1 and serviced owns the
# control device, so the runner cannot claim it (and capability-mode would
# confine the test process).  Boot the test host with the plane disabled so
# stock /sbin/init runs instead:
#   at the loader prompt:  set capability_plane="NO"  (then boot)
#   or persistently:       echo 'capability_plane="NO"' >> /boot/loader.conf
# The kernel + mac_capability modules still load; only the plane stays down.
#

set -e

SCRIPT_DIR=${TESTSDIR:-$(CDPATH= cd "$(dirname "$0")" && pwd -P)}

CORE_MODULE="mac_capability"
BOOT_MODULES="mac_capability_capprotect mac_capability_isolation"
SERVICE_MODULES="mac_capability_test_kernelstore mac_capability_test_keystore mac_capability_channel mac_capability_identity mac_capability_node mac_capability_accounting mac_capability_mount mac_capability_system mac_capability_coalition"

MAC_CAPABILITY_TEST_BIN="${SCRIPT_DIR}/mac_capability_test"
die() { echo "FAIL: $1" >&2; exit 1; }
info() { echo "=== $1 ==="; }

wait_for_control_device()
{
	_waited=0
	while [ ! -c /dev/mac_capability ]; do
		_waited=$((_waited + 1))
		if [ "$_waited" -ge 10 ]; then
			return 1
		fi
		sleep 1
	done
	return 0
}

expected_services=0
for _service in $SERVICE_MODULES; do
	expected_services=$((expected_services + 1))
done

# Check root
[ "$(id -u)" -eq 0 ] || die "must be root"

# Refuse to run on a live capability plane: capsule (authorityd's PID 1
# personality) as PID 1 means serviced owns /dev/mac_capability and the runner
# cannot claim it.  Direct the operator to boot plane-free instead of failing
# later with an opaque EBUSY/EPERM on the control device.
_pid1_comm=$(ps -p 1 -o comm= 2>/dev/null || true)
case "$_pid1_comm" in
*[Cc]apsule*|*[Aa]uthority*)
	echo ""
	echo "A live capability plane is running (PID 1 = ${_pid1_comm})."
	echo "These tests need a plane-free boot.  Reboot with the plane"
	echo "disabled so stock /sbin/init runs:"
	echo "  at the loader:  set capability_plane=\"NO\"   (then boot)"
	echo "  persistently:   echo 'capability_plane=\"NO\"' >> /boot/loader.conf"
	die "capability plane active; boot plane-free to run these tests"
	;;
esac

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
	# A prior interrupted test run can leave a service module loaded.  The
	# best-effort cleanup above deliberately does not make that fatal, so do
	# not mistake kldload(8)'s EEXIST result for a load failure here.
	if kldstat -m "$m" >/dev/null 2>&1; then
		continue
	fi
	kldload "$m" 2>/dev/null || kldload "./${m}.ko" 2>/dev/null ||
	    die "kldload $m"
done

# Verify all modules loaded
info "Verifying modules"
kldstat -m "$CORE_MODULE" >/dev/null || die "$CORE_MODULE not loaded"
for m in $SERVICE_MODULES; do
	kldstat -m "$m" >/dev/null || die "$m not loaded"
done

# A service unload revokes its instances synchronously, but the owning
# processes can close their revoked descriptors just after kldunload returns.
# An isolation instance may still be releasing a vnode claim during that
# interval, making stat(2) of the otherwise-present control node fail with
# EACCES.  Wait for the device to become accessible instead of misreporting
# that transient state as ENOENT.
if ! wait_for_control_device; then
	echo "Control-device diagnostics:" >&2
	ls -ld /dev /dev/mac_capability >&2 || true
	sysctl kern.mac_capability.instances >&2 || true
	sysctl kern.mac_capability.service_details >&2 || true
	die "/dev/mac_capability did not become accessible"
fi

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
		case_log=$(mktemp /tmp/mac-capability-atf-cases.XXXXXX) ||
		    die "cannot create ATF case-list output"
		if ! "$testbin_path" -l >"$case_log" 2>&1; then
			cat "$case_log" >&2
			rm -f "$case_log"
			die "ATF case discovery failed: ${testbin}"
		fi
		testcases=$(awk '/^ident: / { print $2 }' "$case_log")
		rm -f "$case_log"
		[ -n "$testcases" ] || die "ATF test declares no cases: ${testbin}"
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
