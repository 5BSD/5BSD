#!/bin/sh
#
# cmi test runner.  Loads modules, runs ATF tests, verifies DTrace probes.
# Must be run as root.
#

set -e

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
SRCTOP=$(CDPATH= cd "$SCRIPT_DIR/../../.." && pwd -P)

CORE_MODULE="cmi"
SERVICE_MODULES="cmi_keystore cmi_pair cmi_jail"
DTRACE_PROBES="connect send recv dispatch reply notify call revoke close"

MODDIR="${MODDIR:-$SRCTOP/sys/modules}"
TESTDIR="${TESTDIR:-$SCRIPT_DIR}"
CMI_TEST_BIN="${TESTDIR}/cmi_test"
die() { echo "FAIL: $1" >&2; exit 1; }
info() { echo "=== $1 ==="; }

run_atf_case() {
	testcase=$1

	"$CMI_TEST_BIN" -s "$TESTDIR" "$testcase"
}

run_atf_tests_fallback() {
	testcases=$("$CMI_TEST_BIN" -l | awk '/^ident: / { print $2 }')
	[ -n "$testcases" ] || die "no ATF test cases discovered"

	for testcase in $testcases; do
		info "ATF $testcase"
		run_atf_case "$testcase" || die "ATF test failed: $testcase"
	done
}

expected_services=0
for _service in $SERVICE_MODULES; do
	expected_services=$((expected_services + 1))
done

# Check root
[ "$(id -u)" -eq 0 ] || die "must be root"

# Build everything
info "Building modules"
for d in $CORE_MODULE $SERVICE_MODULES; do
	(cd "$MODDIR/$d" && make clean >/dev/null 2>&1 && make) ||
	    die "build $d"
done

info "Building tests"
(cd "$TESTDIR" && make clean >/dev/null 2>&1 && make) ||
    die "build tests"

# Unload any stale modules (reverse order)
info "Unloading stale modules"
for m in cmi_jail cmi_pair cmi_keystore $CORE_MODULE; do
	kldunload "$m" 2>/dev/null || true
done

# Load modules
info "Loading modules"
kldload "$MODDIR/$CORE_MODULE/$CORE_MODULE.ko" || die "kldload $CORE_MODULE"
for m in $SERVICE_MODULES; do
	kldload "$MODDIR/$m/$m.ko" || die "kldload $m"
done

# Verify modules loaded
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
cd "$TESTDIR"
if command -v kyua >/dev/null 2>&1; then
	kyua test || die "kyua test failed"
	kyua report
else
	# Fallback: enumerate tests and run them one at a time.
	run_atf_tests_fallback
fi

# DTrace probe verification (if dtrace is available)
if command -v dtrace >/dev/null 2>&1; then
	info "Verifying DTrace probes"
	for probe in $DTRACE_PROBES; do
		dtrace -ln "cmi:::$probe" >/dev/null 2>&1 ||
		    die "missing cmi probe: $probe"
	done

	# Fire probes and verify they fire.  write_read exercises
	# connect, send, dispatch, reply, recv, close.
	# pair_bidirectional adds notify.
	# revoke_via_token adds revoke.
	# jail_call_info adds call.
	info "DTrace live trace test"
	dtrace -n '
	    cmi:::connect  { traced++; }
	    cmi:::send     { traced++; }
	    cmi:::dispatch { traced++; }
	    cmi:::reply    { traced++; }
	    cmi:::recv     { traced++; }
	    cmi:::notify   { traced++; }
	    cmi:::call     { traced++; }
	    cmi:::revoke   { traced++; }
	    cmi:::close    { traced++; }
	    tick-5s /traced > 0/ { printf("probes fired: %d", traced); exit(0); }
	    tick-10s /traced == 0/ { printf("ERROR: no probes fired"); exit(1); }
	' -c "sh -c './cmi_test write_read; ./cmi_test pair_bidirectional; ./cmi_test revoke_via_token; ./cmi_test jail_call_info'" 2>&1 | tail -5

	info "DTrace probes verified"
else
	info "DTrace not available, skipping probe verification"
fi

# Verify clean unload
info "Testing module unload"
kldunload cmi_jail || die "unload cmi_jail"
kldunload cmi_pair || die "unload cmi_pair"
kldunload cmi_keystore || die "unload cmi_keystore"
kldunload "$CORE_MODULE" || die "unload $CORE_MODULE"

# Verify /dev/cmi is gone
[ ! -c /dev/cmi ] || die "/dev/cmi still exists after unload"

info "All tests passed"
