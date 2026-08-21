#!/bin/sh
# Verify that every WASPNest-specific test subtree has one pkgbase owner.
set -eu

srctop=${SRCTOP:-/usr/src}

fail()
{
	echo "validate-package-layout: $*" >&2
	exit 1
}

[ -d "$srctop/tests" ] || fail "test source tree is unavailable: $srctop/tests"

owners='tests/waspnest/Makefile
tests/sys/vmm/Makefile
tests/sys/vmm/intr_snapshot_harness/Makefile
tests/sys/kern/waspnest_core/Makefile
tests/sys/kern/vsock_device_harness/Makefile
tests/sys/kern/vsock_e2e/Makefile
tests/sys/kern/vsock_rx_harness/Makefile'

printf '%s\n' "$owners" | while IFS= read -r makefile; do
	[ -f "$srctop/$makefile" ] || fail "missing package owner: $makefile"
	grep -Eq '^PACKAGE=[[:space:]]*waspnest-tests$' "$srctop/$makefile" ||
	    fail "$makefile is not owned by waspnest-tests"
done

if grep -R -E '^PACKAGE=[[:space:]]*vsock-tests$' "$srctop/tests" >/dev/null; then
	fail "obsolete vsock-tests package owner remains"
fi

package_makefile=$srctop/packages/waspnest-tests/Makefile
[ -f "$package_makefile" ] || fail "WASPNest pkgbase metadata is missing"
grep -Eq '^WORLDPACKAGE=[[:space:]]*waspnest-tests$' "$package_makefile" ||
    fail "WASPNest pkgbase metadata has the wrong package name"
grep -Eq '^SUBPACKAGES=[[:space:]]*dbg$' "$package_makefile" ||
    fail "WASPNest debug payload is not packaged"
if grep -Eq 'PKG_DEPS\.waspnest-tests\+=[[:space:]]*(tests|vsock-tests)$' \
    "$package_makefile"; then
	fail "WASPNest package still depends on a former payload owner"
fi
[ ! -e "$srctop/packages/vsock-tests" ] ||
    fail "obsolete packages/vsock-tests metadata remains"
if grep -Eq 'SUBDIR.*vsock-tests' "$srctop/packages/Makefile"; then
	fail "obsolete vsock-tests package remains in the package build"
fi

generic=$srctop/tests/sys/kern/Makefile
core=$srctop/tests/sys/kern/waspnest_core/Makefile
for test_program in vsock_test vsock_wire_test vsock_iov_test; do
	if grep -Eq "^ATF_TESTS_C\+=[[:space:]]*$test_program$" "$generic"; then
		fail "$test_program still leaks into the generic tests package"
	fi
	grep -Eq "^ATF_TESTS_C\+=[[:space:]]*$test_program$" "$core" ||
	    fail "$test_program is missing from the WASPNest core package"
done
grep -Eq '^ATF_TESTS_PYTEST\+=[[:space:]]*sglist_boundary_test\.py$' "$core" ||
    fail "sglist boundary test is missing from the WASPNest core package"
grep -Eq '^ATF_TESTS_SH\+=[[:space:]]*run_vsock_tests_test$' "$core" ||
    fail "VSOCK runner self-test is missing from the WASPNest core package"

echo "PASS WASPNest package layout: one owner, waspnest-tests"
