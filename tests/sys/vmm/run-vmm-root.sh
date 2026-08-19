#!/bin/sh
# Run the complete VMM Kyua suite against one explicitly selected module.

set -eu

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 077

OBJTOP=${OBJTOP:-/usr/obj/usr/src/amd64.amd64}
MODULE=${MODULE:-$OBJTOP/sys/modules/vmm/vmm.ko}
KERNBUILDDIR=${KERNBUILDDIR:-$OBJTOP/sys/VBSD}
KYUAFILE=${KYUAFILE:-$OBJTOP/tests/sys/vmm/Kyuafile}
if [ -n "${WORKDIR:-}" ]; then
	RESULT=${RESULT:-$WORKDIR/kyua-vmm-root.db}
else
	RESULT=${RESULT:-/tmp/kyua-vmm-root-$(date -u +%Y%m%dT%H%M%SZ).db}
fi

fail()
{
	echo "VMM root gate: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ -f "$MODULE" ] && [ ! -L "$MODULE" ] ||
    fail "reviewed module is not a regular file: $MODULE"
[ -f "$KERNBUILDDIR/opt_bhyve_snapshot.h" ] &&
    grep -qx '#define BHYVE_SNAPSHOT 1' \
    "$KERNBUILDDIR/opt_bhyve_snapshot.h" ||
    fail "kernel object directory does not enable BHYVE_SNAPSHOT"
nm "$MODULE" | grep -Eq '[[:space:]]vmmdev_snapshot_session_begin$' ||
    fail "reviewed module lacks snapshot-session support"
[ -f "$KYUAFILE" ] && [ ! -L "$KYUAFILE" ] ||
    fail "built test Kyuafile is not a regular file: $KYUAFILE"

inventory=$(kyua list -k "$KYUAFILE")
for test_case in \
    vmm_run_live_test:real_mode_io_and_halt \
    vmm_run_live_test:breakpoint_exit \
    vmm_run_live_test:pause_exit; do
	printf '%s\n' "$inventory" | grep -qx "$test_case" ||
	    fail "built suite lacks live hardware-entry case: $test_case"
done

busy=no
for node in /dev/vmm/*; do
	if [ -c "$node" ]; then
		echo "active VM blocks module replacement: $node" >&2
		busy=yes
	fi
done
[ "$busy" = no ] || fail "stop the listed VMs and rerun"

if kldstat -q -m vmm; then
	kldunload vmm
fi
kldload "$MODULE"
kldstat -v | grep -F "vmm.ko ($MODULE)" >/dev/null ||
    fail "loaded module path does not match $MODULE"

echo "VMM-MODULE path=$MODULE sha256=$(sha256 -q "$MODULE")"
echo "VMM-CAPABILITIES"
sysctl -a 2>/dev/null | grep -E \
    '^hw\.vmm\.(vmx|svm|iommu|ppt|ept|npt|pvclock)\.' | sort || true

test_status=0
kyua test -k "$KYUAFILE" -r "$RESULT" || test_status=$?
report_status=0
report=$(kyua report -r "$RESULT") || report_status=$?
printf '%s\n' "$report"
echo "VMM-RESULT database=$RESULT"

leaked=no
for node in /dev/vmm/*; do
	if [ -c "$node" ]; then
		echo "VMM test leaked VM device: $node" >&2
		leaked=yes
	fi
done
[ "$leaked" = no ] || fail "test cleanup leaked a VM"
[ "$report_status" -eq 0 ] || exit "$report_status"
[ "$test_status" -eq 0 ] || exit "$test_status"
printf '%s\n' "$report" | grep -Eq \
    'Test cases: [0-9]+ total, 0 skipped, 0 expected failures, 0 broken, 0 failed' ||
    fail "gate requires zero skips and zero non-passing results"
echo "VMM-POSTCONDITION no-leaked-vms"
