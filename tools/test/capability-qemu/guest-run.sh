#!/bin/sh
# Execute the staged ATF suite with Kyua's production isolation semantics.

set -u

payload=${1:-/mnt}
export LD_LIBRARY_PATH=/lib:/usr/lib

mkdir -p /usr/src /usr/obj/usr/src/amd64.amd64
cp -R "$payload/source/." /usr/src/
cp -R "$payload/obj/." /usr/obj/usr/src/amd64.amd64/

if ! kldstat -q -m cryptodev; then
	kldload cryptodev || exit 1
fi

# The capability storage pool is file-backed and was exported before the
# disposable reboot to avoid a suspend-on-teardown wedge.  Re-import it here,
# in single-user, with the directory hint tzfsd's plain `zpool import` lacks
# (it searches /dev only, never finding a file vdev).  Component-storage
# tests mint tzfsd datasets from this pool.
if ! zpool list capability >/dev/null 2>&1; then
	kldload zfs 2>/dev/null || true
	zpool import -N -d /var capability 2>/dev/null || true
fi

echo "Kernel: $(uname -K) $(uname -m)"
sysctl kern.crypto.cryptokey_objects >/dev/null || exit 1
# Kyua normally applies this test-suite configuration requirement.  This
# standalone runner must do so explicitly or software-provider cases skip.
sysctl kern.crypto.allow_soft=1 >/dev/null || exit 1

command -v kyua >/dev/null 2>&1 || {
	echo "kyua is required by the capability VM harness" >&2
	exit 69
}

results=/tmp/capability-kyua.db
status=0
kyua -c none -v test_suites.capability.allow_sysctl_side_effects=true \
    test -k "$payload/Kyuafile" --build-root="$payload/tests" \
    -r "$results" || status=$?
kyua -c none report -r "$results" --verbose
exit "$status"
