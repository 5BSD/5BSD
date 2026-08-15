#!/bin/sh
#
# Compile the production VMM kernel module used by Intel nested-VMX
# qualification.  Model tests are valuable, but they must not hide an API,
# warning, or link regression in the module that will run on the host.

set -eu

src=${SRCTOP:-/usr/src}
jobs=${MAKE_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 1)}

case "$jobs" in
''|*[!0-9]*)
	echo "VMM module build: MAKE_JOBS must be numeric" >&2
	exit 2
	;;
esac
[ "$jobs" -gt 0 ] || {
	echo "VMM module build: MAKE_JOBS must be positive" >&2
	exit 2
}

work=$(mktemp -d /tmp/waspnest-vmm-module.XXXXXX)
cleanup()
{
	status=${1:-$?}
	trap - EXIT HUP INT TERM
	rm -rf "$work"
	exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
obj=$work/obj
log=$work/build.log

if ! env MAKEOBJDIRPREFIX="$obj" make -C "$src/sys/modules/vmm" \
    -j"$jobs" >> "$log" 2>&1; then
	echo "VMM module build failed" >&2
	tail -n 120 "$log" >&2
	exit 1
fi

paths=$(find "$obj" -type f -name vmm.ko -print)
[ "$(printf '%s\n' "$paths" | sed '/^$/d' | wc -l | tr -d ' ')" -eq 1 ] || {
	echo "VMM module build did not produce exactly one vmm.ko" >&2
	exit 1
}
[ -s "$paths" ] || {
	echo "VMM module build produced an empty vmm.ko" >&2
	exit 1
}

echo "PASS VMM module architecture=$(uname -m)"
