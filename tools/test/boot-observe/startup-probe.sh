#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Run only in an explicitly selected disposable guest. Requests guest shutdown.
set -eu
if [ "$#" -lt 2 ]; then
    echo "usage: startup-probe.sh hostname enforcing [expected-daemon ...]" >&2
    exit 64
fi
expected_hostname=$1
expected_enforcing=$2
shift 2
case "$expected_enforcing" in
0|1) ;;
*) echo "enforcing must be 0 or 1" >&2; exit 64 ;;
esac
test "$(/usr/bin/id -u)" = 0
test "$(/sbin/sysctl -n security.mac.system_integrity.enforcing)" = "$expected_enforcing"
test "$(/bin/hostname)" = "$expected_hostname"
for control in bypass_before_seeding read_random_bypassed_before_seeding arc4random_bypassed_before_seeding; do
    test "$(/sbin/sysctl -n kern.random.initial_seeding.$control)" = 0
done
/bin/dd if=/dev/random of=/dev/null bs=32 count=1 status=none
for daemon do
    /bin/pgrep -x "$daemon" >/dev/null || { echo "missing process: $daemon" >&2; exit 1; }
done
work=$(/usr/bin/mktemp -d /tmp/bip-startup.XXXXXXXX)
trap '/bin/rm -rf "$work"' EXIT
cd "$work"
if ! /usr/tests/sys/file/tty_open_test -r "$work/result" private_slave >"$work/output" 2>&1; then
    /bin/cat "$work/output" >&2
    test ! -f "$work/result" || /bin/cat "$work/result" >&2
    exit 1
fi
/usr/bin/grep -qx passed "$work/result"
/sbin/shutdown -p +1 >/dev/null 2>&1
printf 'BIP_STARTUP_PTY_SMOKE_OK\n'
