#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Run as the real root rc child in the authenticated provider fixture.
set -e
fail() { echo "RC_HOSTID_FAIL $*"; exit 1; }
trap 'fail unexpected-exit' EXIT
before_uuid=$(/sbin/sysctl -n kern.hostuuid)
before_id=$(/sbin/sysctl -n kern.hostid)
[ "$before_uuid" = "$(/bin/cat /etc/hostid)" ]
/bin/sh /etc/rc.d/hostid onestart
/bin/sh /etc/rc.d/hostid_save onestart
if /bin/sh /etc/rc.d/hostid reset; then
    fail reset-accepted
fi
# Root may not change the kernel identity or the protected compatibility files.
if /sbin/sysctl "kern.hostid=$((before_id ^ 1))"; then
    fail kernel-id-write-accepted
fi
if /sbin/sysctl kern.hostuuid=00000000-0000-0000-0000-000000000000; then
    fail kernel-uuid-write-accepted
fi
for path in /etc/hostid /etc/machine-id; do
    if (printf 'invalid\n' > "$path") 2>/dev/null; then
        fail cache-write-accepted
    fi
done
[ "$before_uuid" = "$(/sbin/sysctl -n kern.hostuuid)" ]
[ "$before_id" = "$(/sbin/sysctl -n kern.hostid)" ]
/bin/sh /etc/rc.d/hostid_save onestart
trap - EXIT
printf 'RC_HOSTID_PASS startup caches reset kernel-and-file-denials\n'
