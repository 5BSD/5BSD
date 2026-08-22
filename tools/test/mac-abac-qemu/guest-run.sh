#!/bin/sh

set -u

media=${1:-/mnt}
results=${MAC_ABAC_RESULTS:-/tmp/mac-abac-test-results.txt}

if [ ! -f "$media/mac_abac.ko" ]; then
	mkdir -p "$media"
	mount -t cd9660 /dev/cd0 "$media" || exit 1
fi

echo "== guest =="
uname -a

echo "== install current MAC ABAC ABI and tools =="
mkdir -p /usr/include/security/mac_abac
cp "$media/include/security/mac_abac/mac_abac.h" \
	/usr/include/security/mac_abac/
cp "$media/bin/mac_abac_ctl" /usr/sbin/mac_abac_ctl
cp "$media/bin/mac_abacd" /usr/sbin/mac_abacd

echo "== load current MAC ABAC kernel module =="
if ! kldstat -q -m mac_abac; then
	kldload "$media/mac_abac.ko" || exit 1
fi
kldstat -v | grep -i mac_abac || true
/usr/sbin/mac_abac_ctl status || exit 1

echo "== compile shipped policy examples =="
for policy in "$media"/examples/sample.conf "$media"/examples/sample.json \
    "$media"/examples/sample.ucl; do
	/usr/sbin/mac_abacd -t -c "$policy" || exit 1
done
/usr/sbin/mac_abac_ctl rule validate -f "$media/examples/sample.rules" || exit 1

echo "== MAC ABAC Kyua suite =="
cd "$media/tests" || exit 1
kyua test -k Kyuafile
test_status=$?
kyua report | tee "$results"
report_status=$?

if [ "$test_status" -ne 0 ] || [ "$report_status" -ne 0 ]; then
	kyua report --verbose
	exit 1
fi
exit 0
