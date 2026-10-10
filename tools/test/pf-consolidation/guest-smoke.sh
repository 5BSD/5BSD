#!/bin/sh
# Run only as init_rc in a disposable VM.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
trap 'rc=$?; echo PF_SMOKE_EXIT "$rc"; sync; /sbin/halt -p' EXIT
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
chmod 1777 /tmp
hostname pf-smoke.local
ifconfig lo0 127.0.0.1/8 up
echo PF_SMOKE_BEGIN
uname -a
test "$(sysctl -n hw.ncpu)" = 4
while IFS= read -r artifact; do sha256 "$artifact"; done < /root/pf-artifacts
for module in pf pflog dummynet if_epair if_bridge; do
    kldstat -q -m "$module" || kldload "$module"
done
test ! -e /sbin/ipfw
if kldload ipfw; then echo UNEXPECTED_IPFW_LOAD; exit 1; fi
if kldstat -q -m ipfw; then echo UNEXPECTED_IPFW_MODULE; exit 1; fi
ifconfig vtnet0 up
dhclient -b vtnet0
tries=0
until ifconfig vtnet0 inet | grep -q "inet 10.0.2.15 "; do
    tries=$((tries + 1))
    test "$tries" -lt 45
    sleep 1
done
ifconfig vtnet0
ping -c 3 -t 10 10.0.2.2
echo PF_NETWORK_PASS
rc=0
kyua test -k /usr/tests/sbin/dnctl/Kyuafile -r /root/dnctl.db || rc=$?
kyua report --verbose --results-filter=passed,skipped,xfail,broken,failed -r /root/dnctl.db
echo DNCTL_RESULT "$rc"
test "$rc" = 0
kyua test -k /usr/tests/sys/netpfil/pf/Kyuafile -r /root/pf.db \
    pass_block:enable_disable pass_block:v4 pass_block:v6 pass_block:bridge_filter \
    match:dummynet nat:dummynet_mask pflog:matches limiters:show_aliases || rc=$?
kyua report --verbose --results-filter=passed,skipped,xfail,broken,failed -r /root/pf.db
echo PF_TEST_RESULT "$rc"
kldstat
zpool sync
zpool status -x
echo PF_SMOKE_DONE
test "$rc" = 0
