#!/bin/sh
# Run only as init_rc or from rc.local in a disposable VM.
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
if [ "${1-}" = "--normal-boot" ]; then
    pfctl -si | grep -q '^Status: Enabled'
    kldstat -q -m dummynet
    dnctl pipe 65000 show | grep -q '65000:'
    echo PF_NORMAL_BOOT_PASS
fi
# 5BSD: the capability plane denies kldload(2) after boot.  pf (with the
# pflog, pfsync and pflow cloners) and DTrace are loader defaults; the image
# must preload if_epair and if_bridge (loader.conf); dummynet may come from
# the SystemExtension broker.
for module in pf if_epair if_bridge; do
    kldstat -q -m "$module" || { echo "PF_SMOKE_NOT_PRELOADED $module"; exit 1; }
done
for cloner in pflog pfsync pflow; do
    ifconfig -C | tr ' ' '\n' | grep -qx "$cloner" ||
        { echo "PF_SMOKE_NO_CLONER $cloner"; exit 1; }
done
kldstat -q -m dummynet || sysextctl load dummynet
kldstat -q -m dummynet
test ! -e /sbin/ipfw
test ! -e /boot/kernel/ipfw.ko
if kldload ipfw; then echo UNEXPECTED_IPFW_LOAD; exit 1; fi
if kldstat -q -m ipfw; then echo UNEXPECTED_IPFW_MODULE; exit 1; fi
echo PF_IPFW_ABSENT
ifconfig vtnet0 up
if ! ifconfig vtnet0 inet | grep -q "inet 10.0.2.15 "; then
    dhclient -b vtnet0
fi
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
if [ "${1-}" != "--followup-only" ]; then
    kyua test -k /usr/tests/sbin/dnctl/Kyuafile -r /root/dnctl.db || rc=$?
    kyua report --verbose --results-filter=passed,skipped,xfail,broken,failed -r /root/dnctl.db
    echo DNCTL_RESULT "$rc"
    test "$rc" = 0
fi
if [ "${1-}" = "--followup-only" ]; then
    set -- pass_block:v4 pass_block:v6 snmp:retired_bridge_filter
else
    set -- \
    pass_block:enable_disable pass_block:v4 pass_block:v6 pass_block:bridge_filter \
    match:dummynet nat:dummynet_mask pflog:matches limiters:show_aliases pass_block:blocklist_helpers snmp:retired_bridge_filter
fi
for testcase; do
    database="/root/pf-${testcase%:*}-${testcase#*:}.db"
    kyua test -k /usr/tests/sys/netpfil/pf/Kyuafile -r "$database" "$testcase" || rc=$?
    kyua report --verbose --results-filter=passed,skipped,xfail,broken,failed -r "$database"
done
echo PF_TEST_RESULT "$rc"
test "$rc" = 0
kyua test -k /usr/tests/sys/netpfil/common/Kyuafile -r /root/common.db \
    dummynet:pf_pipe dummynet:pf_pipe_v6 dummynet:pf_codel dummynet:pf_wf2q_heap || rc=$?
kyua report --verbose --results-filter=passed,skipped,xfail,broken,failed -r /root/common.db
echo COMMON_TEST_RESULT "$rc"
kldstat
zpool sync
zpool status -x
echo PF_SMOKE_DONE
test "$rc" = 0
