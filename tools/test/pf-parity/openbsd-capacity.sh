#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Reference counterpart of tests/sys/netpfil/pf/limiters.sh source_capacity_*.
# Run only in a dedicated OpenBSD PF parity guest; this replaces its PF policy.
set -eu
[ "$(uname -s)" = OpenBSD ]
[ -f /root/pf-parity-disposable ]
fail()
{
    echo "REFERENCE_FAILURE: $*" >&2
    exit 1
}
cleanup()
{
    pfctl -F all >/dev/null 2>&1 || true
    ifconfig pair1 destroy >/dev/null 2>&1 || true
    ifconfig pair2 destroy >/dev/null 2>&1 || true
}
trap cleanup EXIT
# Refuse to reuse an existing topology.
if ifconfig pair1 >/dev/null 2>&1 || ifconfig pair2 >/dev/null 2>&1; then
    trap - EXIT
    fail 'pair1/pair2 already exist'
fi
ifconfig pair1 create
ifconfig pair2 create
ifconfig pair1 rdomain 1 up
# Keep the filtered endpoint in rdomain 0: upstream pfctl source deletion
# does not initialize the ioctl routing-domain field or honor -V there.
ifconfig pair2 up
ifconfig pair1 patch pair2
ifconfig pair2 inet 192.0.2.1/24
ifconfig pair2 inet6 2001:db8::1/64
for host in 2 3 4; do
    ifconfig pair1 inet 192.0.2.${host}/24 alias
    ifconfig pair1 inet6 2001:db8::${host}/64 alias
done
# DAD completion is bounded; do not mistake a tentative address for a PF failure.
tries=0
while ifconfig pair1 inet6 | grep -q tentative || ifconfig pair2 inet6 | grep -q tentative; do
    tries=$((tries + 1))
    [ "$tries" -lt 20 ] || fail 'IPv6 DAD did not complete'
    sleep 1
done
if ! pfctl -si | grep -q '^Status: Enabled'; then pfctl -e; fi
for family in inet inet6; do
    if [ "$family" = inet ]; then
        prefix=192.0.2.; ping_cmd=ping; proto=icmp; type=icmp-type
    else
        prefix=2001:db8::; ping_cmd=ping6; proto=icmp6; type=icmp6-type
    fi
    for action in default block no-match; do
        option="($action)"
        [ "$action" != default ] || option=""
        pfctl -F all
        # The client endpoint bypasses filtering, matching the 5BSD VNET test.
        printf 'set skip on { lo pair1 }\npass\n' | pfctl -f -
        for host in 2 3 4; do
            $ping_cmd -V 1 -I ${prefix}${host} -c 1 -w 3 ${prefix}1 >/dev/null || fail "baseline $family $host"
        done
        pfctl -F all
        cat <<RULES | pfctl -f -
set skip on { lo pair1 }
set timeout icmp.first 600
set timeout icmp.error 600
set timeout src.track 600
source limiter "capacity" id 1 entries 2 limit 100
pass in quick on pair2 $family proto $proto $type echoreq source limiter "capacity" $option
pass
RULES
        for host in 2 3; do
            $ping_cmd -V 1 -I ${prefix}${host} -c 1 -w 3 ${prefix}1 >/dev/null || fail "admit $family $action $host"
        done
        pfctl -s Srclimiters | grep -Eq '^[[:space:]]*1[[:space:]]+2/2[[:space:]]' || fail 'entry count'
        admitted=no
        if $ping_cmd -V 1 -I ${prefix}4 -c 1 -w 3 ${prefix}1 >/dev/null; then admitted=yes; fi
        if [ "$action" = no-match ]; then
            [ "$admitted" = yes ] || fail 'no-match failed to fall through'
        else
            [ "$admitted" = no ] || fail "$family $action failed to block exhausted capacity"
        fi
        pfctl -s Srclimiters | awk '$1 == 1 && $6 > 0 { found = 1 } END { exit !found }' || fail 'capacity counter'
        $ping_cmd -V 1 -I ${prefix}2 -c 1 -w 3 ${prefix}1 >/dev/null || fail 'existing source excluded'
        pfctl -k ${prefix}4
        /root/openbsd-clear-source ${prefix}3
        $ping_cmd -V 1 -I ${prefix}4 -c 1 -w 3 ${prefix}1 >/dev/null || fail 'capacity not restored'
        pfctl -s Srclimiters | grep -Eq '^[[:space:]]*1[[:space:]]+2/2[[:space:]]' || fail 'restored count'
        echo "REFERENCE_CASE $family $action passed"
    done
done
echo REFERENCE_CAPACITY_DONE
