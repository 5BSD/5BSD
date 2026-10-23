#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
[ "$(uname -s)" = OpenBSD ]
[ -f /root/pf-parity-disposable ]
if ifconfig pair1 >/dev/null 2>&1 || ifconfig pair2 >/dev/null 2>&1; then
    echo 'Refusing existing topology' >&2
    exit 1
fi
cleanup()
{
    pfctl -F all >/dev/null 2>&1 || true
    ifconfig pair1 destroy >/dev/null 2>&1 || true
    ifconfig pair2 destroy >/dev/null 2>&1 || true
}
trap cleanup EXIT
ifconfig pair1 create
ifconfig pair2 create
ifconfig pair1 rdomain 1 up
ifconfig pair2 up
ifconfig pair1 patch pair2
ifconfig pair1 inet6 fe80::1234/64
ifconfig pair2 inet6 fe80::5678/64
sleep 3
pfctl -F all
cat <<'RULES' | pfctl -f -
set skip on { lo pair1 }
set timeout icmp.first 600
set timeout icmp.error 600
block
pass in quick on pair2 inet6 proto icmp6 from fe80::1234 to ff02::1 keep state
RULES
if ! pfctl -si | grep -q '^Status: Enabled'; then pfctl -e; fi
for type in query report; do
    pfctl -F states
    for item in ff02::101:1 ff02::101:1 ff02::102:2 ff02::101:2; do
        group=${item%:*}
        expected=${item##*:}
        route -T 1 exec /root/openbsd-mld-send pair1 "$type" "$group"
        tries=0
        while :; do
            count=$(pfctl -N -ss | grep -c 'fe80::1234' || true)
            [ "$count" = "$expected" ] && break
            tries=$((tries + 1))
            if [ "$tries" -ge 15 ]; then
                pfctl -N -ss
                echo "REFERENCE_MLD_FAILURE $type $group expected=$expected actual=$count"
                exit 1
            fi
            sleep 1
        done
    done
    echo "REFERENCE_MLD_GROUP $type passed"
done
echo REFERENCE_MLD_DONE
