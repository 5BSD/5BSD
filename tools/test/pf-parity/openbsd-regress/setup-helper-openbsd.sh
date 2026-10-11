#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Configure the OpenBSD helper guest as SRC (rdomain 0), RT (rdomain 2) and
# ECO (rdomain 3) of the upstream regress topology.  Disposable guest only.
#
#  SRC vio1 ==link A== PF_IFIN [DUT] PF_IFOUT ==link B== vio2 RT(rd2)
#  RT pair2 (mtu 1300) <-> pair3 ECO(rd3), ECO_OUT/RTT_* on vether3 (rd3)
set -eu
[ -f /root/pf-parity-disposable ] || { echo "not a disposable guest"; exit 1; }
p6=fdd7:e83e:66bc

pfctl -d >/dev/null 2>&1 || true
sysctl -q net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 >/dev/null

# SRC, rdomain 0
ifconfig vio1 up mtu 1500
ifconfig vio1 inet 10.188.210.10/24
ifconfig vio1 inet6 $p6:210:fce1:baff:fed1:561f/64
ifconfig lo0 inet 10.188.220.10/24 alias          # RPT_IN
ifconfig lo0 inet 10.188.221.10/24 alias          # RPT_OUT
ifconfig lo0 inet6 $p6:1220:fce1:baff:fed1:561f/64
ifconfig lo0 inet6 $p6:1221:fce1:baff:fed1:561f/64
for n in 211 212 213 214 215 216 217 218; do
	route -q add -inet 10.188.$n.0/24 10.188.210.50 || true
	route -q add -inet6 $p6:$n::/64 $p6:210:5054:ff:fe12:3450 || true
done

# pf_state FAKE_NET: blackholed on LOCAL (SRC)
route -q add -inet 10.188.219.0/24 127.0.0.1 -blackhole || true
route -q add -inet6 $p6:219::/64 ::1 -blackhole || true

# RT, rdomain 2
ifconfig vio2 rdomain 2 up mtu 1500
ifconfig vio2 inet 10.188.211.51/24
ifconfig vio2 inet6 $p6:211:5054:ff:fe12:3451/64
ifconfig lo2 rdomain 2 up 2>/dev/null || ifconfig lo2 create rdomain 2 up
ifconfig pair2 create 2>/dev/null || true
ifconfig pair3 create 2>/dev/null || true
ifconfig pair2 rdomain 2 mtu 1300 up
ifconfig pair2 inet 10.188.212.51/24
ifconfig pair2 inet6 $p6:212:5054:ff:fe12:3451/64
for n in 210 220 221; do
	route -q -T 2 add -inet 10.188.$n.0/24 10.188.211.50 || true
done
for n in 210 1220 1221; do
	route -q -T 2 add -inet6 $p6:$n::/64 $p6:211:5054:ff:fe12:3450 || true
done
for n in 213 217 218; do
	route -q -T 2 add -inet 10.188.$n.0/24 10.188.212.52 || true
	route -q -T 2 add -inet6 $p6:$n::/64 $p6:212:5054:ff:fe12:3452 || true
done

# ECO, rdomain 3
ifconfig lo3 rdomain 3 up 2>/dev/null || ifconfig lo3 create rdomain 3 up
ifconfig pair3 rdomain 3 mtu 1500 up
ifconfig pair3 inet 10.188.212.52/24
ifconfig pair3 inet6 $p6:212:5054:ff:fe12:3452/64
ifconfig pair2 patch pair3 2>/dev/null || true
ifconfig vether3 create 2>/dev/null || true
ifconfig vether3 rdomain 3 up
ifconfig vether3 inet 10.188.213.52/24
ifconfig vether3 inet 10.188.217.52/24 alias
ifconfig vether3 inet 10.188.218.52/24 alias
ifconfig vether3 inet6 $p6:213:5054:ff:fe12:3452/64
ifconfig vether3 inet6 $p6:217:5054:ff:fe12:3452/64
ifconfig vether3 inet6 $p6:218:5054:ff:fe12:3452/64
route -q -T 3 add -inet default 10.188.212.51 || true
route -q -T 3 add -inet6 default $p6:212:5054:ff:fe12:3451 || true

cat > /etc/inetd.eco.conf <<'EOF'
echo	stream	tcp	nowait	root	internal
echo	stream	tcp6	nowait	root	internal
echo	dgram	udp	wait	root	internal
echo	dgram	udp6	wait	root	internal
EOF
pkill -f 'inetd /etc/inetd.eco.conf' || true
route -T 3 exec /usr/sbin/inetd /etc/inetd.eco.conf
# SRC also echoes for 2-host suites (pf_state/pf_divert use REMOTE echo on DUT).
sleep 3   # IPv6 DAD
echo HELPER_SETUP_DONE
