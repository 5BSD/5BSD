#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Configure the OpenBSD reference DUT ("PF" role).  Disposable guest only.
set -eu
[ -f /root/pf-parity-disposable ] || { echo "not a disposable guest"; exit 1; }
p6=fdd7:e83e:66bc
IFIN=vio1 IFOUT=vio2 IFCTL=vio0

sysctl -q net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 >/dev/null
ifconfig $IFIN up mtu 1500
ifconfig $IFIN inet 10.188.210.50/24
ifconfig $IFIN inet6 $p6:210:5054:ff:fe12:3450/64
ifconfig $IFOUT up mtu 1400
ifconfig $IFOUT inet 10.188.211.50/24
ifconfig $IFOUT inet6 $p6:211:5054:ff:fe12:3450/64
for n in 212 213; do
	route -q add -inet 10.188.$n.0/24 10.188.211.51 || true
	route -q add -inet6 $p6:$n::/64 $p6:211:5054:ff:fe12:3451 || true
done
# pf_state FAKE_NET behind LOCAL (helper SRC)
route -q add -inet 10.188.219.0/24 10.188.210.10 || true
route -q add -inet6 $p6:219::/64 $p6:210:fce1:baff:fed1:561f || true
for n in 217 218 220 221; do
	route -q add -reject -inet 10.188.$n.0/24 127.0.0.1 || true
done
for n in 217 218 1220 1221; do
	route -q add -reject -inet6 $p6:$n::/64 ::1 || true
done

cat > /etc/pf.conf <<EOF
set skip on $IFCTL
pass
anchor "regress"
EOF
pfctl -f /etc/pf.conf
pfctl -e >/dev/null 2>&1 || true

cat > /etc/inetd.conf <<'EOF'
echo	stream	tcp	nowait	root	internal
echo	stream	tcp6	nowait	root	internal
chargen	stream	tcp	nowait	root	internal
chargen	stream	tcp6	nowait	root	internal
echo	dgram	udp	wait	root	internal
echo	dgram	udp6	wait	root	internal
EOF
pkill -x inetd || true
/usr/sbin/inetd /etc/inetd.conf
sleep 3   # IPv6 DAD
echo DUT_SETUP_DONE
