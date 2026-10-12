#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Configure a 5BSD DUT ("PF" role) like setup-dut-openbsd.sh.  Disposable
# guest only.  Interface names differ (vtnet); everything else is the same
# topology.  The regress tree is expected at /usr/src/regress.
set -eu
[ -f /root/pf-parity-disposable ] || { echo "not a disposable guest"; exit 1; }
# No DNS in the isolated topology: fail lookups immediately (as NXDOMAIN
# would) instead of timing out against the unreachable slirp resolver.
sed -i '' 's/^hosts:.*/hosts: files/' /etc/nsswitch.conf
# D6 test-image plumbing: OpenBSD group ids printed by the pfctl corpus
# (group nobody 32767, group sshd 27).
pw groupmod nobody -g 32767 2>/dev/null || true
pw groupmod sshd -g 27 2>/dev/null || true
# Harness plumbing: the pf_divert Perl client hardcodes OpenBSD's
# SO_BINDANY value (0x1000, SO_ACCEPTFILTER here); 5BSD's is 0x80000.
f=/usr/src/regress/sys/net/pf_divert/Client.pm
[ -f $f ] && sed -i '' 's/SO_BINDANY => 0x1000;/SO_BINDANY => 0x80000;/' $f
p6=fdd7:e83e:66bc
IFIN=vtnet1 IFOUT=vtnet2 IFCTL=vtnet0

# PF modules are preloaded by loader.conf (late kldload is brokered).
sysctl -q net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 >/dev/null
sysctl -q net.inet6.ip6.accept_rtadv=0 >/dev/null 2>&1 || true
ifconfig $IFIN up mtu 1500
ifconfig $IFIN inet 10.188.210.50/24
ifconfig $IFIN inet6 -ifdisabled
ifconfig $IFIN inet6 $p6:210:5054:ff:fe12:3450/64
ifconfig $IFOUT up mtu 1400
ifconfig $IFOUT inet 10.188.211.50/24
ifconfig $IFOUT inet6 -ifdisabled
ifconfig $IFOUT inet6 $p6:211:5054:ff:fe12:3450/64
for n in 212 213; do
	route -q add -inet 10.188.$n.0/24 10.188.211.51 || true
	route -q add -inet6 $p6:$n::/64 $p6:211:5054:ff:fe12:3451 || true
done
route -q add -inet 10.188.219.0/24 10.188.210.10 || true
route -q add -inet6 $p6:219::/64 $p6:210:fce1:baff:fed1:561f || true
for n in 217 218 220 221; do
	route -q add -inet 10.188.$n.0/24 127.0.0.1 -reject || true
done
for n in 217 218 1220 1221; do
	route -q add -inet6 $p6:$n::/64 ::1 -reject || true
done

cat > /etc/pf.conf <<EOF
set skip on $IFCTL
pass
anchor "regress"
EOF
pfctl -f /etc/pf.conf
pfctl -e >/dev/null 2>&1 || true
ifconfig pflog0 create >/dev/null 2>&1 || true

cat > /etc/inetd.conf <<'EOF'
echo	stream	tcp	nowait	root	internal
echo	stream	tcp6	nowait	root	internal
chargen	stream	tcp	nowait	root	internal
chargen	stream	tcp6	nowait	root	internal
discard	stream	tcp	nowait	root	internal
discard	stream	tcp6	nowait	root	internal
echo	dgram	udp	wait	root	internal
echo	dgram	udp6	wait	root	internal
EOF
pkill -x inetd || true
/usr/sbin/inetd -wW /etc/inetd.conf
sleep 3   # IPv6 DAD
echo DUT_SETUP_DONE
