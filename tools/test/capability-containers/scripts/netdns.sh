#!/bin/sh
# Born-in-capmode DNS resolution proof (end to end, over a real network path).
#
# bsdnetwork's in-process resolver runs in capability mode.  Files resolution
# (/etc/hosts) was already proven; a DNS lookup additionally needs the capmode
# UDP path (proven separately by `networkcmpctl udp`) to actually reach a
# nameserver.  This drives a real lookup of a name that is NOT in /etc/hosts.
#
# qemu's default NIC (em0) is user-mode networking: 10.0.2.0/24, gateway/NAT at
# 10.0.2.2, forwarding to the host's internet.  We configure em0 STATICALLY
# (not dhclient, which would rewrite /etc/resolv.conf to a new inode and stale
# the descriptor bsdnetwork retained at startup) so the shipped resolv.conf
# (9.9.9.9 / 1.1.1.1, reachable through the NAT) stays valid.
#
# PASS = the resolver returns an address for the name -- never ECAPMODE
# ("...capability mode") and never a policy denial ("Capabilities insufficient").
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
: "${NAME:=one.one.one.one}"
scrub_stage

# Grant the default label the resolve policy (plus the others, harmless).
NC=$R/Capabilities/System/Network.cap/Units/bsdnetwork.unit/Config/bsdnetwork.conf
chmod u+w "$NC"
echo 'default { listen = true; connect = true; udp = true; resolve = true; }' > "$NC"
chmod u+w "$R/METALOG"
sed -i '' 's#^\(\./Capabilities/System/Network.cap/Units/bsdnetwork.unit/Config/bsdnetwork.conf type=file [^ ]* [^ ]* mode=[0-7]*\) size=[0-9]*#\1#' \
    "$R/METALOG"

build_image dns
boot rw || exit 1

echo "=== bring up em0 statically on the qemu user-net (NAT to the host) ==="
V "ifconfig em0 inet 10.0.2.15 netmask 255.255.255.0 up; route -q add default 10.0.2.2 2>&1 | tail -1; \
   sleep 1; ifconfig em0 | grep -a 'inet '; echo GW:; netstat -rn -f inet 2>/dev/null | grep -a default; \
   echo RESOLVCONF:; cat /etc/resolv.conf" 40

echo "=== sanity: the host/NAT path reaches a nameserver (raw UDP from base tools) ==="
V "host -W 4 $NAME 9.9.9.9 2>&1 | head -3 || drill -Q $NAME @9.9.9.9 2>&1 | head -3 || echo '(no base resolver tool)'" 30

echo "=== capmode resolver: networkcmpctl resolve $NAME ==="
V "networkcmpctl resolve $NAME 2>&1 | tee /tmp/r.out; \
   grep -qiE 'capability mode' /tmp/r.out && echo DNS_ECAPMODE_FAIL || \
   { grep -qiE 'insufficient' /tmp/r.out && echo DNS_POLICY_DENIED_FAIL || \
     { grep -qE 'address=[0-9]|count=[1-9]' /tmp/r.out && echo DNS_RESOLVED_PASS || \
       echo DNS_NO_RESULT; }; }" 40
echo DONE
