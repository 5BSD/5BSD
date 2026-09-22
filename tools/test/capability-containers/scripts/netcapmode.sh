#!/bin/sh
# Born-in-capmode networking reachability proof: CONNECT (TCP) and UDP.
#
# bsdnetwork is born in capability mode.  Plain connect(2)/bind(2) are not
# CAPENABLED, connectat/bindat reject AT_FDCWD, and INET protocols have no
# pr_connectat/pr_bindat -- so before the kernel sobindat()/soconnectat() INET
# fallback (uipc_socket.c) every outbound path returned ECAPMODE.  LISTEN was
# proven earlier; this proves the two remaining syscall variants reach the
# stack: a connected TCP socket and a connected SOCK_DGRAM (UDP) socket.
#
# The rig has no network, so the RESULT is expected to be an ordinary network
# error (Network is unreachable) or a success -- never ECAPMODE ("...capability
# mode"), and never a policy denial ("Capabilities insufficient", which would
# mean the connect/udp grants below did not take).
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
scrub_stage

# Grant the default label connect + udp (listen is already the shipped default).
NC=$R/Capabilities/System/Network.cap/Units/bsdnetwork.unit/Config/bsdnetwork.conf
chmod u+w "$NC"
echo 'default { listen = true; connect = true; udp = true; }' > "$NC"
chmod u+w "$R/METALOG"
sed -i '' 's#^\(\./Capabilities/System/Network.cap/Units/bsdnetwork.unit/Config/bsdnetwork.conf type=file [^ ]* [^ ]* mode=[0-7]*\) size=[0-9]*#\1#' \
    "$R/METALOG"

build_image nc
boot rw || exit 1

echo "=== CONNECT (TCP) under cap_enter ==="
V "networkcmpctl connect 8.8.8.8 53 2>&1 | tee /tmp/c.out; \
   grep -qi 'capability mode' /tmp/c.out && echo CONNECT_ECAPMODE_FAIL || \
   { grep -qi insufficient /tmp/c.out && echo CONNECT_POLICY_DENIED_FAIL || \
     echo CONNECT_REACHED_STACK_PASS; }" 30

echo "=== UDP (SOCK_DGRAM) under cap_enter ==="
V "networkcmpctl udp 8.8.8.8 53 2>&1 | tee /tmp/u.out; \
   grep -qi 'capability mode' /tmp/u.out && echo UDP_ECAPMODE_FAIL || \
   { grep -qi insufficient /tmp/u.out && echo UDP_POLICY_DENIED_FAIL || \
     echo UDP_REACHED_STACK_PASS; }" 30
echo DONE
