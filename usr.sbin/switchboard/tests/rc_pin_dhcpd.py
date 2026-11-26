#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# rc_pin_dhcpd.py: a DHCP server on the far end of a tap(4) interface, for
# the dhclient pins of switchboard-init-rescope.md (SR0): the guests have no
# DHCP server and no network, so the test plays the server.
#
# usage: python3 rc_pin_dhcpd.py [--forever] tapN SERVER_IP CLIENT_IP
#
# It opens /dev/tapN (an existing tap interface: opening it gives the
# interface its link), prints "ready", and answers every DHCPDISCOVER with
# a DHCPOFFER and every DHCPREQUEST with a DHCPACK of CLIENT_IP/24 from
# SERVER_IP.  Without --forever it prints "ack" after each ACK and exits
# when its standard input reaches end of file (the test closes it); with
# --forever (an rc.d script at boot) it prints nothing after "ready" and
# runs until it is killed.  It waits on select(2), never on a timer.

import os
import select
import socket
import struct
import sys

MAGIC = b"\x63\x82\x53\x63"
SERVER_MAC = b"\x02\x00\x5e\x53\x00\x01"
BROADCAST_MAC = b"\xff" * 6


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def options(data):
    """The DHCP options after the magic cookie, as {code: bytes}."""
    found, i = {}, 0
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        found[code] = data[i + 2:i + 2 + length]
        i += 2 + length
    return found


def reply(request, msgtype, server, client):
    """A BOOTREPLY to request (the BOOTP payload) of the given type."""
    xid, flags, chaddr = request[4:8], request[10:12], request[28:44]
    body = struct.pack("!BBBB", 2, 1, 6, 0) + xid + struct.pack("!H", 0)
    body += flags + b"\0" * 4 + client + server + b"\0" * 4 + chaddr
    body += b"\0" * 64 + b"\0" * 128 + MAGIC
    body += bytes([53, 1, msgtype]) + bytes([54, 4]) + server
    body += bytes([51, 4]) + struct.pack("!I", 86400)
    body += bytes([1, 4]) + socket.inet_aton("255.255.255.0")
    body += bytes([255])
    udp = struct.pack("!HHHH", 67, 68, 8 + len(body), 0) + body
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17,
                     0, server, b"\xff" * 4)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return BROADCAST_MAC + SERVER_MAC + b"\x08\x00" + ip + udp


def handle(frame, server, client):
    """The reply frame and its DHCP message type, or (None, 0)."""
    if len(frame) < 14 + 20 + 8 + 240 or frame[12:14] != b"\x08\x00":
        return None, 0
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17:
        return None, 0
    udp = ip[ihl:]
    if struct.unpack("!H", udp[2:4])[0] != 67:
        return None, 0
    bootp = udp[8:]
    if len(bootp) < 240 or bootp[0] != 1 or bootp[236:240] != MAGIC:
        return None, 0
    msg = options(bootp[240:]).get(53, b"")
    if msg == b"\x01":
        return reply(bootp, 2, server, client), 2
    if msg == b"\x03":
        return reply(bootp, 5, server, client), 5
    return None, 0


def main(argv):
    forever = len(argv) > 1 and argv[1] == "--forever"
    args = argv[2:] if forever else argv[1:]
    if len(args) != 3:
        sys.stderr.write("usage: rc_pin_dhcpd.py [--forever] tapN "
                         "SERVER_IP CLIENT_IP\n")
        return 2
    ifname, server, client = args
    server, client = socket.inet_aton(server), socket.inet_aton(client)
    fd = os.open("/dev/" + ifname, os.O_RDWR)
    sys.stdout.write("ready\n")
    sys.stdout.flush()
    watched = [fd] if forever else [fd, sys.stdin.fileno()]
    while True:
        ready, _, _ = select.select(watched, [], [])
        if sys.stdin.fileno() in ready and not forever:
            if not os.read(sys.stdin.fileno(), 4096):
                return 0
        if fd in ready:
            out, msgtype = handle(os.read(fd, 65536), server, client)
            if out is not None:
                os.write(fd, out)
                if msgtype == 5 and not forever:
                    sys.stdout.write("ack\n")
                    sys.stdout.flush()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
