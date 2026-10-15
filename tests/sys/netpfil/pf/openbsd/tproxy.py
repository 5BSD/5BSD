#!/usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# Transparent proxy for the pf divert-to tests.  TCP: accept connections
# on the divert address and answer an HTTP request with the original
# destination, read with getsockname(2).  UDP: answer each datagram with
# the original destination address and port, read with IP_RECVDSTADDR /
# IP_RECVDSTPORT (IPV6_PKTINFO / IPV6_RECVDSTPORT for IPv6).

import socket
import struct
import sys

IP_RECVDSTADDR = 7
IP_RECVDSTPORT = 33
IPV6_RECVPKTINFO = 36
IPV6_PKTINFO = 46
IPV6_RECVDSTPORT = 76


def tcp(addr, port, count):
    fam = socket.AF_INET6 if ':' in addr else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(8)
    print('READY', flush=True)
    for _ in range(count):
        c, peer = s.accept()
        req = b''
        while b'\r\n\r\n' not in req:
            d = c.recv(4096)
            if not d:
                break
            req += d
        orig = c.getsockname()
        body = 'origdst=%s port=%d peer=%s\n' % (orig[0], orig[1], peer[0])
        c.sendall(('HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s' %
                   (len(body), body)).encode())
        c.close()


def udp(addr, port, count):
    v6 = ':' in addr
    fam = socket.AF_INET6 if v6 else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    if v6:
        s.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)
        s.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVDSTPORT, 1)
    else:
        s.setsockopt(socket.IPPROTO_IP, IP_RECVDSTADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, IP_RECVDSTPORT, 1)
    s.bind((addr, port))
    print('READY', flush=True)
    for _ in range(count):
        data, anc, _flags, peer = s.recvmsg(2048, 1024)
        daddr, dport = None, None
        for level, typ, cdata in anc:
            if not v6 and level == socket.IPPROTO_IP and typ == IP_RECVDSTADDR:
                daddr = socket.inet_ntop(socket.AF_INET, cdata[:4])
            elif v6 and level == socket.IPPROTO_IPV6 and typ == IPV6_PKTINFO:
                daddr = socket.inet_ntop(socket.AF_INET6, cdata[:16])
            elif typ in (IP_RECVDSTPORT, IPV6_RECVDSTPORT):
                dport = struct.unpack('!H', cdata[:2])[0]
        # Reply from the original destination (needs SO_BINDANY).
        r = socket.socket(fam, socket.SOCK_DGRAM)
        r.setsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_BINDANY', 0x20000000), 1)
        r.bind((daddr, dport))
        r.sendto(('origdst=%s port=%d\n' % (daddr, dport)).encode(), peer[:2])
        r.close()


if __name__ == '__main__':
    proto, addr, port, count = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    (tcp if proto == 'tcp' else udp)(addr, port, count)
