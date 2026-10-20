#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Fragment helper for the 5BSD seam tests (quotas.sh).
#
#   quota_frags.py SRC DST COUNT
#	Send COUNT IPv4 first fragments (UDP, more-fragments set, offset 0)
#	from SRC to DST, each with its own IP id and never completed, so a
#	reassembling pf at DST holds one fragment entry for each until the
#	fragment timeout.  Prints "sent N".

import socket
import struct
import sys


def checksum(data):
    words = struct.unpack('!%dH' % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def head(src, dst, ident):
    # 24 bytes (a multiple of 8) of a 64-byte UDP datagram.
    payload = struct.pack('!HHHH', 42000, 42001, 64, 0) + b'Q' * 16
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload),
                         ident, 0x2000, 64, socket.IPPROTO_UDP, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return header + payload


def main():
    if len(sys.argv) != 4:
        print("usage: quota_frags.py SRC DST COUNT", file=sys.stderr)
        return 2
    src, dst, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
    # FreeBSD's IPPROTO_RAW does not imply IP_HDRINCL (Linux's and
    # OpenBSD's do); the header is in network byte order.
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sent = 0
    for i in range(count):
        s.sendto(head(src, dst, 0x5b00 + i % 0xa000), (dst, 0))
        sent += 1
    s.close()
    print("sent %d" % sent)
    return 0


if __name__ == '__main__':
    sys.exit(main())
