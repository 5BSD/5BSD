#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Interleave equal-key IPv4/IPv6 fragments across PF input and output hooks."""
import argparse
import errno
import logging
from pathlib import Path
import socket
import struct


def checksum(data):
    words = struct.unpack('!%dH' % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def fragment(source, destination, marker, part, family='inet'):
    # A zero IPv4 UDP checksum lets the receiver detect mixed payloads itself.
    # Otherwise checksum rejection could hide the actual corruption mechanism.
    if family == 'inet6':
        # Reordering 16-bit words preserves the UDP checksum even if the
        # defective reassembler joins halves from different datagrams.
        payload = (b'ABCD' if marker == b'A' else b'CDAB') * 8
        source6 = socket.inet_pton(socket.AF_INET6, source)
        destination6 = socket.inet_pton(socket.AF_INET6, destination)
        body = struct.pack('!HHHH', 42000, 42001, 40, 0) + payload
        pseudo = source6 + destination6 + struct.pack('!I3xB', 40, socket.IPPROTO_UDP)
        value = checksum(pseudo + body) or 0xffff
        body = body[:6] + struct.pack('!H', value) + body[8:]
        field, payload = (1, body[:24]) if part == 'head' else (24, body[24:])
        extension = struct.pack('!BBHI', socket.IPPROTO_UDP, 0, field, 0x5bfd)
        header = struct.pack('!IHBB16s16s', 6 << 28, len(extension + payload),
                             socket.IPPROTO_FRAGMENT, 64, source6, destination6)
        return header + extension + payload
    body = struct.pack('!HHHH', 42000, 42001, 40, 0) + marker * 32
    offset, payload = (0x2000, body[:24]) if part == 'head' else (3, body[24:])
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload),
                         0x5bfd, offset, 64, socket.IPPROTO_UDP, 0,
                         socket.inet_aton(source), socket.inet_aton(destination))
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return header + payload


p = argparse.ArgumentParser(description=__doc__)
p.add_argument('mode', choices=['input', 'output', 'receive'])
p.add_argument('--family', choices=['inet', 'inet6'], default='inet')
p.add_argument('--source')
p.add_argument('--destination')
p.add_argument('--part', choices=['head', 'tail'])
p.add_argument('--interface')
p.add_argument('--mac')
p.add_argument('--ready', type=Path)
a = p.parse_args()
a.source = a.source or ('192.0.2.2' if a.family == 'inet' else '2001:db8:1::2')
a.destination = a.destination or ('198.51.100.2' if a.family == 'inet' else '2001:db8:2::2')
af = socket.AF_INET if a.family == 'inet' else socket.AF_INET6
if a.mode == 'receive':
    if a.ready is None:
        p.error('receive requires --ready')
    with socket.socket(af, socket.SOCK_DGRAM) as sock:
        sock.bind((a.destination, 42001))
        sock.settimeout(240)
        a.ready.touch()
        packets = [sock.recv(65535), sock.recv(65535)]
    expected = [b'A' * 32, b'B' * 32] if a.family == 'inet' else [b'ABCD' * 8, b'CDAB' * 8]
    assert sorted(packets) == expected, repr(packets)
    print('Two intact datagrams from opposite PF directions')
else:
    if a.part is None:
        p.error('send requires --part')
    packet = fragment(a.source, a.destination,
                      b'A' if a.mode == 'input' else b'B', a.part, a.family)
    if a.mode == 'input':
        if not a.interface or not a.mac:
            p.error('input requires interface and destination MAC')
        # BPF injection from the peer must enter the router's PF_IN hook.
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        from scapy.all import Ether, Raw, get_if_hwaddr, sendp
        sendp(Ether(src=get_if_hwaddr(a.interface), dst=a.mac, type=0x0800 if a.family == 'inet' else 0x86dd) / Raw(packet),
              iface=a.interface, verbose=False)
    else:
        # BPF injection here would bypass PF_OUT and invalidate the test.
        protocol = socket.IPPROTO_RAW if a.family == 'inet' else socket.IPPROTO_FRAGMENT
        with socket.socket(af, socket.SOCK_RAW, protocol) as sock:
            if a.family == 'inet':
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            else:
                # raw_ip6 supplies the IPv6 header with protocol 44. Supply
                # our fragment header and payload, preserving their ID/offset.
                sock.bind((a.source, 0))
                packet = packet[40:]
            try:
                sock.sendto(packet, (a.destination, 0))
            except PermissionError as error:
                if error.errno != errno.EACCES:
                    raise
                # Native PF may return DROP when consuming a fragment into
                # its reassembly queue. Do not confuse the socket status
                # with delivery: the receiver must still obtain both exact
                # complete datagrams, or this test fails.
                print('Raw output returned EACCES; complete delivery still required')
