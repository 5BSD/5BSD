#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Audit Ethernet captures of the unchanged pf_fragment/frag6_ext.py fixture.

The echo-only fixture can pass while extra malformed packets are emitted.
Require exactly two ICMPv6 fragments per tested flow, its exact payload,
and no other fragment next-header values. No timing measurements are used.
"""
import argparse
import collections
import ipaddress
import json
from pathlib import Path
import struct


def audit(raw, expected_flows):
    magic = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
             b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
    if len(raw) < 24 or raw[:4] not in magic:
        raise ValueError('not a supported pcap file')
    endian = magic[raw[:4]]
    if struct.unpack_from(endian + 'I', raw, 20)[0] != 1:
        raise ValueError('Ethernet capture required')
    pos = 24
    flows = collections.defaultdict(list)
    invalid = []
    frames = 0
    while pos < len(raw):
        if len(raw) - pos < 16:
            raise ValueError('truncated pcap record header')
        _, _, cap, wire = struct.unpack_from(endian + 'IIII', raw, pos)
        pos += 16
        pkt = raw[pos:pos + cap]
        pos += cap
        if len(pkt) != cap or cap < wire:
            raise ValueError('truncated captured packet')
        frames += 1
        if len(pkt) < 14:
            raise ValueError('short Ethernet header')
        etype = struct.unpack_from('!H', pkt, 12)[0]
        off = 14
        while etype in (0x8100, 0x88a8):
            if len(pkt) < off + 4:
                raise ValueError('short VLAN header')
            etype = struct.unpack_from('!H', pkt, off + 2)[0]
            off += 4
        if etype != 0x86dd:
            continue
        ip = pkt[off:]
        if len(ip) < 40:
            raise ValueError('short IPv6 header')
        plen = struct.unpack_from('!H', ip, 4)[0]
        if len(ip) < 40 + plen:
            raise ValueError('short IPv6 payload')
        ip = ip[:40 + plen]
        if ip[6] != 0:
            continue
        if len(ip) < 48:
            raise ValueError('short hop-by-hop header')
        hlen = (ip[41] + 1) * 8
        if ip[40] != 44:
            continue
        off = 40 + hlen
        if len(ip) < off + 8:
            raise ValueError('short fragment header')
        nh, reserved, flags, fid = struct.unpack_from('!BBHI', ip, off)
        if nh != 58:
            invalid.append({'frame': frames, 'next_header': nh})
            continue
        key = (str(ipaddress.IPv6Address(ip[8:24])),
               str(ipaddress.IPv6Address(ip[24:40])), fid)
        flows[key].append({'offset': flags & 0xfff8, 'more': flags & 1,
                           'reserved': reserved | (flags & 6),
                           'payload': ip[off + 8:]})
    checked = []
    for (src, dst, fid), fragments in sorted(flows.items()):
        fragments.sort(key=lambda f: f['offset'])
        data = b''.join(f['payload'] for f in fragments)
        valid = (len(fragments) == 2 and
                 [(f['offset'], f['more'], len(f['payload']), f['reserved'])
                  for f in fragments] == [(0, 1, 16, 0), (16, 0, 8, 0)] and
                 len(data) == 24 and data[:2] == b'\x80\0' and
                 data[8:] == b'ABCDEFGHIJKLOMNO')
        checked.append({'src': src, 'dst': dst, 'id': fid,
                        'fragments': len(fragments), 'valid': valid})
    return {'expected_flows': expected_flows, 'flows': checked,
            'non_icmp6_fragment_headers': invalid,
            'accounting_pass': len(checked) == expected_flows and
            all(f['valid'] for f in checked) and not invalid}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('pcap', type=Path)
    p.add_argument('--expected-flows', type=int, default=3)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    try:
        result = audit(args.pcap.read_bytes(), args.expected_flows)
    except ValueError as error:
        p.error(str(error))
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')
    return 0 if result['accounting_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
