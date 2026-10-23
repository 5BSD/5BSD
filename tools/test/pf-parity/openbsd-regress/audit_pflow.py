#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check pflow exports against saved loopback packets, without changing fixtures.

Supports the DLT_NULL (5BSD) and DLT_LOOP=12 (OpenBSD) captures produced by
this harness. An accounting pass is not an upstream fixture pass: preserve
FIXTURE_EXIT independently. This is a packet-counter check, not a benchmark.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import struct


def audit(capture, output, family):
    raw = capture.read_bytes()
    if len(raw) < 24 or raw[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        raise ValueError('unsupported or truncated pcap header')
    endian = '<' if raw[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    linktype = struct.unpack_from(endian + 'I', raw, 20)[0]
    if linktype not in (0, 12, 108):
        raise ValueError('expected a 5BSD/OpenBSD loopback capture')
    totals = defaultdict(lambda: {'packets': 0, 'octets': 0, 'syn_lengths': [],
                                  'packet_lengths': []})
    off = 24
    while off < len(raw):
        if len(raw) - off < 16:
            raise ValueError('truncated packet record')
        _, _, caplen, wirelen = struct.unpack_from(endian + 'IIII', raw, off)
        off += 16
        if caplen != wirelen or caplen > len(raw) - off or caplen < 24:
            raise ValueError('truncated captured packet')
        ip = raw[off + 4:off + caplen]
        off += caplen
        if ip[0] >> 4 != family:
            raise ValueError('unexpected IP family')
        if family == 4:
            hlen = (ip[0] & 15) * 4
            size = struct.unpack_from('!H', ip, 2)[0]
            proto = ip[9]
        else:
            if len(ip) < 40:
                raise ValueError('truncated IPv6 header')
            hlen = 40
            size = 40 + struct.unpack_from('!H', ip, 4)[0]
            proto = ip[6]
        if proto != 6 or hlen < 20 or size != len(ip) or size < hlen + 20:
            raise ValueError('expected a complete TCP packet without extension headers')
        sport, dport = struct.unpack_from('!HH', ip, hlen)
        if {sport, dport} != {12345, 12346}:
            raise ValueError('unexpected fixture TCP ports')
        record = totals[str(sport)]
        record['packets'] += 1
        record['octets'] += size
        record['packet_lengths'].append(size)
        if ip[hlen + 13] & 2:
            record['syn_lengths'].append(size)
    text = output.read_text()
    records = []
    # The first four blocks are the unmodified flow.pl output. A subsequent
    # diff may repeat lines with +/- prefixes and must not count as evidence.
    for block in text.split('12 elements')[1:5]:
        fields = dict(re.findall(
            r'^(packetDeltaCount|octetDeltaCount|sourceTransportPort): ([0-9a-f]+)$',
            block, re.MULTILINE))
        if len(fields) != 3:
            raise ValueError('missing export fields')
        fields = {k: int(v, 16) for k, v in fields.items()}
        actual = totals.get(str(fields['sourceTransportPort']))
        if actual is None or (fields['packetDeltaCount'], fields['octetDeltaCount']) != (
                actual['packets'], actual['octets']):
            raise ValueError('pflow counters disagree with captured packets')
        records.append(fields)
    if len(records) != 4 or sorted(r['sourceTransportPort'] for r in records) != [12345, 12345, 12346, 12346]:
        raise ValueError('expected four exports, two for each direction')
    marker = re.search(r'^FIXTURE_EXIT=(\d+)$', text, re.MULTILINE)
    return {'accounting_pass': True, 'family': family, 'pcap_linktype': linktype,
            'strict_fixture_exit': int(marker[1]) if marker else None,
            'totals': dict(totals), 'export_records_checked': len(records)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--family', type=int, choices=(4, 6), required=True)
    args = parser.parse_args()
    try:
        result = audit(args.capture, args.output, args.family)
    except (ValueError, OSError, struct.error) as error:
        parser.exit(1, str(error) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
