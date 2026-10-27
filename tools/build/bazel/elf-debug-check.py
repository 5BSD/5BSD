#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check an ELF GNU debug link against its separate debug file and CRC."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib


def sections(data):
    if data[:4] != b'\x7fELF' or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError('supported ELF encoding required')
    endian = '<' if data[5] == 1 else '>'
    is64 = data[4] == 2
    header = struct.unpack_from(endian + ('HHIQQQIHHHHHH' if is64 else 'HHIIIIIHHHHHH'), data, 16)
    offset, stride, count, strings = header[5], header[10], header[11], header[12]
    fmt = endian + ('IIQQQQIIQQ' if is64 else 'IIIIIIIIII')
    if not count or strings >= count or stride != struct.calcsize(fmt):
        raise ValueError('extended or invalid section table unsupported')
    if offset + stride * count > len(data):
        raise ValueError('truncated section table')
    entries = [struct.unpack_from(fmt, data, offset + i * stride) for i in range(count)]
    def payload(entry):
        start, size = entry[4:6]
        if start + size > len(data):
            raise ValueError('truncated section payload')
        return data[start:start + size]
    names = payload(entries[strings])
    result = {}
    for entry in entries:
        end = names.find(b'\0', entry[0])
        if end < 0:
            raise ValueError('invalid section name')
        name = names[entry[0]:end].decode('ascii')
        if name in ('.gnu_debuglink', '.debug_info', '.zdebug_info', '.symtab'):
            if name in result:
                raise ValueError('duplicate inspected section')
            result[name] = payload(entry)
    return endian, result


def verify(binary, debug):
    runtime = binary.read_bytes()
    symbols = debug.read_bytes()
    endian, runtime_sections = sections(runtime)
    debug_endian, debug_sections = sections(symbols)
    if runtime[:20] != symbols[:20] or endian != debug_endian:
        raise ValueError('debug ELF identity differs')
    if any(n in runtime_sections for n in ('.debug_info', '.zdebug_info', '.symtab')):
        raise ValueError('installed binary retains debug or static symbol sections')
    if not any(debug_sections.get(n) for n in ('.debug_info', '.zdebug_info')):
        raise ValueError('separate debug file lacks debug information')
    link = runtime_sections.get('.gnu_debuglink', b'')
    end = link.find(b'\0')
    if end <= 0 or link[:end].decode('utf-8') != debug.name:
        raise ValueError('debug link name differs')
    crc_offset = (end + 4) & ~3
    if len(link) != crc_offset + 4:
        raise ValueError('invalid debug link size')
    expected = struct.unpack_from(endian + 'I', link, crc_offset)[0]
    if expected != zlib.crc32(symbols):
        raise ValueError('debug link CRC differs')
    return {'binary': str(binary), 'debug': str(debug),
            'binary_sha256': hashlib.sha256(runtime).hexdigest(),
            'debug_sha256': hashlib.sha256(symbols).hexdigest(),
            'debuglink_crc32': expected, 'status': 'passed'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--debug', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = verify(a.binary, a.debug)
    with a.output.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
