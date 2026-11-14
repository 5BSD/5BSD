#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check split ELF debug links, CRCs and optional GNU build-ID pairing."""
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
        if name in ('.gnu_debuglink', '.debug_info', '.zdebug_info', '.symtab', '.note.gnu.build-id'):
            if name in result:
                raise ValueError('duplicate inspected section')
            if name == '.note.gnu.build-id' and entry[1] != 7:
                raise ValueError('GNU build-ID section must be a note')
            result[name] = payload(entry)
    return endian, result



def build_id(note, endian):
    """Read one GNU build-ID note without assuming its digest algorithm."""
    if len(note) < 20:
        raise ValueError('invalid GNU build-ID note')
    name_size, size, kind = struct.unpack_from(endian + 'III', note)
    if (name_size != 4 or kind != 3 or note[12:16] != b'GNU\0' or
            not size or len(note) != 16 + ((size + 3) & ~3) or
            any(note[16 + size:])):
        raise ValueError('invalid GNU build-ID note')
    return note[16:16 + size]


def verify(binary, debug, *, module=False, kernel=False, retain_symbols=False):
    if module and kernel:
        raise ValueError("choose kernel or module debug validation")
    if retain_symbols and (module or kernel):
        raise ValueError("choose ordinary retained-symbol, kernel or module validation")
    runtime = binary.read_bytes()
    symbols = debug.read_bytes()
    endian, runtime_sections = sections(runtime)
    debug_endian, debug_sections = sections(symbols)
    if runtime[:20] != symbols[:20] or endian != debug_endian:
        raise ValueError('debug ELF identity differs')
    if any(n in runtime_sections for n in ('.debug_info', '.zdebug_info')):
        raise ValueError('installed binary retains debug information')
    if module or kernel:
        allowed = (2,) if kernel else (1, 3)
        if struct.unpack_from(endian + 'H', runtime, 16)[0] not in allowed:
            raise ValueError('kernel must be executable ELF' if kernel else
                             'kernel module must be relocatable or shared ELF')
        if not runtime_sections.get('.symtab'):
            raise ValueError('kernel lacks its loader symbol table' if kernel else
                             'kernel module lacks its loader symbol table')
    elif retain_symbols:
        if not runtime_sections.get('.symtab'):
            raise ValueError('installed binary lacks its required static symbol table')
    elif '.symtab' in runtime_sections:
        raise ValueError('installed binary retains static symbol sections')
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
    note = '.note.gnu.build-id'
    identity = None
    if note in runtime_sections or note in debug_sections:
        if note not in runtime_sections or note not in debug_sections:
            raise ValueError('binary/debug GNU build-ID presence differs')
        identity = build_id(runtime_sections[note], endian)
        if identity != build_id(debug_sections[note], debug_endian):
            raise ValueError('binary/debug GNU build IDs differ')
    return {'binary': str(binary), 'debug': str(debug),
            'binary_sha256': hashlib.sha256(runtime).hexdigest(),
            'debug_sha256': hashlib.sha256(symbols).hexdigest(),
            'debuglink_crc32': expected, 'build_id': identity.hex() if identity is not None else None, 'status': 'passed'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--debug', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    kind = p.add_mutually_exclusive_group()
    kind.add_argument('--module', action='store_true', help='require the loader symbol table in a kernel module')
    kind.add_argument('--kernel', action='store_true', help='require executable ELF and the kernel loader symbol table')
    kind.add_argument('--retain-symbols', action='store_true', help='require an ordinary ELF artifact to retain its static symbol table')
    a = p.parse_args()
    result = verify(a.binary, a.debug, module=a.module, kernel=a.kernel, retain_symbols=a.retain_symbols)
    with a.output.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
