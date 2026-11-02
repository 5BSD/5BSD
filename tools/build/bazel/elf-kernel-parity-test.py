#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare complete linked kernels under identical declared compiler inputs.

The Make control must use the same source filename/config/version policy. This
migration test never edits an ELF payload. GNU build identities are reported
separately because differing nonallocated debug inputs legitimately change them.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def read_elf(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('ELF64 little-endian kernel required')
    header = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    if header[0] != 2 or header[10] != 64 or not header[11] or header[12] >= header[11]:
        raise ValueError('ordinary executable kernel section table required')
    entries = [struct.unpack_from('<IIQQQQIIQQ', data, header[5] + i * 64)
               for i in range(header[11])]
    names_entry = entries[header[12]]
    names = data[names_entry[4]:names_entry[4] + names_entry[5]]
    sections, payloads, index_names = {}, {}, []
    for entry in entries:
        name = names[entry[0]:names.index(0, entry[0])].decode('ascii')
        index_names.append(name)
        if not name:
            continue
        if name in sections:
            raise ValueError('duplicate kernel section: ' + name)
        blob = b'' if entry[1] == 8 else data[entry[4]:entry[4] + entry[5]]
        if entry[1] != 8 and len(blob) != entry[5]:
            raise ValueError('truncated kernel section')
        sections[name] = dict(type=entry[1], flags=entry[2], address=entry[3],
                              size=entry[5], alignment=entry[8], entry_size=entry[9],
                              sha256=hashlib.sha256(blob).hexdigest())
        payloads[name] = blob
    note = payloads.get('.note.gnu.build-id', b'')
    if len(note) != 36 or struct.unpack_from('<III', note) != (4, 20, 3) or note[12:16] != b'GNU\0':
        raise ValueError('SHA-1 GNU kernel build identity required')
    symbols, files = [], []
    for entry in entries:
        if entry[1] != 2:
            continue
        if entry[9] != 24 or entry[5] % 24:
            raise ValueError('ordinary kernel symbol table required')
        names_entry = entries[entry[6]]
        symbol_names = data[names_entry[4]:names_entry[4] + names_entry[5]]
        for at in range(entry[4], entry[4] + entry[5], 24):
            offset, info, other, section, value, size = struct.unpack_from('<IBBHQQ', data, at)
            name = symbol_names[offset:symbol_names.index(0, offset)].decode('utf-8')
            section_name = index_names[section] if section < len(index_names) else str(section)
            if info & 15 == 4:
                files.append(name)
            else:
                symbols.append((name, info, other, section_name, value, size))
    if not symbols:
        raise ValueError('kernel loader symbol table required')
    return dict(identity=data[:20].hex(), entry=header[3], sections=sections,
                payloads=payloads, build_id=note[16:].hex(), symbols=sorted(symbols),
                file_symbols=files, sha256=hashlib.sha256(data).hexdigest())


def compare(native, control):
    if native['identity'] != control['identity'] or native['entry'] != control['entry']:
        raise ValueError('kernel ELF identity or entry differs')
    left = {n: dict(v) for n, v in native['sections'].items() if v['flags'] & 2}
    right = {n: dict(v) for n, v in control['sections'].items() if v['flags'] & 2}
    # Each note's type/name/length was validated independently. All section
    # metadata remains strict; only its content identity is reported separately.
    for sections in (left, right):
        sections['.note.gnu.build-id'].pop('sha256')
    different = [n for n in sorted(left.keys() | right.keys()) if left.get(n) != right.get(n)]
    if different:
        raise ValueError('allocated kernel sections differ: ' + ', '.join(different))
    if native['symbols'] != control['symbols']:
        raise ValueError('kernel loader symbol identities differ')
    if not native['payloads'].get('.SUNW_ctf') or native['payloads']['.SUNW_ctf'] != control['payloads'].get('.SUNW_ctf'):
        raise ValueError('merged kernel CTF differs')
    return dict(status='passed', allocated_sections=len(left),
                loader_symbols=len(native['symbols']), ctf_bytes_exact=True,
                native_sha256=native['sha256'], control_sha256=control['sha256'],
                native_build_id=native['build_id'], control_build_id=control['build_id'],
                native_file_symbols=native['file_symbols'], control_file_symbols=control['file_symbols'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--make-control', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    native, control = read_elf(args.native), read_elf(args.make_control)
    try:
        result = compare(native, control)
    except ValueError as error:
        args.output.write_text(json.dumps(dict(status='rejected', diagnostic=str(error)), indent=2) + '\n')
        raise
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('Allocated kernel sections, loader symbols and merged CTF match Make control')


if __name__ == '__main__':
    main()
