# SPDX-License-Identifier: BSD-2-Clause
"""Exact allocated ELF32/ELF64 object data and symbolic relocation contracts.

No binary bytes or relocation addends are normalized. Symbol indices are resolved
through their actual symbol/string tables; debug-only sections are outside scope.
"""
import hashlib
import json
import struct


def contract(data, *, allow_duplicate_sections=False):
    # Partial links can retain multiple sections with the same name. Preserve
    # their occurrence identity for both payloads and symbol/relocation bindings;
    # never merge or discard them. Existing callers retain strict name uniqueness.
    if type(allow_duplicate_sections) is not bool:
        raise ValueError('duplicate-section selection must be a bool')
    if data[:4] != b'\x7fELF' or data[4:6] not in (b'\x01\x01', b'\x02\x01'):
        raise ValueError('ELF32/ELF64 little-endian object required')
    wide = data[4] == 2

    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError('ELF record exceeds file')
        return struct.unpack_from(fmt, data, offset)

    header = unpack('<16sHHIQQQIHHHHHH' if wide else '<16sHHIIIIIHHHHHH', 0)
    if header[1] != 1:
        raise ValueError('relocatable ELF object required')
    section_format = '<IIQQQQIIQQ' if wide else '<IIIIIIIIII'
    if header[11] != struct.calcsize(section_format) or not 0 < header[13] < header[12]:
        raise ValueError('unsupported ELF section table')
    sections = [unpack(section_format, header[6] + i * header[11]) for i in range(header[12])]

    def payload(section):
        offset, size = section[4:6]
        if offset + size > len(data):
            raise ValueError('ELF section exceeds file')
        return data[offset:offset + size]

    def text(strings, offset):
        if offset >= len(strings):
            raise ValueError('ELF string offset exceeds table')
        end = strings.find(b'\0', offset)
        if end < 0:
            raise ValueError('unterminated ELF string')
        return strings[offset:end].decode('utf-8')

    names = payload(sections[header[13]])
    section_names = [text(names, section[0]) for section in sections]
    if allow_duplicate_sections:
        occurrences = {}
        identities = []
        for name in section_names:
            ordinal = occurrences.get(name, 0)
            occurrences[name] = ordinal + 1
            identities.append(json.dumps([name, ordinal], separators=(',', ':')))
        section_names = identities

    def symbol(table, index):
        fmt = '<IBBHQQ' if wide else '<IIIBBH'
        if table[9] != struct.calcsize(fmt) or (index + 1) * table[9] > table[5]:
            raise ValueError('invalid ELF symbol reference')
        values = unpack(fmt, table[4] + index * table[9])
        name, info, other, section, value, size = values if wide else (values[0], values[3], values[4], values[5], values[1], values[2])
        return dict(name=text(payload(sections[table[6]]), name), info=info, other=other,
                    section=section_names[section] if 0 < section < len(sections) else section,
                    value=value, size=size)

    allocated, relocations, external = {}, {}, []
    for name, section in zip(section_names, sections):
        if section[2] & 2:
            if name in allocated:
                raise ValueError('duplicate allocated ELF section name')
            allocated[name] = dict(type=section[1], flags=section[2], size=section[5], alignment=section[8],
                                   sha256=None if section[1] == 8 else hashlib.sha256(payload(section)).hexdigest())
        if section[1] == 2:
            if not section[9] or section[5] % section[9]:
                raise ValueError('invalid ELF symbol table size')
            for index in range(section[5] // section[9]):
                entry = symbol(section, index)
                if entry['info'] >> 4 in (1, 2):
                    external.append(entry)
        if section[1] not in (4, 9):
            continue
        if section[7] >= len(sections) or section[6] >= len(sections):
            raise ValueError('invalid ELF relocation section reference')
        if not sections[section[7]][2] & 2:
            continue
        fmt = ('<QQq' if wide else '<IIi') if section[1] == 4 else ('<QQ' if wide else '<II')
        if section[9] != struct.calcsize(fmt) or section[5] % section[9]:
            raise ValueError('invalid ELF relocation table size')
        if name in relocations:
            raise ValueError('duplicate ELF relocation section name')
        records = []
        for offset in range(section[4], section[4] + section[5], section[9]):
            values = unpack(fmt, offset)
            records.append(dict(offset=values[0], kind=values[1] & (0xffffffff if wide else 0xff),
                                addend=values[2] if section[1] == 4 else None,
                                symbol=symbol(sections[section[6]], values[1] >> (32 if wide else 8))))
        relocations[name] = dict(target=section_names[section[7]], records=records)
    return dict(identity=dict(elf_class=data[4], machine=header[2], version=header[3], ident_version=data[6], osabi=data[7], abi_version=data[8], flags=header[7]),
                allocated=allocated, relocations=relocations,
                external=sorted(external, key=lambda entry: tuple(str(entry[key]) for key in sorted(entry))))
