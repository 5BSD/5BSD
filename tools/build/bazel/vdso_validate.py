#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Validate a compact, self-contained ELF64 VDSO and derive its symbol offset.

Policy values are target inputs. Offsets come from the supplied target ELF,
never fixed addresses. ELF constants follow sys/sys/elf_common.h.
"""
import argparse
from pathlib import Path
import re
import struct


def inspect(blob, *, machine, osabi, maximum_size, symbol, soname):
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    def region(offset, size):
        require(0 <= offset <= len(blob) and 0 <= size <= len(blob) - offset,
                'ELF range outside image')
        return blob[offset:offset + size]

    def unpack(fmt, offset):
        return struct.unpack(fmt, region(offset, struct.calcsize(fmt)))

    def string(table, offset):
        require(0 <= offset < len(table), 'string offset outside table')
        end = table.find(b'\0', offset)
        require(end >= 0, 'unterminated ELF string')
        return table[offset:end]

    require(0 < maximum_size and 64 <= len(blob) <= maximum_size,
            'VDSO size outside target limit')
    require(blob[:7] == b'\x7fELF\x02\x01\x01' and blob[7] == osabi,
            'unsupported ELF identity')
    h = unpack('<HHIQQQIHHHHHH', 16)
    kind, arch, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = h
    require((kind, arch, version, entry, flags, ehsize) == (3, machine, 1, 0, 0, 64),
            'unsupported VDSO ELF header')
    require(phsize == 56 and 0 < phnum < 0xffff and shsize == 64 and
            0 < shnum < 0xff00 and 0 < shstr < shnum,
            'unsupported ELF table layout')
    region(phoff, phsize * phnum)
    region(shoff, shsize * shnum)
    programs = [unpack('<IIQQQQQQ', phoff + phsize * i) for i in range(phnum)]
    require(all(p[0] in (1, 2, 0x6474e550) for p in programs),
            'unsupported VDSO program segment')
    for program in programs:
        region(program[2], program[5])
    loads = [p for p in programs if p[0] == 1]
    dynamics = [p for p in programs if p[0] == 2]
    require(len(loads) == len(dynamics) == 1, 'VDSO needs one LOAD and DYNAMIC segment')
    load = loads[0]
    require(load[1] == 5 and load[2] == load[3] == load[4] == 0 and
            load[5] == load[6] and load[5] >= phoff + phsize * phnum,
            'VDSO LOAD must be read/execute, based at zero, without BSS')
    region(load[2], load[5])
    dynamic = dynamics[0]
    require(dynamic[1] == 5 and dynamic[2] == dynamic[3] == dynamic[4] and
            dynamic[5] == dynamic[6] and dynamic[5] > 0 and dynamic[5] % 16 == 0 and
            dynamic[2] + dynamic[5] <= load[5], 'invalid dynamic segment')
    tags = {}
    terminated = False
    for offset in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = unpack('<qQ', offset)
        if tag == 0:
            require(value == 0, 'invalid DT_NULL')
            terminated = True
            continue
        require(not terminated, 'dynamic entry after DT_NULL')
        require(tag not in tags, 'duplicate dynamic tag')
        tags[tag] = value
    require(terminated, 'unterminated dynamic table')
    require(1 not in tags, 'VDSO must not need a shared library')
    require(22 not in tags and not tags.get(30, 0) & 4,
            'VDSO must not require text relocations')
    require(not any(tags.get(t, 0) for t in (2, 8, 18, 35, 0x6ffffff9, 0x6ffffffa)),
            'VDSO must not contain runtime relocations')
    sections = [unpack('<IIQQQQIIQQ', shoff + shsize * i) for i in range(shnum)]
    require(sections[0] == (0,) * 10, 'invalid null section')
    for section in sections[1:]:
        if section[1] != 8:
            region(section[4], section[5])
        else:
            require(section[5] == 0, 'VDSO must not contain nonempty NOBITS')
        if section[2] & 2:
            require(not section[2] & 1 and section[3] == section[4] and
                    section[3] + section[5] <= load[6], 'invalid allocated section')
        require(not (section[1] in (4, 9, 19) and section[5]),
                'VDSO must not contain relocation sections')
    symbols = [s for s in sections if s[1] == 11]
    require(len(symbols) == 1, 'VDSO needs exactly one dynamic symbol table')
    table = symbols[0]
    require(table[9] == 24 and table[5] % 24 == 0 and 0 < table[6] < shnum,
            'invalid dynamic symbol table')
    strings = sections[table[6]]
    require(table[2] == 2 and strings[2] == 2, 'dynamic metadata must be allocated read-only')
    dynamic_sections = [sec for sec in sections if sec[1] == 6]
    require(len(dynamic_sections) == 1 and dynamic_sections[0][2] == 2 and
            dynamic_sections[0][3:6] == (dynamic[3], dynamic[2], dynamic[5]) and
            dynamic_sections[0][6] == table[6], 'dynamic section disagrees with segment')
    require(strings[1] == 3, 'invalid dynamic string table')
    names = region(strings[4], strings[5])
    require(tags.get(5) == strings[3] and tags.get(10) == len(names) and
            tags.get(6) == table[3] and tags.get(11) == 24,
            'dynamic pointers disagree with section tables')
    require(14 in tags and string(names, tags[14]) == soname.encode(),
            'unexpected VDSO SONAME')
    matches = []
    for offset in range(table[4], table[4] + table[5], 24):
        name, info, other, index, value, size = unpack('<IBBHQQ', offset)
        label = string(names, name)
        require(not (index == 0 and label), 'undefined VDSO dynamic symbol')
        if label == symbol.encode():
            require(info == 0x12 and other == 0 and 0 < index < shnum,
                    'VDSO entry must be a defined global default-visible function')
            section = sections[index]
            require(section[2] & 6 == 6 and size > 0 and
                    section[3] <= value and value + size <= section[3] + section[5],
                    'VDSO entry outside executable section')
            matches.append(value)
    require(len(matches) == 1, 'missing or duplicate VDSO entry symbol')
    return matches[0]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--src', required=True, type=Path)
    p.add_argument('--image', required=True, type=Path)
    p.add_argument('--header', required=True, type=Path)
    p.add_argument('--maximum-size', required=True, type=int)
    p.add_argument('--machine', required=True, type=int)
    p.add_argument('--osabi', required=True, type=int)
    p.add_argument('--symbol', required=True)
    p.add_argument('--macro', required=True)
    p.add_argument('--soname', required=True)
    a = p.parse_args()
    try:
        if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', a.macro):
            raise ValueError('invalid header macro')
        if a.src.stat().st_size > a.maximum_size:
            raise ValueError('VDSO exceeds target size limit')
        blob = a.src.read_bytes()
        offset = inspect(blob, machine=a.machine, osabi=a.osabi,
                         maximum_size=a.maximum_size, symbol=a.symbol, soname=a.soname)
        a.image.write_bytes(blob)
        a.header.write_text(f'#define {a.macro} 0x{offset:016x}\n', encoding='ascii')
    except (OSError, ValueError, struct.error) as error:
        p.exit(1, f'vdso_validate: {error}\n')


if __name__ == '__main__':
    main()
