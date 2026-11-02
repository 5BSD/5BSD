#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inventory emitted DOF provider/probe schemas and site offsets in linked ELF.

This checks metadata coverage, not loader registration or live probe firing.
Unsupported ELF/DOF layouts fail explicitly.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import struct
import subprocess


class RelocatableDof:
    """Resolve amd64 ET_REL DOF sites against actual function symbols and bytes."""
    def __init__(self, path, symbols=None):
        self.object = self.read(path)
        self.symbols = self.object if symbols is None else self.read(symbols)
        self.bindings = []

    @staticmethod
    def read(path):
        data = path.read_bytes()
        if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
            raise ValueError('relocatable metadata requires ELF64 little-endian input')
        h = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
        if h[0] != 1 or h[1] != 62 or h[10] != 64 or not h[11] or h[12] >= h[11] or h[5] + h[10] * h[11] > len(data):
            raise ValueError('relocatable metadata requires bounded amd64 ET_REL sections')
        sections = [struct.unpack_from('<IIQQQQIIQQ', data, h[5] + n * 64) for n in range(h[11])]
        def payload(index):
            if index >= len(sections):
                raise ValueError('invalid ELF section reference')
            s = sections[index]
            if s[1] == 8 or s[4] + s[5] > len(data):
                raise ValueError('invalid ELF section payload')
            return data[s[4]:s[4] + s[5]]
        def string(table, index):
            end = table.find(b'\0', index)
            if index >= len(table) or end < 0:
                raise ValueError('invalid ELF string')
            return table[index:end].decode('utf-8')
        names = payload(h[12])
        section_names = [string(names, s[0]) for s in sections]
        tables = {}
        for index, section in enumerate(sections):
            if section[1] != 2:  # SHT_SYMTAB
                continue
            if section[9] != 24 or section[5] % 24:
                raise ValueError('unsupported ELF symbol table')
            table, strings = payload(index), payload(section[6])
            entries = []
            for pos in range(0, len(table), 24):
                name, info, other, target, value, size = struct.unpack_from('<IBBHQQ', table, pos)
                entries.append({'name': string(strings, name), 'binding': info >> 4,
                    'type': info & 15, 'visibility': other & 3, 'section': target,
                    'value': value, 'size': size})
            tables[index] = entries
        relocations = {}
        for index, section in enumerate(sections):
            if section[1] not in (4, 9) or section[7] >= len(sections) or sections[section[7]][1] != 0x6ffffff4:
                continue
            if section[1] != 4 or section[9] != 24 or section[5] % 24 or section[6] not in tables:
                raise ValueError('unsupported DOF ELF relocation table')
            raw = payload(index)
            for pos in range(0, len(raw), 24):
                offset, info, addend = struct.unpack_from('<QQq', raw, pos)
                symbols = tables[section[6]]
                if info >> 32 >= len(symbols) or offset + 8 > sections[section[7]][5]:
                    raise ValueError('invalid DOF ELF relocation reference')
                key = (section[7], offset)
                if key in relocations:
                    raise ValueError('duplicate DOF ELF relocation')
                relocations[key] = {'kind': info & 0xffffffff, 'addend': addend,
                    'symbol': symbols[info >> 32], 'section': index, 'offset': pos}
        return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(),
            'data': data, 'sections': sections, 'section_names': section_names,
            'tables': tables, 'relocations': relocations}

    def resolve(self, section, offset, function, user_kind, ordinary, enabled):
        relocation = self.object['relocations'].get((section, offset))
        if relocation is None:
            raise ValueError('probe lacks a DOF ELF relocation')
        if (relocation['kind'], user_kind) not in ((24, 2), (1, 1)) or relocation['addend']:
            raise ValueError('unsupported DOF ELF/user relocation semantics')
        reference = relocation['symbol']
        owner = self.symbols if reference['section'] == 0 else self.object
        alias = re.fullmatch(r'\$dtrace([0-9]+)\.(.+)', reference['name'])
        if alias is None or alias[2] != function:
            raise ValueError('DOF relocation does not name its actual function alias')
        matches = [symbol for table in owner['tables'].values() for symbol in table
                   if symbol['name'] == reference['name'] and symbol['section'] not in (0, 0xfff1)]
        if len(matches) != 1:
            raise ValueError('DOF function requires one defined matching object symbol')
        symbol = matches[0]
        if symbol['type'] != 2 or symbol['binding'] != 1 or symbol['visibility'] != 2 or not symbol['size'] or symbol['section'] >= len(owner['sections']):
            raise ValueError('DOF function alias lacks a bounded hidden global FUNC definition')
        code = owner['sections'][symbol['section']]
        if code[1] == 8 or not code[2] & 4 or symbol['value'] + symbol['size'] > code[5] or code[4] + code[5] > len(owner['data']):
            raise ValueError('DOF function exceeds its executable section')
        start = code[4] + symbol['value']
        data = owner['data'][start:start + symbol['size']]
        for site in ordinary:
            if site + 5 > len(data) or data[site] not in (0x90, 0xc3) or data[site + 1:site + 5] != b'\x90' * 4:
                raise ValueError('relocatable ordinary site lacks bounded NOP/RET patch')
        for site in enabled:
            if site < 3 or site + 2 > len(data) or data[site - 3:site] != b'\x48\x33\xc0' or data[site] not in (0x90, 0xc3) or data[site + 1] != 0x90:
                raise ValueError('relocatable enabled site lacks bounded XOR/NOP patch')
        self.bindings.append({'dof_section': section, 'dof_offset': offset,
            'elf_relocation_kind': relocation['kind'], 'user_relocation_kind': user_kind,
            'addend': relocation['addend'], 'symbol': symbol,
            'symbol_source_sha256': owner['sha256'],
            'code_section': owner['section_names'][symbol['section']],
            'function_sha256': hashlib.sha256(data).hexdigest(),
            'ordinary_offsets': ordinary, 'enabled_offsets': enabled})
        return symbol['value']


def inventory(path, relocatable=False, symbols=None):
    data = path.read_bytes()
    if data[:4] != b'\x7fELF' or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError('supported ELF encoding required')
    endian = '<' if data[5] == 1 else '>'
    header = struct.unpack_from(endian + ('HHIQQQIHHHHHH' if data[4] == 2 else 'HHIIIIIHHHHHH'), data, 16)
    resolver = RelocatableDof(path, symbols) if relocatable else None
    if not relocatable and header[0] not in (2, 3):
        raise ValueError('linked executable or shared ELF required')
    offset, stride, count = header[5], header[10], header[11]
    fmt = endian + ('IIQQQQIIQQ' if data[4] == 2 else 'IIIIIIIIII')
    if not count or stride != struct.calcsize(fmt) or offset + stride * count > len(data):
        raise ValueError('invalid/extended section table unsupported')
    providers, probes, records = [], [], 0
    for i in range(count):
        section = struct.unpack_from(fmt, data, offset + i * stride)
        if section[1] != 0x6ffffff4:  # SHT_SUNW_dof, sys/elf_common.h
            continue
        start, size = section[4:6]
        if start + size > len(data):
            raise ValueError('truncated ELF DOF section')
        payload = data[start:start + size]
        cursor = 0
        while cursor < len(payload):
            if not any(payload[cursor:]):
                break
            if payload[cursor:cursor + 4] != b'\x7fDOF' or len(payload) - cursor < 64:
                raise ValueError('invalid DOF record boundary')
            ident = payload[cursor:cursor + 16]
            if ident[4] not in (1, 2) or ident[5] not in (1, 2) or ident[6] not in (1, 2):
                raise ValueError('unsupported DOF model/encoding/version')
            order = '<' if ident[5] == 1 else '>'
            flags, hdrsize, secsize, secnum, secoff, loadsz, filesz, pad = struct.unpack_from(order + '4I4Q', payload, cursor + 16)
            if flags or pad or hdrsize != 64 or secsize != 32 or not secnum or not (hdrsize <= loadsz <= filesz <= len(payload) - cursor) or secoff + secsize * secnum > filesz:
                raise ValueError('invalid DOF header')
            record = payload[cursor:cursor + filesz]
            sections = [struct.unpack_from(order + '4I2Q', record, secoff + n * secsize) for n in range(secnum)]
            def content(index, kind):
                if index >= secnum:
                    raise ValueError('invalid DOF section reference')
                s = sections[index]
                if s[0] != kind or s[4] + s[5] > filesz:
                    raise ValueError('wrong/truncated DOF section type')
                return record[s[4]:s[4] + s[5]]
            # Apply the user relocation semantics used by dtrace_dof_relocate.
            # ELF virtual load bias is zero for this offline address comparison.
            relocations = {}
            relocation_kinds = {}
            for ri, rs in enumerate(sections):
                if rs[0] != 12:  # DOF_SECT_URELHDR
                    continue
                rh = content(ri, 12)
                if len(rh) != 12:
                    raise ValueError('unsupported DOF relocation header')
                strings_index, table_index, target_index = struct.unpack(order + '3I', rh)
                content(strings_index, 8)
                table = content(table_index, 10)
                if target_index >= secnum or sections[table_index][3] != 24 or len(table) % 24:
                    raise ValueError('invalid DOF relocation table')
                target = sections[target_index]
                for ro in range(0, len(table), 24):
                    name, kind, position, extra = struct.unpack_from(order + '2I2Q', table, ro)
                    if kind == 0:
                        continue
                    if kind not in (1, 2) or position + 8 > target[5] or target[4] + position + 8 > filesz:
                        raise ValueError('unsupported/invalid DOF address relocation')
                    key = (target_index, position)
                    if key in relocations:
                        raise ValueError('duplicate DOF address relocation')
                    relocations[key] = 0 if kind == 1 else section[3] + cursor + target[4] + position
                    relocation_kinds[key] = kind
            for si, sec in enumerate(sections):
                if sec[0] != 15:  # DOF_SECT_PROVIDER
                    continue
                provider = content(si, 15)
                if len(provider) != 44:
                    raise ValueError('unsupported provider record size')
                pv = struct.unpack(order + '11I', provider)
                strings = content(pv[0], 8)
                def string(index):
                    end = strings.find(b'\0', index)
                    if index >= len(strings) or end < 0:
                        raise ValueError('invalid DOF string')
                    return strings[index:end].decode('utf-8'), end + 1
                def arguments(index, count):
                    result = []
                    for _ in range(count):
                        text, index = string(index); result.append(text)
                    return result
                provider_name = string(pv[4])[0]
                providers.append({'name': provider_name, 'attributes': list(pv[5:10])})
                rows = content(pv[1], 16)
                if sections[pv[1]][3] != 48 or len(rows) % 48:
                    raise ValueError('unsupported probe record size')
                maps = content(pv[2], 17)
                offsets = content(pv[3], 18)
                enabled = content(pv[10], 26) if pv[10] != 0 else b''  # DOF_SECT_NONE
                def locations(table, index, count):
                    if (index + count) * 4 > len(table):
                        raise ValueError('probe offsets exceed table')
                    return list(struct.unpack_from(order + str(count) + 'I', table, index * 4)) if count else []
                for pos in range(0, len(rows), 48):
                    pr = struct.unpack_from(order + 'Q6IBBHIHHI', rows, pos)
                    if pr[5] + pr[8] > len(maps) or pr[12] or pr[13]:
                        raise ValueError('invalid probe argument map/padding')
                    if (pv[1], pos) not in relocations:
                        raise ValueError('probe address has no supported user relocation')
                    address = (pr[0] + relocations[(pv[1], pos)]) & ((1 << 64) - 1)
                    if resolver is not None:
                        if pr[0]:
                            raise ValueError('unsupported nonzero relocatable probe address field')
                        address = resolver.resolve(i, cursor + sections[pv[1]][4] + pos,
                            string(pr[1])[0], relocation_kinds[(pv[1], pos)],
                            locations(offsets, pr[6], pr[9]), locations(enabled, pr[10], pr[11]))
                    probes.append({'provider': provider_name, 'function': string(pr[1])[0],
                        'name': string(pr[2])[0], 'native_arguments': arguments(pr[3], pr[7]),
                        'translated_arguments': arguments(pr[4], pr[8]),
                        'argument_mapping': list(maps[pr[5]:pr[5] + pr[8]]),
                        'offsets': locations(offsets, pr[6], pr[9]),
                        'enabled_offsets': locations(enabled, pr[10], pr[11]),
                        'address': address})
            records += 1
            end = cursor + filesz
            cursor = min((end + 7) & ~7, len(payload))
            if any(payload[end:cursor]):
                raise ValueError('nonzero DOF alignment padding')
    if not records or not probes:
        raise ValueError('no emitted probe metadata')
    schemas = []
    for item in probes:
        schemas.append({k: v for k, v in item.items() if k not in ('address', 'offsets', 'enabled_offsets')} |
                       {'site_count': len(item['offsets']), 'enabled_site_count': len(item['enabled_offsets'])})
    canonical = lambda item: json.dumps(item, sort_keys=True)
    result = {'binary_sha256': hashlib.sha256(data).hexdigest(), 'dof_records': records,
            'providers': sorted({canonical(p): p for p in providers}.values(), key=canonical),
            'probe_schemas': sorted(schemas, key=canonical),
            'probe_locations': sorted(probes, key=canonical)}
    if resolver is not None:
        if len(resolver.bindings) != len(resolver.object['relocations']):
            raise ValueError('unconsumed DOF ELF relocation')
        result['relocatable_metadata'] = {
            'scope': 'amd64 ET_REL schemas, symbol-relative locations and patched bytes; no load addresses, registration or live firing',
            'symbols': {'path': resolver.symbols['path'], 'sha256': resolver.symbols['sha256']},
            'bindings': resolver.bindings}
    return result


def validate_amd64_sites(binary, symbols, metadata):
    """Check each emitted site against its function and dt_modtext's amd64 ABI."""
    data = binary.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('site instruction check requires amd64 ELF64 little-endian')
    header = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    offset, stride, count = header[5], header[10], header[11]
    if stride != 64 or not count or offset + stride * count > len(data):
        raise ValueError('unsupported section table')
    code = []
    for i in range(count):
        section = struct.unpack_from('<IIQQQQIIQQ', data, offset + stride * i)
        if section[2] & 4:  # SHF_EXECINSTR
            if section[4] + section[5] > len(data):
                raise ValueError('truncated executable section')
            code.append((section[3], data[section[4]:section[4] + section[5]]))
    def instruction(address, size):
        for base, contents in code:
            if base <= address and address + size <= base + len(contents):
                return contents[address - base:address - base + size]
        raise ValueError('probe site is outside executable section')
    ranges = {}
    text = subprocess.check_output(['/usr/bin/nm', '-S', '-a', str(symbols)], text=True)
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[2] in ('t', 'T', 'w', 'W'):
            name = fields[3]
            # dt_link.c may retain only its generated hidden function alias.
            alias = re.fullmatch(r'\$dtrace(?:[0-9]+)?\.(.+)', name)
            if alias:
                name = alias[1]
            ranges.setdefault(name, set()).add((int(fields[0], 16), int(fields[1], 16)))
    ordinary = enabled = 0
    for probe in metadata['probe_locations']:
        matches = [size for address, size in ranges.get(probe['function'], set()) if address == probe['address']]
        if not matches:
            raise ValueError('DOF address does not match function: ' + probe['function'])
        size = max(matches)
        for off in probe['offsets']:
            if off + 5 > size:
                raise ValueError('probe exceeds function bounds')
            insn = instruction(probe['address'] + off, 5)
            if insn[0] not in (0x90, 0xc3) or insn[1:] != b'\x90' * 4:
                raise ValueError('probe lacks expected patched NOP/RET sequence')
            ordinary += 1
        for off in probe['enabled_offsets']:
            if off < 3 or off + 2 > size:
                raise ValueError('is-enabled probe exceeds function bounds')
            insn = instruction(probe['address'] + off - 3, 5)
            if insn[:3] != b'\x48\x33\xc0' or insn[3] not in (0x90, 0xc3) or insn[4] != 0x90:
                raise ValueError('is-enabled probe lacks expected XOR/NOP sequence')
            enabled += 1
    return {'ordinary_sites': ordinary, 'enabled_sites': enabled,
            'symbols_sha256': hashlib.sha256(symbols.read_bytes()).hexdigest(),
            'scope': 'amd64 function address/range and patched instruction bytes; no live firing'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--check-amd64-sites', action='store_true')
    p.add_argument('--relocatable-metadata', action='store_true',
                   help='inspect amd64 ET_REL metadata with actual object symbol/site bindings; no load addresses')
    p.add_argument('--symbols', type=Path)
    a = p.parse_args()
    if a.relocatable_metadata and a.check_amd64_sites:
        p.error('relocatable metadata does not establish linked load addresses')
    result = inventory(a.binary, relocatable=a.relocatable_metadata, symbols=a.symbols)
    if a.check_amd64_sites:
        result['site_checks'] = validate_amd64_sites(a.binary, a.symbols or a.binary, result)
    with a.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
