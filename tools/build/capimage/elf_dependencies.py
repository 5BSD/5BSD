# SPDX-License-Identifier: BSD-2-Clause
"""Inspect ELF loading metadata without executing the target or resolving paths.

This is a construction primitive, not a loader, ABI validator, dependency
resolver or trust decision. Read quiescent, reconciled bytes supplied by caller.
Program headers are used: loadable objects need not retain section headers.
"""
import struct


def inspect(data):
    if not isinstance(data, bytes):
        raise ValueError('ELF inspection requires immutable bytes')
    if len(data) < 16 or data[:4] != b'\x7fELF':
        raise ValueError('not an ELF object')
    cls, encoding, version = data[4:7]
    if cls not in (1, 2) or encoding not in (1, 2) or version != 1:
        raise ValueError('unsupported ELF identification')
    order = '<' if encoding == 1 else '>'
    header_fmt = order + ('HHIIIIIHHHHHH' if cls == 1 else 'HHIQQQIHHHHHH')
    ph_fmt = order + ('IIIIIIII' if cls == 1 else 'IIQQQQQQ')
    dyn_fmt = order + ('iI' if cls == 1 else 'qQ')

    def region(offset, size):
        if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
            raise ValueError('ELF region outside file')
        return data[offset:offset + size]

    header = struct.unpack(header_fmt, region(16, struct.calcsize(header_fmt)))
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = header
    if version != 1 or kind not in (2, 3) or ehsize != 16 + struct.calcsize(header_fmt):
        raise ValueError('unsupported ELF executable header')
    # Extended counts require section metadata, outside this initial reader.
    # Reject them explicitly rather than silently examining fewer headers.
    if phnum == 0xffff:
        raise ValueError('extended ELF program-header count unsupported')
    if phnum and phsize != struct.calcsize(ph_fmt):
        raise ValueError('invalid ELF program-header size')
    region(phoff, phsize * phnum)
    loads, interpreters, dynamics, notes = [], [], [], []
    all_regions_bounded = True
    for index in range(phnum):
        values = struct.unpack(ph_fmt, region(phoff + index * phsize, phsize))
        if cls == 1:
            ptype, offset, address, physical, size, memsize, pflags, align = values
        else:
            ptype, pflags, offset, address, physical, size, memsize, align = values
        all_regions_bounded &= offset <= len(data) and size <= len(data) - offset
        if ptype in (1, 2, 3, 4):
            region(offset, size)
        if ptype == 1:
            if size > memsize:
                raise ValueError('ELF load segment file size exceeds memory size')
            if address + memsize > 1 << (32 if cls == 1 else 64):
                raise ValueError('ELF load address range overflows target width')
            loads.append((address, size, memsize, offset))
        elif ptype == 2:
            dynamics.append((address, offset, size))
        elif ptype == 3:
            interpreters.append(region(offset, size))
        elif ptype == 4:
            notes.append((offset, size))
    if len(interpreters) > 1 or len(dynamics) > 1:
        raise ValueError('duplicate ELF interpreter or dynamic segment')

    # Record every FreeBSD feature-control occurrence, without choosing a
    # winning note or inferring kernel acceptance. Brand selection, target
    # PAGE_SIZE and kernel parse limits are separate runtime requirements.
    feature_controls, abi_notes, note_segments = [], [], []
    for offset, size in notes:
        end, pos, count = offset + size, offset, 0
        while pos < end:
            count += 1
            if pos % 4 or end - pos < 12:
                raise ValueError('misaligned or truncated ELF note header')
            namesize, descsize, notetype = struct.unpack(order + 'III', region(pos, 12))
            namepos = pos + 12
            descpos = namepos + ((namesize + 3) & ~3)
            nextpos = descpos + ((descsize + 3) & ~3)
            if nextpos > end:
                raise ValueError('ELF note exceeds segment')
            name = region(namepos, namesize)
            if name == b'FreeBSD\0' and notetype in (1, 4):
                if descsize != 4:
                    raise ValueError('invalid FreeBSD ABI/feature-control note size')
                (feature_controls if notetype == 4 else abi_notes).append(dict(offset=pos, segment_size=size,
                    value=struct.unpack(order + 'I', region(descpos, 4))[0]))
            pos = nextpos
        note_segments.append(dict(offset=offset, size=size, count=count))

    def mapped_offset(address, size):
        # The loader consumes mapped virtual addresses. Reject any competing
        # segment touching these bytes, including a partial or zero-fill
        # overlap; a unique whole-region match alone is insufficient.
        touching = [(start, extent, offset) for start, extent, memory, offset in loads
                    if start < address + size and address < start + memory]
        if len(touching) != 1:
            raise ValueError('ELF metadata lacks unique file-backed mapping')
        start, extent, offset = touching[0]
        if address < start or address - start > extent or size > extent - (address - start):
            raise ValueError('ELF metadata lacks unique file-backed mapping')
        return offset + address - start

    def string(raw, allow_empty=False):
        if not raw or raw[-1:] != b'\0' or b'\0' in raw[:-1]:
            raise ValueError('invalid ELF terminated string')
        try:
            value = raw[:-1].decode('utf-8')
        except UnicodeDecodeError as error:
            raise ValueError('ELF path is not UTF-8') from error
        if (not value and not allow_empty) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('empty or control character in ELF string')
        return value

    interpreter = string(interpreters[0]) if interpreters else None
    tags = {}
    if dynamics:
        address, offset, size = dynamics[0]
        if mapped_offset(address, size) != offset:
            raise ValueError('ELF dynamic offset disagrees with load mapping')
        width = struct.calcsize(dyn_fmt)
        if size % width:
            raise ValueError('misaligned ELF dynamic table')
        terminated = False
        for pos in range(offset, offset + size, width):
            tag, value = struct.unpack(dyn_fmt, region(pos, width))
            if tag == 0:
                terminated = True
                break
            tags.setdefault(tag, []).append(value)
        if not terminated:
            raise ValueError('unterminated ELF dynamic table')
    # DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH contain string offsets.
    string_tags = (1, 14, 15, 29, 0x7ffffffd, 0x7fffffff, 0x6ffffefb, 0x6ffffefc)
    for tag in (5, 10, 14, 15, 29):
        if len(tags.get(tag, [])) > 1:
            raise ValueError('duplicate ELF singleton dynamic tag')
    strings = {}
    if any(tag in tags for tag in string_tags):
        if 5 not in tags or 10 not in tags:
            raise ValueError('ELF dependencies lack string table')
        address, size = tags[5][0], tags[10][0]
        table = region(mapped_offset(address, size), size)
        for tag in string_tags:
            strings[tag] = []
            for offset in tags.get(tag, []):
                end = table.find(b'\0', offset) if offset < len(table) else -1
                if end < 0:
                    raise ValueError('ELF string offset or terminator invalid')
                strings[tag].append(string(table[offset:end + 1], allow_empty=tag in (15, 29)))
    # rtld digest_dynamic1 accumulates flag bits across repeated entries.
    # Preserve unknown bits too: a later resolver must not silently assume
    # search semantics from a subset of flags it happens to recognize.
    def combined_flags(tag):
        result = 0
        for value in tags.get(tag, []):
            result |= value
        return result

    return dict(elf_class=32 if cls == 1 else 64,
                byte_order='little' if encoding == 1 else 'big', machine=machine,
                osabi=data[7], abi_version=data[8], program_header_count=phnum,
                program_regions_bounded=all_regions_bounded,
                interpreter=interpreter, needed=strings.get(1, []),
                freebsd_abi_notes=abi_notes, note_segments=note_segments,
                freebsd_feature_control_notes=feature_controls,
                dynamic_flags=combined_flags(30),
                dynamic_flags_1=combined_flags(0x6ffffffb),
                soname=next(iter(strings.get(14, [])), None),
                rpath=next(iter(strings.get(15, [])), None),
                runpath=next(iter(strings.get(29, [])), None),
                auxiliary=strings.get(0x7ffffffd, []),
                filters=strings.get(0x7fffffff, []),
                dependency_audit=strings.get(0x6ffffefb, []),
                audit=strings.get(0x6ffffefc, []),
                dependency_coverage_complete=False)


# Versioned ABI constants, cross-checked against sys/elf_common.h by tests.
BIP_CONTRACT_VERSION = 2
BIP_RESTRICT = 0x80
BIP_MAX_NOTES = 4096


def bip_target(value):
    """Validate explicit target input; never infer it from the builder host."""
    if not isinstance(value, dict) or set(value) != {'elf_class', 'byte_order', 'machine', 'page_size'}:
        raise ValueError('invalid BIP target ELF profile')
    if (type(value['elf_class']) is not int or value['elf_class'] not in (32, 64) or
            value['byte_order'] not in ('little', 'big') or
            type(value['machine']) is not int or not 0 < value['machine'] < 65536 or
            type(value['page_size']) is not int or not 0 < value['page_size'] < 2**31 or
            value['page_size'] & (value['page_size'] - 1)):
        raise ValueError('invalid BIP target ELF profile')
    return dict(value)


def validate_bip_image(metadata, target):
    """Check declared manager metadata; does not qualify kernel or interpreter."""
    target = bip_target(target)
    if any(metadata[key] != target[key] for key in ('elf_class', 'byte_order', 'machine')):
        raise ValueError('BIP image does not match target ELF profile')
    if (metadata['osabi'] != 9 or metadata['abi_version'] != 0 or
            not metadata['program_header_count'] or not metadata['program_regions_bounded']):
        raise ValueError('BIP image requires bounded native FreeBSD ELF headers')
    if any(note['offset'] % 4 or note['size'] > target['page_size'] or
           note['count'] > BIP_MAX_NOTES for note in metadata['note_segments']):
        raise ValueError('BIP image notes exceed native admission bounds')
    features = metadata['freebsd_feature_control_notes']
    if (len(metadata['freebsd_abi_notes']) != 1 or len(features) != 1 or
            not features[0]['value'] & BIP_RESTRICT):
        raise ValueError('BIP image requires one ABI note and one restrictive feature note')
    return dict(scope='declared-bip-image-metadata', required_contract_version=BIP_CONTRACT_VERSION,
                target=target, metadata_valid=True, runtime_enforcement_verified=False)
