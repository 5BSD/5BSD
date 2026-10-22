# SPDX-License-Identifier: BSD-2-Clause
"""Independent structural checks for compiler-produced DOF, not a kernel loader."""
import struct


def validate_dof(data):
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    require(len(data) >= 64 and data[:4] == b'\x7fDOF', 'invalid DOF header')
    require(data[4] in (1, 2) and data[5] in (1, 2), 'invalid model or encoding')
    order = '<' if data[5] == 1 else '>'
    flags, hdrsize, secsize, count, secoff, loadsz, filesz, pad = struct.unpack_from(order+'IIIIQQQQ', data, 16)
    require(hdrsize >= 64 and secsize >= 32, 'undersized headers')
    require(hdrsize <= loadsz <= filesz == len(data), 'invalid file/load sizes')
    require(secoff >= hdrsize and secoff + count * secsize <= loadsz, 'section table outside loadable data')
    require(pad == 0 and not any(data[10:16]), 'nonzero header padding')
    sections = []
    for index in range(count):
        kind, align, secflags, entsize, offset, size = struct.unpack_from(order+'IIIIQQ', data, secoff + index * secsize)
        require(align > 0 and align & (align-1) == 0, 'invalid section alignment')
        require(offset % align == 0, 'misaligned section')
        require(offset <= filesz and size <= filesz-offset, 'section outside file')
        require(not secflags & 1 or offset + size <= loadsz, 'loadable section outside load size')
        require(not entsize or size % entsize == 0, 'partial section entry')
        sections.append({'kind': kind, 'entsize': entsize, 'offset': offset, 'size': size})

    def link(index, kinds, optional=False):
        if optional and index == 0xffffffff:
            return None
        require(index < count, 'section link outside table')
        section = sections[index]
        require(section['kind'] in kinds, 'section link has wrong type')
        return section

    for section in sections:
        kind, offset, size = section['kind'], section['offset'], section['size']
        if kind == 3:  # ECB descriptor: probes, predicate, actions, padding.
            require(size >= 24, 'short ECB descriptor')
            probes, pred, actions, padding = struct.unpack_from(order+'IIII', data, offset)
            link(probes, (4,))
            link(pred, (6,), True)
            link(actions, (5,), True)
            require(padding == 0, 'nonzero ECB padding')
        elif kind == 4:  # Includes the 5BSD VM identifier extension.
            require(size >= 28, 'short probe descriptor')
            values = struct.unpack_from(order+'IIIIII', data, offset)
            strings = link(values[0], (8,))
            for string_offset in values[1:5]:
                require(string_offset < strings['size'], 'probe string outside string table')
                start = strings['offset'] + string_offset
                require(data.find(b'\0', start, strings['offset'] + strings['size']) >= 0,
                    'unterminated probe string')
        elif kind == 5:
            stride = section['entsize']
            require(stride >= 32, 'short action entry')
            for pos in range(offset, offset+size, stride):
                difo, strings = struct.unpack_from(order+'II', data, pos)
                link(difo, (6,), True)
                link(strings, (8,), True)
        elif kind == 6:
            require(size >= 12 and (size-8) % 4 == 0, 'invalid DIFO header size')
            for pos in range(offset+8, offset+size, 4):
                link(struct.unpack_from(order+'I', data, pos)[0], (7, 8, 9, 19, 21))
        elif kind == 8:
            require(size > 0 and data[offset+size-1] == 0, 'unterminated string table')
    return {'sections': count, 'file_size': filesz, 'load_size': loadsz,
        'section_types': sorted({s['kind'] for s in sections})}
