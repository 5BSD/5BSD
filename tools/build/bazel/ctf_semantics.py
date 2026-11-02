# SPDX-License-Identifier: BSD-2-Clause
"""Strict standalone CTF v2/v3 type-layout and ELF symbol association comparison.

Format definitions: sys/sys/ctf.h; symbol filtering: common/ctf/ctf_open.c.
Type IDs are local encodings. All visible roots, symbol associations and other
nonempty types are checked. Only unreferenced empty nonroot UNKNOWN slots may
have different counts. Parent containers and partial/multiple labels fail closed.
"""
import collections
import hashlib
import struct
import zlib
from pathlib import Path

MAX_BODY = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def string(table, offset):
    require(0 <= offset < len(table), 'string offset outside table')
    end = table.find(b'\0', offset)
    require(end >= 0, 'unterminated string')
    return table[offset:end].decode('utf-8')


class Graph:
    def __init__(self, data, symbols=(), external_strings=b''):
        require(len(data) >= 36, 'truncated CTF header')
        require(data[:2] in (b'\xf1\xcf', b'\xcf\xf1'), 'bad CTF magic')
        endian = '<' if data[:2] == b'\xf1\xcf' else '>'
        magic, version, flags, parent_label, parent_name, lbl, obj, fun, typ, strings, length = struct.unpack_from(endian + 'HBB8I', data)
        require(version in (2, 3) and not flags & ~1, 'unsupported CTF version/flags')
        require(not parent_label and not parent_name, 'parent CTF containers unsupported')
        require(lbl == 0 and lbl <= obj <= fun <= typ <= strings, 'invalid CTF offsets')
        require(strings + length <= MAX_BODY, 'CTF body exceeds limit')
        if flags & 1:
            inflater = zlib.decompressobj()
            body = inflater.decompress(data[36:], MAX_BODY + 1)
            require(len(body) <= MAX_BODY and inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail, 'invalid or oversized compressed CTF')
        else:
            body = data[36:]
        require(len(body) == strings + length, 'CTF body length mismatch')
        names = body[strings:]
        require(names[:1] == b'\0', 'CTF string zero missing')
        def name(value):
            return string(external_strings if value >> 31 else names, value & 0x7fffffff)
        width = 2 if version == 2 else 4
        word = 'H' if width == 2 else 'I'
        sentinel = 0xffff if version == 2 else 0xffffffff
        threshold = 1 << (13 if version == 2 else 29)
        def info(value):
            if version == 3:
                require(not value & (1 << 24), 'reserved CTF info bit')
            return (value >> (11 if version == 2 else 26), bool(value & (1 << (10 if version == 2 else 25))), value & (0x3ff if version == 2 else 0xffffff))
        def unpack(fmt, at, stop):
            size = struct.calcsize(endian + fmt)
            require(at + size <= stop, 'truncated CTF record')
            return struct.unpack_from(endian + fmt, body, at), at + size
        nodes = {}
        at = typ
        while at < strings:
            (nm, encoded, size), at = unpack('IHH' if version == 2 else 'III', at, strings)
            kind, root, count = info(encoded)
            require(kind <= 13, 'unsupported CTF type kind')
            reference_kind = kind in (3, 5, 9, 10, 11, 12, 13)
            if not reference_kind and size == sentinel:
                (high, low), at = unpack('II', at, strings)
                size = high << 32 | low
            attrs = [kind, root, name(nm)]
            refs = []
            if kind in (1, 2):
                require(count in (0, 1), 'scalar vlen')
                (encoding,), at = unpack('I', at, strings)
                attrs += [size, encoding]
            elif kind in (3, 10, 11, 12, 13):
                require(count == 0, 'reference vlen')
                refs = [size]
            elif kind == 4:
                require(count in (0, 1), 'array vlen')
                (content, index, number), at = unpack('HHI' if version == 2 else 'III', at, strings)
                attrs += [size, number]
                refs = [content, index]
            elif kind == 5:
                refs = [size]
                for _ in range(count):
                    (ref,), at = unpack(word, at, strings)
                    refs.append(ref)
                padding = -(count * width) % 4
                require(at + padding <= strings and not any(body[at:at + padding]), 'function type padding')
                at += padding
            elif kind in (6, 7):
                attrs += [size]
                members = []
                for _ in range(count):
                    if size < threshold:
                        (member, ref, offset), at = unpack('IHH' if version == 2 else 'III', at, strings)
                    else:
                        if version == 2:
                            (member, ref, pad, high, low), at = unpack('IHHII', at, strings)
                            require(pad == 0, 'long member padding')
                        else:
                            (member, ref, high, low), at = unpack('IIII', at, strings)
                        offset = high << 32 | low
                    members.append((name(member), offset))
                    refs.append(ref)
                attrs.append(tuple(members))
            elif kind == 8:
                attrs += [size]
                values = []
                for _ in range(count):
                    (member, value), at = unpack('Ii', at, strings)
                    values.append((name(member), value))
                attrs.append(tuple(values))
            elif kind == 9:
                require(count == 0 and size in (0, 6, 7, 8), 'invalid forward type')
                attrs += [size]
            else:
                require(not root and not nm and not count and not size, 'nonempty UNKNOWN type')
            nodes[len(nodes) + 1] = (tuple(attrs), tuple(refs))
        require(at == strings, 'type table boundary mismatch')
        for attrs, refs in nodes.values():
            require(all(ref == 0 or ref in nodes for ref in refs), 'dangling or child type reference')
        require(obj - lbl in (0, 8), 'partial/multiple labels unsupported')
        labels = []
        if obj != lbl:
            (label, boundary), _ = unpack('II', lbl, obj)
            require(boundary == len(nodes), 'partial CTF label unsupported')
            labels.append(name(label))
        associations = {}
        positions = {1: obj, 2: fun}
        for identity in symbols:
            kind = identity[1]
            if kind not in (1, 2):
                continue
            pos = positions[kind]
            stop = fun if kind == 1 else typ
            require(pos < stop, 'missing CTF symbol association')
            (value,), pos = unpack(word, pos, stop)
            if kind == 1:
                refs = (value,)
            else:
                function_kind, root, count = info(value)
                if function_kind == 0:
                    require(value == 0, 'invalid unknown function association')
                    refs = ()
                else:
                    require(function_kind == 5, 'invalid function association')
                    values, pos = unpack(word * (count + 1), pos, stop)
                    refs = tuple(values)
                    padding = -((count + 2) * width) % 4
                    require(pos + padding <= stop and not any(body[pos:pos + padding]), 'function association padding')
                    pos += padding
            require(all(ref == 0 or ref in nodes for ref in refs), 'invalid symbol type reference')
            association_key = (identity, root if kind == 2 else False)
            require(association_key not in associations, 'ambiguous symbol identity')
            associations[association_key] = refs
            positions[kind] = pos
        for kind, stop in [(1, fun), (2, typ)]:
            pad = body[positions[kind]:stop]
            require(len(pad) < 4 and not any(pad), 'unbound CTF symbol records')
        self.nodes, self.symbols, self.labels = nodes, associations, tuple(labels)
        self.version = version


def read_elf(path):
    data = Path(path).read_bytes()
    require(len(data) >= 16 and data[:5] == b'\x7fELF\x02' and data[5] in (1, 2), 'ELF64 required')
    endian = '<' if data[5] == 1 else '>'
    require(len(data) >= 64, 'truncated ELF header')
    h = struct.unpack_from(endian + 'HHIQQQIHHHHHH', data, 16)
    require(h[0] == 1 and h[10] == 64 and h[11] and h[12] < h[11], 'ordinary relocatable section table required')
    require(h[5] + 64 * h[11] <= len(data), 'truncated ELF sections')
    entries = [struct.unpack_from(endian + 'IIQQQQIIQQ', data, h[5] + i * 64) for i in range(h[11])]
    def payload(entry):
        require(entry[1] != 8 and entry[4] + entry[5] <= len(data), 'invalid section payload')
        return data[entry[4]:entry[4] + entry[5]]
    require(entries[h[12]][1] == 3, 'invalid ELF section string table')
    names = payload(entries[h[12]])
    sections = [string(names, entry[0]) for entry in entries]
    require(sections.count('.SUNW_ctf') == 1, 'one CTF section required')
    ctf = entries[sections.index('.SUNW_ctf')]
    require(ctf[1] == 1, 'CTF requires a data section')
    require(ctf[6] < len(entries) and entries[ctf[6]][1] == 2, 'CTF must link to SYMTAB')
    symtab = entries[ctf[6]]
    require(symtab[9] == 24 and symtab[5] % 24 == 0 and symtab[6] < len(entries), 'invalid ELF symtab')
    require(entries[symtab[6]][1] == 3, 'invalid ELF symbol string table')
    strings = payload(entries[symtab[6]])
    symbols = []
    raw = payload(symtab)
    for offset in range(0, len(raw), 24):
        nm, flags, other, section, value, size = struct.unpack_from(endian + 'IBBHQQ', raw, offset)
        label = string(strings, nm)
        kind = flags & 15
        if not nm or not section or label in ('_START_', '_END_') or kind not in (1, 2) or (kind == 1 and section == 0xfff1 and value == 0):
            continue
        require(section < len(entries), 'special ELF symbol sections unsupported')
        symbols.append((label, kind, flags >> 4, other, sections[section], value, size))
    graph = Graph(payload(ctf), symbols, strings)
    graph.elf_identity = (h[0], h[1], h[6], data[5], data[7], data[8])
    graph.sha256 = hashlib.sha256(data).hexdigest()
    graph.ctf_sha256 = hashlib.sha256(payload(ctf)).hexdigest()
    return graph


def compare(left, right):
    require(getattr(left, 'elf_identity', None) == getattr(right, 'elf_identity', None), 'ELF identity differs')
    require(left.labels == right.labels, 'CTF label names differ')
    require(set(left.symbols) == set(right.symbols), 'ELF symbol association identities differ')
    # Joint partition refinement compares ordered reference graphs, including
    # cycles, without recursive traversal or quadratic anonymous-root matching.
    nodes = {(side, i): node for side, graph in enumerate((left, right))
             for i, node in graph.nodes.items()}
    nodes[(0, 0)] = nodes[(1, 0)] = (("void/varargs",), ())
    def intern(values):
        classes = {}
        result = {}
        for key, value in values.items():
            if value not in classes:
                classes[value] = len(classes)
            result[key] = classes[value]
        return result, len(classes)
    colors, count = intern({key: attrs for key, (attrs, _) in nodes.items()})
    rounds = 0
    while True:
        signatures = {key: (colors[key], tuple(colors[(key[0], ref)] for ref in refs))
                      for key, (_, refs) in nodes.items()}
        colors, refined = intern(signatures)
        rounds += 1
        if refined == count:
            break
        count = refined
    for key in left.symbols:
        require(tuple(colors[(0, i)] for i in left.symbols[key]) ==
                tuple(colors[(1, i)] for i in right.symbols[key]),
                'symbol type association differs')
    referenced = []
    included = []
    unreachable = []
    for side, graph in enumerate((left, right)):
        refs = {i for _, values in graph.nodes.values() for i in values}
        refs.update(i for values in graph.symbols.values() for i in values)
        referenced.append(refs)
        included.append(collections.Counter(colors[(side, i)] for i, (a, _) in graph.nodes.items()
                                             if a[0] != 0 or i in refs))
        visited = set()
        work = [i for i, (attrs, _) in graph.nodes.items() if attrs[1]]
        work += [i for values in graph.symbols.values() for i in values]
        while work:
            i = work.pop()
            if i == 0 or i in visited:
                continue
            visited.add(i)
            work.extend(graph.nodes[i][1])
        unreachable.append([{'id': i, 'kind': a[0], 'name': a[2]}
                            for i, (a, _) in graph.nodes.items() if i not in visited])
    require(included[0] == included[1], 'nonempty/referenced type classes or multiplicities differ')
    return {'equivalent': True, 'refinement_rounds': rounds,
            'symbol_associations': len(left.symbols), 'labels': list(left.labels),
            'left_types': len(left.nodes), 'right_types': len(right.nodes),
            'left_unreachable_types': unreachable[0], 'right_unreachable_types': unreachable[1],
            'left_unreferenced_empty_slots': [i for i, (a, _) in left.nodes.items() if a[0] == 0 and i not in referenced[0]],
            'right_unreferenced_empty_slots': [i for i, (a, _) in right.nodes.items() if a[0] == 0 and i not in referenced[1]]}
