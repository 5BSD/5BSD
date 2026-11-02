# SPDX-License-Identifier: BSD-2-Clause
"""Independent binary CTF fixtures: renumbering, cycles and negative ABI changes."""
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from ctf_semantics import Graph, compare, read_elf


def fixture(version=3, endian='<', compressed=False, order=None, empty=False, mutation=None):
    # Declarative ABI fixtures, encoded from sys/sys/ctf.h (not parser output).
    definitions = {
        1: [1, False, 'char', 1, 0x03000008],
        2: [1, False, 'long', 8, 0x01000040],
        3: [4, False, '', 28, (1, 2, 28)],
        4: [6, True, 'gateway', 40, [('payload', 3, 0), ('next', 6, 256)]],
        5: [10, True, 'Gateway', 4, None],
        6: [3, False, '', 4, None],
        7: [5, False, '', 2, [5, 6, 0]],
        8: [8, True, 'status', 4, [('OK', 0), ('BAD', -1)]],
        9: [7, True, 'choice', 8, [('number', 2, 0), ('link', 6, 0)]],
        10: [2, True, 'double', 8, 0x02000040],
        11: [9, True, 'incomplete', 6, None],
        12: [11, False, '', 5, None],
        13: [12, False, '', 5, None],
        14: [13, False, '', 6, None],
        15: [6, True, 'huge', (1 << 32) + 8, [('payload', 2, 1 << 33)]],
    }
    if mutation:
        mutation(definitions)
    order = list(definitions) if order is None else order
    ids = {old: i + 1 + int(empty) for i, old in enumerate(order)}
    ref = lambda old: ids[old] if old else 0
    names = bytearray(b'\0')
    offsets = {'': 0}
    def name(value):
        if value not in offsets:
            offsets[value] = len(names)
            names.extend(value.encode() + b'\0')
        return offsets[value]
    def pack(fmt, *values):
        return struct.pack(endian + fmt, *values)
    def info(kind, root, count):
        return kind << (11 if version == 2 else 26) | int(root) << (10 if version == 2 else 25) | count
    word = 'H' if version == 2 else 'I'
    types = bytearray(pack('IHH' if version == 2 else 'III', 0, 0, 0) if empty else b'')
    for old in order:
        kind, root, label, value, extra = definitions[old]
        count = len(extra) if kind in (5, 6, 7, 8) else (1 if kind in (1, 2, 4) else 0)
        encoded = ref(value) if kind in (3, 5, 10, 11, 12, 13) else value
        large = kind in (6, 7) and encoded >= (0xffff if version == 2 else 0xffffffff)
        types.extend(pack('IHH' if version == 2 else 'III', name(label), info(kind, root, count), (0xffff if version == 2 else 0xffffffff) if large else encoded))
        if large:
            types.extend(pack('II', encoded >> 32, encoded & 0xffffffff))
        if kind in (1, 2):
            types.extend(pack('I', extra))
        elif kind == 4:
            types.extend(pack('HHI' if version == 2 else 'III', ref(extra[0]), ref(extra[1]), extra[2]))
        elif kind == 5:
            for x in extra:
                types.extend(pack(word, ref(x)))
            types.extend(bytes(-len(types) % 4))
        elif kind in (6, 7):
            for member, target, offset in extra:
                if value < (1 << (13 if version == 2 else 29)):
                    types.extend(pack('IHH' if version == 2 else 'III', name(member), ref(target), offset))
                elif version == 2:
                    types.extend(pack('IHHII', name(member), ref(target), 0, offset >> 32, offset & 0xffffffff))
                else:
                    types.extend(pack('IIII', name(member), ref(target), offset >> 32, offset & 0xffffffff))
        elif kind == 8:
            for member, number in extra:
                types.extend(pack('Ii', name(member), number))
    label = pack('II', name('build'), len(order) + int(empty))
    objects = pack(word, ref(4))
    objects += bytes(-(len(label) + len(objects)) % 4)
    functions = pack(word * 5, info(5, True, 3), ref(2), ref(5), ref(6), 0)
    functions += bytes(-len(functions) % 4)
    typ = len(label) + len(objects) + len(functions)
    strings = typ + len(types)
    body = label + objects + functions + types + names
    header = pack('HBB8I', 0xcff1, version, int(compressed), 0, 0, 0, len(label), len(label) + len(objects), typ, strings, len(names))
    symbols = [('gateway_instance', 1, 1, 0, '.data', 0, 40), ('lookup', 2, 1, 0, '.text', 0, 16)]
    return header + (zlib.compress(body) if compressed else body), symbols


def elf(ctf, symbols):
    names = b'\0.text\0.data\0.strtab\0.symtab\0.SUNW_ctf\0.shstrtab\0'
    strings = bytearray(b'\0')
    symtab = bytearray(bytes(24))
    for label, kind, bind, visibility, section, value, size in symbols:
        nm = len(strings)
        strings.extend(label.encode() + b'\0')
        symtab.extend(struct.pack('<IBBHQQ', nm, bind << 4 | kind, visibility, 1 if section == '.text' else 2, value, size))
    payloads = [b'', bytes(16), bytes(40), bytes(strings), bytes(symtab), ctf, names]
    data = bytearray(bytes(64)); entries = [bytes(64)]
    for i in range(1, 7):
        offset = len(data); data.extend(payloads[i])
        label = ['', '.text', '.data', '.strtab', '.symtab', '.SUNW_ctf', '.shstrtab'][i]
        entries.append(struct.pack('<IIQQQQIIQQ', names.index(label.encode() + b'\0'), 2 if i == 4 else (3 if i in (3, 6) else 1), 0, 0, offset, len(payloads[i]), 3 if i == 4 else (4 if i == 5 else 0), 1 if i == 4 else 0, 1, 24 if i == 4 else 0))
    offset = len(data);data.extend(b''.join(entries))
    data[:16] = b'\x7fELF\x02\x01\x01\x09' + bytes(8)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 1, 62, 1, 0, 0, offset, 0, 64, 0, 0, 64, 7, 6)
    return bytes(data)


class CtfSemanticsTest(unittest.TestCase):
    def graph(self, **kwargs):
        return Graph(*fixture(**kwargs))

    def changed(self, mutation):
        with self.assertRaises(ValueError):
            compare(self.graph(), self.graph(mutation=mutation))

    def test_versions_endianness_compression_and_renumbering(self):
        for version in (2, 3):
            for endian in ('<', '>'):
                for compressed in (False, True):
                    with self.subTest(version=version, endian=endian, compressed=compressed):
                        result = compare(self.graph(), self.graph(version=version, endian=endian, compressed=compressed, order=list(reversed(range(1, 16))), empty=True))
                        self.assertEqual(result['right_unreferenced_empty_slots'], [1])
                        self.assertEqual(result['symbol_associations'], 2)

    def test_v2_record_relative_padding(self):
        data,symbols=fixture(version=2)
        header=list(struct.unpack_from('<HBB8I',data))
        # Omit optional object-table alignment bytes. Function record lengths
        # are rounded independently of their absolute offset (ctf_open.c).
        fun=header[7];body=data[36:];body=body[:fun-2]+body[fun:]
        header[7]-=2;header[8]-=2;header[9]-=2
        unaligned=struct.pack('<HBB8I',*header)+body
        self.assertTrue(compare(self.graph(),Graph(unaligned,symbols))['equivalent'])

    def test_member_offset(self):
        self.changed(lambda d: d[4][4].__setitem__(0, ('payload', 3, 8)))

    def test_member_name(self):
        self.changed(lambda d: d[4][4].__setitem__(0, ('other', 3, 0)))

    def test_member_type(self):
        self.changed(lambda d: d[4][4].__setitem__(0, ('payload', 2, 0)))

    def test_struct_size(self):
        self.changed(lambda d: d[4].__setitem__(3, 48))

    def test_long_member_offset(self):
        self.changed(lambda d: d[15][4].__setitem__(0, ('payload', 2, (1 << 33) + 8)))

    def test_array_length(self):
        self.changed(lambda d: d[3].__setitem__(4, (1, 2, 27)))

    def test_integer_encoding(self):
        self.changed(lambda d: d[1].__setitem__(4, 0x00000008))

    def test_float_encoding(self):
        self.changed(lambda d: d[10].__setitem__(4, 0x06000040))

    def test_enum_value(self):
        self.changed(lambda d: d[8][4].__setitem__(1, ('BAD', -2)))

    def test_pointer_target(self):
        self.changed(lambda d: d[6].__setitem__(3, 2))

    def test_function_argument_order(self):
        self.changed(lambda d: d[7].__setitem__(4, [6, 5, 0]))

    def test_const_target(self):
        self.changed(lambda d: d[13].__setitem__(3, 2))

    def test_visible_root_flag(self):
        self.changed(lambda d: d[4].__setitem__(1, False))

    def test_nonempty_type_multiplicity(self):
        self.changed(lambda d: d.__setitem__(16, list(d[3])))

    def test_symbol_identity(self):
        data, symbols = fixture();other = list(symbols);other[0] = ('other', *other[0][1:])
        with self.assertRaises(ValueError):compare(Graph(data, symbols), Graph(data, other))

    def test_symbol_association(self):
        data, symbols = fixture();changed = bytearray(data);obj = struct.unpack_from('<I', data, 16)[0];struct.pack_into('<I', changed, 36 + obj, 2)
        with self.assertRaises(ValueError):compare(Graph(data, symbols), Graph(changed, symbols))

    def test_missing_symbol_records(self):
        data, symbols = fixture()
        with self.assertRaises(ValueError):Graph(data, symbols + [('extra', 1, 1, 0, '.data', 40, 40)])

    def test_unsupported_parent(self):
        data, symbols = fixture();data=bytearray(data);struct.pack_into('<I', data, 8, 1)
        with self.assertRaisesRegex(ValueError, 'parent'):Graph(data, symbols)

    def test_truncated_records(self):
        data, symbols = fixture()
        for length in (0, 35, len(data) - 1):
            with self.subTest(length=length), self.assertRaises(ValueError):Graph(data[:length], symbols)

    def test_invalid_reference(self):
        data, symbols = fixture();data=bytearray(data);obj=struct.unpack_from('<I',data,16)[0];struct.pack_into('<I',data,36+obj,0x80000001)
        with self.assertRaises(ValueError):Graph(data,symbols)

    def test_compressed_trailing_data(self):
        data, symbols = fixture(compressed=True)
        with self.assertRaises(ValueError):Graph(data+b'junk',symbols)

    def test_function_association_return(self):
        data,symbols=fixture();changed=bytearray(data);fun=struct.unpack_from('<I',data,20)[0];struct.pack_into('<I',changed,36+fun+4,1)
        with self.assertRaises(ValueError):compare(Graph(data,symbols),Graph(changed,symbols))

    def test_function_association_arguments(self):
        data,symbols=fixture();changed=bytearray(data);fun=struct.unpack_from('<I',data,20)[0];struct.pack_into('<II',changed,36+fun+8,6,5)
        with self.assertRaises(ValueError):compare(Graph(data,symbols),Graph(changed,symbols))

    def test_partial_label(self):
        data,symbols=fixture();changed=bytearray(data);struct.pack_into('<I',changed,40,3)
        with self.assertRaisesRegex(ValueError,'partial'):Graph(changed,symbols)

    def test_label_name(self):
        data,symbols=fixture();changed=data.replace(b'build\0',b'other\0');self.assertNotEqual(data,changed)
        with self.assertRaisesRegex(ValueError,'label names'):compare(Graph(data,symbols),Graph(changed,symbols))

    def test_elf_reader_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'a.o';q=Path(directory)/'b.o';data,symbols=fixture();p.write_bytes(elf(data,symbols));other,syms=fixture(version=2,compressed=True,empty=True);q.write_bytes(elf(other,syms))
            self.assertTrue(compare(read_elf(p),read_elf(q))['equivalent'])
            raw=bytearray(q.read_bytes());struct.pack_into('<H',raw,18,183);q.write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'ELF identity'):compare(read_elf(p),read_elf(q))

    def test_elf_ctf_link(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'a.o';data,symbols=fixture();raw=bytearray(elf(data,symbols));table=struct.unpack_from('<Q',raw,40)[0];struct.pack_into('<I',raw,table+5*64+40,3);p.write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'SYMTAB'):read_elf(p)


if __name__ == '__main__':
    unittest.main()
