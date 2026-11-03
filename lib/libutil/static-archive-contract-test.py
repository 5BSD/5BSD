#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect libutil's default traced archive; never execute target objects."""
import hashlib
import json
import os
from pathlib import Path
import struct
import unittest


def members(data):
    if data[:8] != b'!<arch>\n':
        raise ValueError('archive magic')
    result, names, offset = [], b'', 8
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:] != b'`\n':
            raise ValueError('archive header')
        try:
            size = int(header[48:58].decode('ascii').strip())
            name = header[:16].decode('ascii').strip()
        except (ValueError, UnicodeError) as error:
            raise ValueError('archive fields') from error
        start, end = offset + 60, offset + 60 + size
        if size < 0 or end > len(data):
            raise ValueError('archive bounds')
        body = data[start:end]
        offset = end + (size & 1)
        if offset > len(data):
            raise ValueError('archive padding')
        if name == '//':
            names = body
            continue
        if name in ('/', '/SYM64/'):
            continue
        if name.startswith('#1/'):
            length = int(name[3:])
            if length > len(body):
                raise ValueError('BSD name bounds')
            name, body = body[:length].rstrip(b'\0').decode('ascii'), body[length:]
        elif name.startswith('/'):
            pos = int(name[1:])
            if pos >= len(names):
                raise ValueError('GNU name bounds')
            terminator = names.find(b'/\n', pos)
            if terminator < 0:
                raise ValueError('GNU name terminator')
            name = names[pos:terminator].decode('ascii')
        else:
            name = name.removesuffix('/')
        if name.startswith('__.SYMDEF'):
            continue
        if not name or '/' in name or name in ('.', '..'):
            raise ValueError('member basename')
        result.append((name, body))
    return result


def elf(body):
    if len(body) < 64 or body[:6] != b'\x7fELF\x02\x01':
        raise ValueError('ELF64 little endian required')
    if struct.unpack_from('<HH', body, 16) != (1, 62):
        raise ValueError('amd64 relocatable required')
    shoff = struct.unpack_from('<Q', body, 40)[0]
    stride, count, names_index = struct.unpack_from('<HHH', body, 58)
    if stride != 64 or not count or names_index >= count or shoff + count * stride > len(body):
        raise ValueError('section table bounds')
    sections = [struct.unpack_from('<IIQQQQIIQQ', body, shoff + i * stride) for i in range(count)]
    def payload(section):
        start, size = section[4:6]
        if start + size > len(body):
            raise ValueError('section bounds')
        return body[start:start + size]
    symbols, dof = [], []
    for section in sections:
        if section[1] == 0x6ffffff4:
            dof.append(payload(section))
        if section[1] != 2:
            continue
        if section[6] >= count or section[9] != 24 or section[5] % 24:
            raise ValueError('symbol table bounds')
        strings = payload(sections[section[6]])
        table = payload(section)
        for pos in range(0, len(table), 24):
            name, info, other, index, value, size = struct.unpack_from('<IBBHQQ', table, pos)
            end = strings.find(b'\0', name)
            if end < 0:
                raise ValueError('symbol string bounds')
            symbols.append((strings[name:end].decode('ascii'), index, info >> 4))
    return symbols, dof


def check(items, expected, anchor=None):
    names = [name.removesuffix('.nopic.o') + '.o' if name.endswith('.nopic.o') else name for name, _ in items]
    if len(set(names)) != len(names):
        raise ValueError('duplicate member identity')
    if names != expected:
        raise ValueError('original Make member order')
    defined, required = set(), set()
    for (name, body), normalized in zip(items, names):
        symbols, dof = elf(body)
        anchors = [symbol for symbol, index, _ in symbols
                   if index != 0 and symbol.startswith('__bsd_dof_anchor_')]
        if normalized != 'logincap_provider.o' and dof:
            raise ValueError('DOF embedded in regular member')
        if normalized == 'logincap_provider.o':
            if len(dof) != 1 or not dof[0].startswith(b'\x7fDOF'):
                raise ValueError('separate provider DOF')
            if anchors != ([anchor] if anchor else []):
                raise ValueError('separate provider static anchor')
            required.update(symbol for symbol, index, _ in symbols if index == 0 and symbol.startswith('$dtrace'))
        elif dof:
            raise ValueError('DOF embedded in regular member')
        else:
            if anchors:
                raise ValueError('separate provider static anchor')
            defined.update(symbol for symbol, index, _ in symbols if index != 0 and symbol.startswith('$dtrace'))
    if not required or not required <= defined:
        raise ValueError('provider alias closure')


class ArchiveContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get('TEST_SRCDIR', '.')) / os.environ.get('TEST_WORKSPACE', '')
        base = root / 'lib/libutil'
        fixture = json.loads((base / 'static-archive-contract.json').read_text())
        for name, digest in fixture['source_sha256'].items():
            if hashlib.sha256((base / name).read_bytes()).hexdigest() != digest:
                raise ValueError('original contract source drift: ' + name)
        paths = list(base.glob('*.a'))
        if len(paths) != 1:
            raise ValueError('one declared archive required: ' + repr(paths))
        cls.raw = paths[0].read_bytes()
        cls.items, cls.expected = members(cls.raw), fixture['members']
        cls.anchor = fixture.get('required_provider_anchor')

    def test_actual(self):
        check(self.items, self.expected, self.anchor)

    def test_order(self):
        items = self.items.copy()
        items[0], items[1] = items[1], items[0]
        with self.assertRaisesRegex(ValueError, 'order'):
            check(items, self.expected, self.anchor)

    def test_duplicate(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            check(self.items + [self.items[0]], self.expected, self.anchor)

    def test_suffix_collision(self):
        name, body = self.items[0]
        alias = (name.removesuffix('.nopic.o') + '.o' if name.endswith('.nopic.o')
                 else name.removesuffix('.o') + '.nopic.o')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            check(self.items + [(alias, body)], self.expected, self.anchor)

    def test_missing_dof(self):
        items = self.items[:-1] + [(self.items[-1][0], self.items[0][1])]
        with self.assertRaisesRegex(ValueError, 'provider DOF'):
            check(items, self.expected, self.anchor)

    def test_embedded_dof(self):
        items = [(self.items[0][0], self.items[-1][1])] + self.items[1:]
        with self.assertRaisesRegex(ValueError, 'embedded'):
            check(items, self.expected, self.anchor)

    def test_missing_anchor(self):
        name, body = self.items[-1]
        needle = self.anchor.encode('ascii') + b'\0'
        self.assertIn(needle, body)
        changed = body.replace(needle, b'_' * (len(needle) - 1) + b'\0')
        with self.assertRaisesRegex(ValueError, 'static anchor'):
            check(self.items[:-1] + [(name, changed)], self.expected, self.anchor)

    def test_machine(self):
        body = bytearray(self.items[0][1])
        struct.pack_into('<H', body, 18, 183)
        with self.assertRaisesRegex(ValueError, 'amd64'):
            check([(self.items[0][0], bytes(body))] + self.items[1:], self.expected, self.anchor)

    def test_truncation(self):
        with self.assertRaises(ValueError):
            members(self.raw[:-7])


if __name__ == '__main__':
    unittest.main(verbosity=2)
