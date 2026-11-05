#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the inspector against real ELF32/64 outputs and changed code/debug data."""
import argparse
import os
from pathlib import Path
import struct
import unittest
from elf_object_contract import contract

parser = argparse.ArgumentParser()
parser.add_argument('--elf32', required=True)
parser.add_argument('--elf64', required=True)
args = parser.parse_args()
root = Path(os.environ['TEST_SRCDIR'])
inputs = [(root / args.elf32).read_bytes(), (root / args.elf64).read_bytes()]


def section_ranges(data):
    wide = data[4] == 2
    header = struct.unpack_from('<16sHHIQQQIHHHHHH' if wide else '<16sHHIIIIIHHHHHH', data)
    for i in range(header[12]):
        h = struct.unpack_from('<IIQQQQIIQQ' if wide else '<IIIIIIIIII', data, header[6] + i * header[11])
        yield h


class ObjectContract(unittest.TestCase):
    def test_real_producer_identities(self):
        for data, bits, machine in zip(inputs, [1, 2], [3, 62]):
            result = contract(data)
            self.assertEqual(result['identity']['elf_class'], bits)
            self.assertEqual(result['identity']['machine'], machine)
            changed = bytearray(data)
            changed[8] ^= 1
            self.assertNotEqual(result['identity'], contract(changed)['identity'])
            self.assertTrue(any(e['name'] == 'standalone_add' and e['size'] > 0 for e in result['external']))

    def test_changed_instruction_bytes_are_detected(self):
        for data in inputs:
            h = next(h for h in section_ranges(data) if h[1] == 1 and h[2] & 4 and h[5])
            changed = bytearray(data)
            changed[h[4]] ^= 1
            self.assertNotEqual(contract(data)['allocated'], contract(changed)['allocated'])

    def test_nonallocated_payload_is_outside_contract(self):
        for data in inputs:
            # Nonallocated PROGBITS is outside this contract. String/symbol
            # tables and relocation records have distinct section types.
            h = next(h for h in section_ranges(data) if h[1] == 1 and not h[2] & 2 and h[5])
            changed = bytearray(data)
            changed[h[4]] ^= 1
            self.assertNotEqual(bytes(changed), data)
            self.assertEqual(contract(data), contract(changed))

    def test_invalid_input_fails(self):
        for data in [b'not ELF', inputs[0][:52], inputs[1][:64]]:
            with self.assertRaises(ValueError):
                contract(data)


def fixture(second_value=0x456, left_section=1, duplicate=True):
    strings = b'\0left\0right\0'
    symbol = lambda name, section: struct.pack('<IBBHQQ', name, 0x11, 0, section, 0, 20)
    note = lambda value: struct.pack('<III4sI', 4, 4, 1, b'BSD\0', value)
    names = ['', '.note.tag', '.note.tag' if duplicate else '.note.other',
             '.data', '.rela.data', '.strtab', '.symtab', '.shstrtab']
    shstrings = b'\0';offsets = []
    for name in names:
        offsets.append(len(shstrings));shstrings += name.encode() + b'\0'
    payloads = [b'', note(0x123), note(second_value), b'\0' * 8,
                struct.pack('<QQq', 0, (1 << 32) | 1, 0), strings,
                b'\0' * 24 + symbol(1, left_section) + symbol(6, 2), shstrings]
    # type, flags, link, info, alignment, entry size (independent ELF layout).
    fields = [(0, 0, 0, 0, 0, 0), (7, 2, 0, 0, 4, 0), (7, 2, 0, 0, 4, 0),
              (1, 3, 0, 0, 8, 0), (4, 0, 6, 3, 8, 24), (3, 0, 0, 0, 1, 0),
              (2, 0, 5, 1, 8, 24), (3, 0, 0, 0, 1, 0)]
    data = bytearray(64);headers = []
    for i, (payload, (kind, flags, link, info, alignment, size)) in enumerate(zip(payloads, fields)):
        while len(data) % max(alignment, 1):data.append(0)
        offset = len(data) if i else 0;data += payload
        headers.append(struct.pack('<IIQQQQIIQQ', offsets[i] if i else 0, kind, flags,
                                   0, offset, len(payload), link, info, alignment, size))
    while len(data) % 8:data.append(0)
    shoff = len(data);data += b''.join(headers)
    ident = b'\x7fELF\x02\x01\x01\x09' + b'\0' * 8
    data[:64] = struct.pack('<16sHHIQQQIHHHHHH', ident, 1, 62, 1, 0, 0, shoff,
                           0, 64, 0, 0, 64, len(headers), 7)
    return bytes(data)


class SectionIdentity(unittest.TestCase):
    def test_default_remains_strict(self):
        with self.assertRaisesRegex(ValueError, 'duplicate allocated'):
            contract(fixture())
        self.assertIn('.note.tag', contract(fixture(duplicate=False))['allocated'])

    def test_all_occurrences_are_retained(self):
        value = contract(fixture(), allow_duplicate_sections=True)
        self.assertIn('[".note.tag",0]', value['allocated'])
        self.assertIn('[".note.tag",1]', value['allocated'])
        self.assertNotEqual(value['allocated']['[".note.tag",0]']['sha256'],
                            value['allocated']['[".note.tag",1]']['sha256'])

    def test_second_payload_change_is_detected(self):
        self.assertNotEqual(contract(fixture(), allow_duplicate_sections=True),
                            contract(fixture(second_value=0x789), allow_duplicate_sections=True))

    def test_retargeting_same_named_section_is_detected(self):
        self.assertNotEqual(contract(fixture(), allow_duplicate_sections=True),
                            contract(fixture(left_section=2), allow_duplicate_sections=True))

    def test_selection_requires_bool(self):
        with self.assertRaisesRegex(ValueError, 'must be a bool'):
            contract(fixture(), allow_duplicate_sections='yes')



if __name__ == '__main__':
    unittest.main(argv=[__file__], verbosity=2)
