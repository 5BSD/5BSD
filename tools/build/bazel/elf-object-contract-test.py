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


if __name__ == '__main__':
    unittest.main(argv=[__file__], verbosity=2)
