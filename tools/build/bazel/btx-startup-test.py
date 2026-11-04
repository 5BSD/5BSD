# SPDX-License-Identifier: BSD-2-Clause
"""Inspect real BTX startup objects and their relocatable/debug outputs."""
import argparse
from pathlib import Path
import struct
import sys
import unittest
import zlib

from elf_object_contract import contract

parser = argparse.ArgumentParser()
for name in ['full', 'stripped', 'debug']:
    parser.add_argument('--' + name, type=Path, required=True)
parser.add_argument('--objects', type=Path, nargs=3, required=True)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining


def sections(data):
    header = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
    table = [struct.unpack_from('<IIIIIIIIII', data, header[6] + n * header[11])
             for n in range(header[12])]
    string = table[header[13]]
    names = data[string[4]:string[4] + string[5]]
    return {names[s[0]:names.index(b'\0', s[0])].decode(): data[s[4]:s[4] + s[5]]
            for s in table if s[1] != 8}


class BtxStartup(unittest.TestCase):
    def test_all_real_inputs_and_outputs_are_elf32_relocatable(self):
        for p in [*args.objects, args.full, args.stripped, args.debug]:
            with self.subTest(path=p):
                info = contract(p.read_bytes())
                self.assertEqual((info['identity']['elf_class'], info['identity']['machine']), (1, 3))

    def test_startup_order_and_platform_symbols(self):
        full = args.full.read_bytes()
        self.assertTrue(sections(full)['.text'].startswith(sections(args.objects[0].read_bytes())['.text']))
        info = contract(full)
        symbols = {s['name']: s for s in info['external']}
        self.assertEqual(symbols['_start']['value'], 0)
        self.assertEqual(symbols['_start']['section'], '.text')
        self.assertTrue({'__base', '__args', '__exit', '__exec', '__v86', '__v86int'} <= symbols.keys())
        self.assertEqual({n for n,s in symbols.items() if s['section'] == 0}, {'_edata', '_end', 'exit', 'main'})
        self.assertNotIn('__stack_chk_fail', symbols)

    def test_debug_split_preserves_allocated_contract_and_link(self):
        self.assertEqual(contract(args.full.read_bytes()), contract(args.stripped.read_bytes()))
        full = sections(args.full.read_bytes())
        stripped = sections(args.stripped.read_bytes())
        debug = sections(args.debug.read_bytes())
        self.assertIn('.debug_info', full)
        self.assertNotIn('.debug_info', stripped)
        self.assertIn('.debug_info', debug)
        link = stripped['.gnu_debuglink']
        end = link.index(b'\0')
        self.assertEqual(link[:end].decode(), args.debug.name)
        crc = struct.unpack_from('<I', link, (end + 4) & ~3)[0]
        self.assertEqual(crc, zlib.crc32(args.debug.read_bytes()) & 0xffffffff)


if __name__ == '__main__':
    unittest.main()
