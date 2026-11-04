# SPDX-License-Identifier: BSD-2-Clause
"""Inspect an explicitly declared resource-header consumer without executing it."""
import argparse
import os
from pathlib import Path
import struct
import unittest

parser = argparse.ArgumentParser()
parser.add_argument("--object", required=True)
parser.add_argument("--machine", required=True, type=int)
parser.add_argument("--elf-class", choices=[1, 2], type=int, default=2)
parser.add_argument("--kind", choices=["relocatable", "executable"], default="relocatable")
args = parser.parse_args()
data = (Path(os.environ["TEST_SRCDIR"]) / args.object).read_bytes()

header_format = "<16sHHIQQQIHHHHHH" if args.elf_class == 2 else "<16sHHIIIIIHHHHHH"
section_format = "<IIQQQQIIQQ" if args.elf_class == 2 else "<IIIIIIIIII"
header = struct.unpack_from(header_format, data)


class ResourceObjectTest(unittest.TestCase):
    def test_target_abi(self):
        self.assertEqual(data[:6], b"\x7fELF" + bytes([args.elf_class, 1]))
        self.assertEqual(header[1:4], (2 if args.kind == "executable" else 1, args.machine, 1))
        if args.machine == 243:
            self.assertEqual(header[7] & 6, 0)

    def test_real_function(self):
        self.assertIn(b"standalone_add\0", data)
        self.assertEqual(header[11], struct.calcsize(section_format))
        sections = [struct.unpack_from(section_format, data, header[6] + i * header[11])
                    for i in range(header[12])]
        self.assertTrue(any(h[2] & 4 and h[5] for h in sections))
        if args.kind == "executable":
            self.assertTrue(any(h[2] & 4 and h[3] <= header[4] < h[3] + h[5] for h in sections))
            self.assertTrue(all(struct.unpack_from("<I", data, header[5] + i * header[9])[0] != 3
                                for i in range(header[10])), "freestanding image must not require an interpreter")


if __name__ == "__main__":
    unittest.main(argv=[__file__], verbosity=2)
