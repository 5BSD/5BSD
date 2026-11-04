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
args = parser.parse_args()
data = (Path(os.environ["TEST_SRCDIR"]) / args.object).read_bytes()


class ResourceObjectTest(unittest.TestCase):
    def test_target_abi(self):
        self.assertEqual(data[:6], b"\x7fELF\x02\x01")
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        self.assertEqual(header[1:4], (1, args.machine, 1))
        if args.machine == 243:
            self.assertEqual(header[7] & 6, 0)

    def test_real_function(self):
        self.assertIn(b"standalone_add\0", data)
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, header[6] + i * 64)
                    for i in range(header[12])]
        self.assertTrue(any(h[2] & 4 and h[5] for h in sections))


if __name__ == "__main__":
    unittest.main(argv=[__file__], verbosity=2)
