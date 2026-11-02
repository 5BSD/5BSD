# SPDX-License-Identifier: BSD-2-Clause
"""Inspect actual compiler-produced PIC values, without executing target objects."""
import os
from pathlib import Path
import struct
import unittest

ROOT = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"] / "tools/build/bazel/tests/pic_policy/_objs"

def value(path):
    data = path.read_bytes()
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if h[0][:6] != b"\x7fELF\x02\x01" or h[1:3] != (1, 62):
        raise AssertionError("expected native ELF64 ET_REL")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, h[6] + i*h[11]) for i in range(h[12])]
    found = []
    for s in sections:
        if s[1] != 2:
            continue
        strings = sections[s[6]]
        names = data[strings[4]:strings[4]+strings[5]]
        for offset in range(s[4], s[4]+s[5], s[9]):
            n, info, other, section, address, size = struct.unpack_from("<IBBHQQ", data, offset)
            if names[n:].split(b"\0", 1)[0] == b"policy_pic_level":
                if size != 4 or section <= 0 or section >= len(sections):
                    raise AssertionError("invalid fixture data symbol")
                target = sections[section]
                if target[1] != 1 or address+4 > target[5]:
                    raise AssertionError("fixture value outside file-backed section")
                found.append(struct.unpack_from("<I", data, target[4]+address)[0])
    if len(found) != 1:
        raise AssertionError("fixture symbol missing or ambiguous")
    return found[0]

class PicPolicy(unittest.TestCase):
    def test_default_regular(self):
        self.assertEqual(value(ROOT/"default_objects/pic-policy.o"), 0)
    def test_default_pic(self):
        self.assertEqual(value(ROOT/"default_objects/pic-policy.pic.o"), 2)
    def test_small_regular(self):
        self.assertEqual(value(ROOT/"small_objects/pic-policy.o"), 0)
    def test_small_pic(self):
        self.assertEqual(value(ROOT/"small_objects/pic-policy.pic.o"), 1)

if __name__ == "__main__":
    unittest.main()
