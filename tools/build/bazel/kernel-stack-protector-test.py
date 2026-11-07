# SPDX-License-Identifier: BSD-2-Clause
"""Inspect executable relocations in the real guard initializer and control object."""
import argparse
from pathlib import Path
import struct
import unittest


def executable_references(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("ELF64 little-endian object required")
    header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if header[0] != 1 or header[10] != 64 or not header[11]:
        raise ValueError("ordinary relocatable object required")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, header[5] + i*64)
                for i in range(header[11])]
    references = set()
    for section in sections:
        if section[1] != 4 or not sections[section[7]][2] & 4:
            continue  # SHT_RELA targeting SHF_EXECINSTR; DWARF is not code.
        if section[9] != 24 or section[5] % 24:
            raise ValueError("ordinary ELF64 relocations required")
        symbols = sections[section[6]]
        if symbols[1] != 2 or symbols[9] != 24:
            raise ValueError("linked symbol table required")
        strings = sections[symbols[6]]
        names = data[strings[4]:strings[4]+strings[5]]
        for offset in range(section[4], section[4]+section[5], 24):
            _, info, _ = struct.unpack_from("<QQq", data, offset)
            symbol = info >> 32
            if symbol >= symbols[5] // 24:
                raise ValueError("relocation symbol outside table")
            name = struct.unpack_from("<I", data, symbols[4]+symbol*24)[0]
            references.add(names[name:names.index(0,name)].decode())
    if not references:
        raise ValueError("executable symbol relocations required")
    return references


class GuardInitialization(unittest.TestCase):
    def test_initializer_does_not_check_its_changing_guard(self):
        initializer = executable_references(ARGS.initializer)
        self.assertIn("arc4rand", initializer)
        self.assertIn("__stack_chk_guard", initializer)
        self.assertNotIn("__stack_chk_fail", initializer,
                         "guard initialization must not be stack-protected")
        self.assertIn("__stack_chk_fail", executable_references(ARGS.control),
                      "ordinary kernel protection must remain enabled")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--initializer", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    ARGS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__] + remaining)
