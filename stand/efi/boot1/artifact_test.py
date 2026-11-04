# SPDX-License-Identifier: BSD-2-Clause
"""Inspect real firmware artifacts without executing target code."""
import argparse
import json
import os
from pathlib import Path
import struct
import unittest
import zlib

parser = argparse.ArgumentParser()
parser.add_argument("--program", choices=["boot1", "gptboot", "loader_4th", "loader_simp"], required=True)
parser.add_argument("--arch", choices=["amd64", "aarch64", "riscv64"], required=True)
for name in ["full", "symbols", "debug", "image", "manifest"]:
    parser.add_argument("--" + name, type=Path, required=True)
for name in ["manual", "compressed", "split"]:
    parser.add_argument("--" + name, choices=["yes", "no"], required=True)
parser.add_argument("--help-data", type=Path)
args = parser.parse_args()
for name in ["full", "symbols", "debug", "image", "manifest"]:
    setattr(args, name, Path(os.environ["TEST_SRCDIR"]) / getattr(args, name))

if args.help_data is not None:
    args.help_data = Path(os.environ["TEST_SRCDIR"]) / args.help_data


def elf(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("ELF64 little-endian firmware required")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[11] != 64:
        raise ValueError("invalid section header size")
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, header[6] + i * 64) for i in range(header[12])]
    names = headers[header[13]]
    names = data[names[4]:names[4] + names[5]]
    sections = {}
    for section in headers:
        name = names[section[0]:].split(b"\0", 1)[0].decode()
        payload = b"" if section[1] == 8 else data[section[4]:section[4] + section[5]]
        if section[1] != 8 and len(payload) != section[5]:
            raise ValueError("truncated ELF section")
        sections[name] = (section, payload)
    return header, headers, sections


class FirmwareTest(unittest.TestCase):
    def test_machine_and_entry(self):
        header, _, sections = elf(args.full)
        self.assertEqual(header[1:4], (3, {"amd64": 62, "aarch64": 183, "riscv64": 243}[args.arch], 1))
        if args.arch == "riscv64":
            self.assertEqual(header[7] & 6, 0, "firmware must use the soft-float ABI")
        data = args.image.read_bytes()
        self.assertEqual(data[:2], b"MZ")
        offset = struct.unpack_from("<I", data, 60)[0]
        self.assertEqual(data[offset:offset + 4], b"PE\0\0")
        self.assertEqual(struct.unpack_from("<H", data, offset + 4)[0],
                         {"amd64": 0x8664, "aarch64": 0xaa64, "riscv64": 0x5064}[args.arch])
        self.assertEqual(struct.unpack_from("<H", data, offset + 24)[0], 0x20b)
        self.assertEqual(struct.unpack_from("<I", data, offset + 40)[0], header[4])
        self.assertEqual(struct.unpack_from("<H", data, offset + 92)[0], 10)
        if args.arch != "amd64":
            self.assertEqual(struct.unpack_from("<I", data, offset + 8)[0], 0)
        self.assertTrue(sections[".text"][1])

    def test_debug_split(self):
        full, _, source = elf(args.full)
        stripped, _, binary = elf(args.symbols)
        _, _, debug = elf(args.debug)
        self.assertEqual(full[1:5], stripped[1:5])
        allocated = lambda sections: {n: (h[1], h[2], h[3], h[5], h[8], body)
                                     for n, (h, body) in sections.items() if h[2] & 2}
        self.assertEqual(allocated(source), allocated(binary))
        self.assertIn(".symtab", binary)
        self.assertFalse(any(name.startswith((".debug_", ".zdebug_")) for name in binary))
        self.assertTrue(any(name.startswith((".debug_", ".zdebug_")) for name in debug))
        link = binary[".gnu_debuglink"][1]
        end = link.index(0)
        self.assertEqual(link[:end].decode(), args.program + ".sym.debug")
        self.assertEqual(struct.unpack_from("<I", link, (end + 4) & ~3)[0], zlib.crc32(args.debug.read_bytes()))

    def test_no_runtime_dependencies(self):
        _, headers, sections = elf(args.full)
        for header, body in sections.values():
            if header[1] == 6:
                self.assertEqual(header[9], 16)
                self.assertFalse(any(struct.unpack_from("<q", body, i)[0] == 1 for i in range(0, len(body), 16)))
            if header[1] in [2, 11]:
                self.assertEqual(header[9], 24)
                for i in range(0, len(body), 24):
                    name, info, _, index, _, _ = struct.unpack_from("<IBBHQQ", body, i)
                    self.assertFalse(name and info >> 4 == 1 and index == 0, "unresolved strong symbol")

    def test_installation(self):
        records = json.loads(args.manifest.read_text())["files"]
        self.assertEqual(len(records), 1 + (args.manual == "yes") + (args.help_data is not None))
        entries = {record["destination"]: record for record in records}
        image = entries["/boot/" + args.program + ".efi"]
        self.assertEqual((image["type"], image["owner"], image["group"], image["mode"], image["tags"]),
                         ("file", "root", "wheel", "0555", ["package=bootloader"]))
        if args.help_data is not None:
            help_record = entries["/boot/loader.help.efi"]
            self.assertEqual((help_record["type"], help_record["owner"], help_record["group"], help_record["mode"], help_record["tags"]),
                             ("file", "root", "wheel", "0444", ["package=bootloader"]))
            self.assertTrue(args.help_data.read_bytes())
        if args.manual == "yes":
            manual = entries["/usr/share/man/man8/gptboot.efi.8" + (".gz" if args.compressed == "yes" else "")]
            self.assertEqual((manual["type"], manual["owner"], manual["group"], manual["mode"], manual["tags"]),
                             ("file", "root", "wheel", "0444", ["package=bootloader-man" if args.split == "yes" else "package=bootloader"]))


if __name__ == "__main__":
    unittest.main(argv=[__file__], verbosity=2)
