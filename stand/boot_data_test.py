# SPDX-License-Identifier: BSD-2-Clause
"""Inspect real boot data and font artifacts; never execute a target program."""
import gzip
import os
from pathlib import Path, PurePosixPath
import struct
import sys
import tarfile
import unittest
import zlib


def font(data):
    if len(data) < 32:
        raise ValueError("truncated font header")
    magic, width, height, padding, glyphs, *maps = struct.unpack_from(">8sBBH5I", data)
    if magic != b"VFNT0002" or padding or not width or not height or not glyphs:
        raise ValueError("invalid VFNT geometry/header")
    offset = 32 + ((width + 7) // 8) * height * glyphs
    if offset + 8 * sum(maps) != len(data) or not maps[0]:
        raise ValueError("font payload/mapping size mismatch")
    for count in maps:
        previous = -1
        for _ in range(count):
            source, destination, length = struct.unpack_from(">IHH", data, offset)
            if source <= previous or source + length > 0x10ffff or destination + length >= glyphs:
                raise ValueError("invalid font character/glyph mapping")
            previous = source + length
            offset += 8
    return width, height, glyphs


class BootDataTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archive = Path(os.environ["TEST_SRCDIR"]) / sys.argv[1]
        cls.expect_manuals = sys.argv[2] == "yes"
        with tarfile.open(archive) as stream:
            members = stream.getmembers()
            names = [m.name for m in members]
            if len(names) != len(set(names)):
                raise ValueError("duplicate archive member")
            cls.payload = {}
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isreg()):
                    raise ValueError("unsafe boot data archive entry")
                if member.isreg():
                    if member.uid != 0 or member.gid != 0 or (member.uname, member.gname) != ("root", "wheel"):
                        raise ValueError("unexpected base data ownership")
                    if member.mode != 0o444:
                        raise ValueError("unexpected base data mode")
                    cls.payload[member.name] = stream.extractfile(member).read()
                # Directory permissions come from declared mtree policy. Site
                # extensions may legitimately differ from the default 0755.

    def test_fonts_and_catalog(self):
        fonts = {name: data for name, data in self.payload.items() if name.endswith(".fnt.gz")}
        self.assertTrue(fonts)
        for name, data in fonts.items():
            with self.subTest(font=name):
                self.assertEqual(data[:4], b"\x1f\x8b\x08\x00")
                self.assertEqual(data[4:8], bytes(4))
                geometry = font(gzip.decompress(data))
                width, height = Path(name).name.removesuffix(".fnt.gz").rstrip("bv").split("x")
                self.assertEqual(geometry[:2], (int(width), int(height)))
        catalog = self.payload["boot/fonts/INDEX.fonts"].decode()
        for line in catalog.splitlines():
            if line and not line.startswith("#"):
                name, language, description = line.split(":", 2)
                self.assertTrue(description)
                # INDEX.fonts also carries MENU/FONT localization records;
                # kbdmap consumes those as metadata, not font filenames.
                if name in ["MENU", "FONT"]:
                    continue
                self.assertTrue(name.endswith(".fnt"), name)
                key = "boot/fonts/" + name + ".gz"
                self.assertTrue(key in fonts, key)

    def test_font_corruption_is_detected(self):
        original = gzip.decompress(next(data for name, data in self.payload.items() if name.endswith(".fnt.gz")))
        for data in [original[:31], original[:-1], original[:12] + bytes(4) + original[16:]]:
            with self.subTest(size=len(data)):
                with self.assertRaises(ValueError):
                    font(data)

    def test_manual_streams(self):
        manuals = {name: data for name, data in self.payload.items() if name.startswith("usr/share/man/")}
        self.assertEqual(bool(manuals), self.expect_manuals)
        for name, data in manuals.items():
            if name.endswith(".gz"):
                self.assertEqual(data[:4], b"\x1f\x8b\x08\x00")
                self.assertEqual(data[4:8], bytes(4))
                data = gzip.decompress(data)
            self.assertIn(b".Dd ", data)

    def test_png_checksums(self):
        images = [data for name, data in self.payload.items() if name.endswith(".png")]
        self.assertTrue(images)
        for data in images:
            self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
            offset = 8
            while offset < len(data):
                size = struct.unpack_from(">I", data, offset)[0]
                self.assertLessEqual(offset + 12 + size, len(data))
                chunk = data[offset + 4:offset + 8 + size]
                self.assertEqual(zlib.crc32(chunk), struct.unpack_from(">I", data, offset + 8 + size)[0])
                offset += 12 + size
            self.assertEqual(offset, len(data))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
