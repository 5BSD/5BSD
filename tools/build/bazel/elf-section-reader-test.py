# SPDX-License-Identifier: BSD-2-Clause
"""Section range validation, streaming and rejection of incomplete tool metadata."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('elf_artifact_check',
    Path(__file__).with_name('elf-artifact-check.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class SectionReader(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.artifact = self.root / 'input'

    def read(self, text):
        with patch.object(checker, 'run', return_value=text) as tool:
            result = checker.sections('unused-objcopy', 'readelf', self.artifact, self.root)
            tool.assert_called_once_with(['readelf', '-S', '-W', self.artifact])
        # The reader must not create scratch copies of ELF files or sections.
        self.assertEqual({p.name for p in self.root.iterdir()}, {'input'})
        return result

    def header(self, rows, count=None):
        return ('There are %d section headers, starting at offset 0x0:\n'
                ' [ 0] NULL 00000000 000000 000000 00 0 0 0\n' %
                (len(rows) + 1 if count is None else count)) + '\n'.join(rows)

    def test_large_payload_small_payload_and_nobits(self):
        data = b'x' * (2 * 1024 * 1024 + 17)
        self.artifact.write_bytes(b'pre' + data + b'end')
        result = self.read(self.header([
            ' [ 1] .text PROGBITS 00000000 000003 %06x 00 AX 0 0 1' % len(data),
            ' [ 2] .tail STRTAB 00000000 %06x 000003 00 0 0 1' % (len(data) + 3),
            ' [ 3] .bss NOBITS 00000000 ffffff ffffff 00 WA 0 0 8']))
        self.assertEqual(result, {
            '.text': {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)},
            '.tail': {'sha256': hashlib.sha256(b'end').hexdigest(), 'size': 3}})

    def test_zero_length_section(self):
        self.artifact.write_bytes(b'x')
        self.assertEqual(self.read(self.header([
            ' [ 1] .empty PROGBITS 00000000 000001 000000 00 0 0 1'])),
            {'.empty': {'sha256': hashlib.sha256(b'').hexdigest(), 'size': 0}})

    def test_out_of_bounds_ranges_are_rejected(self):
        self.artifact.write_bytes(b'abc')
        for offset, size in [(4, 0), (2, 2)]:
            with self.subTest(offset=offset, size=size), self.assertRaisesRegex(ValueError, 'out-of-bounds'):
                self.read(self.header([
                    ' [ 1] .bad PROGBITS 00000000 %06x %06x 00 0 0 1' % (offset, size)]))

    def test_duplicate_names_are_rejected(self):
        self.artifact.write_bytes(b'abc')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.read(self.header([
                ' [ 1] .same PROGBITS 00000000 000000 000001 00 0 0 1',
                ' [ 2] .same PROGBITS 00000000 000001 000001 00 0 0 1']))

    def test_missing_table_rows_are_rejected(self):
        self.artifact.write_bytes(b'abc')
        with self.assertRaisesRegex(ValueError, 'incomplete or unordered'):
            self.read(self.header([], count=2))

    def test_unordered_table_rows_are_rejected(self):
        self.artifact.write_bytes(b'abc')
        with self.assertRaisesRegex(ValueError, 'incomplete or unordered'):
            self.read(self.header([' [ 2] .bad PROGBITS 00000000 000000 000001 00 0 0 1']))

    def test_malformed_row_is_rejected(self):
        self.artifact.write_bytes(b'abc')
        with self.assertRaisesRegex(ValueError, 'unsupported ELF section row'):
            self.read(self.header([' [ 1] .bad PROGBITS 00000000']))

    def test_missing_section_count_is_rejected(self):
        self.artifact.write_bytes(b'abc')
        with self.assertRaisesRegex(ValueError, 'section header count'):
            self.read('Section Headers:\n')


if __name__ == '__main__':
    unittest.main()
