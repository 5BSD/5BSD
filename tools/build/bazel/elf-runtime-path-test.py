# SPDX-License-Identifier: BSD-2-Clause
"""Metadata contract negatives; real TLS program comparisons are separate evidence."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('elf_artifact_check',
    Path(__file__).with_name('elf-artifact-check.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

# Independent readelf field fixture. No synthetic ELF is accepted as a real
# qualification candidate: this unit test mocks the external inspection boundary.
_BASE = '''Class: ELF64
Data: 2's complement, little endian
OS/ABI: UNIX - FreeBSD
Machine: Advanced Micro Devices X86-64
Type: DYN (Shared object file)
 [Requesting program interpreter: /libexec/ld-elf.so.1]
 LOAD 0x000000 0x200000 0x200000 0x100 0x100 R E 0x1000
 GNU_STACK 0x000000 0x000000 0x000000 0x000 0x000 RW 0x10
 GNU_RELRO 0x000000 0x000000 0x000000 0x100 0x100 R 0x1
 0x1 (NEEDED) Shared library: [libc.so.7]
 0x1e (FLAGS) BIND_NOW
 0x6ffffffb (FLAGS_1) Flags: NOW PIE
'''
_PATH = ' 0x1d (RUNPATH) Library runpath: [/usr/tests/lib/libc/tls]\n'


class RuntimePathContracts(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.candidate = self.root / 'candidate'
        self.reference = self.root / 'reference'
        self.candidate.write_bytes(b'metadata-contract fixture')
        self.reference.write_bytes(b'metadata-contract fixture')
        self.tool = self.root / 'readelf'
        self.tool.write_bytes(b'inspection boundary fixture')

    def compare(self, candidate, reference, expected=None, static=False):
        def inspect(args):
            return candidate if Path(args[-1]) == self.candidate else reference
        with patch.object(checker, 'run', side_effect=inspect), patch.object(checker, 'sections', return_value={}):
            return checker.compare_program(self.tool, 'unused', self.candidate,
                self.reference, self.root, expected_search_paths=expected, static=static)

    @staticmethod
    def static_metadata():
        lines = [line for line in _BASE.splitlines(True)
                 if not any(marker in line for marker in ('Requesting program interpreter', '(NEEDED)', '(FLAGS)', '(FLAGS_1)'))]
        return ''.join(lines).replace('Type: DYN (Shared object file)', 'Type: EXEC (Executable file)')

    def test_static_contract_is_explicit(self):
        static = self.static_metadata()
        self.assertEqual(self.compare(static, static, static=True)['linkage'], 'static')
        with self.assertRaisesRegex(ValueError, 'interpreter'):
            self.compare(static, static)

    def test_static_rejects_dynamic_program(self):
        with self.assertRaisesRegex(ValueError, 'static program has dynamic'):
            self.compare(_BASE, _BASE, static=True)

    def test_static_rejects_dynamic_metadata_on_either_side(self):
        static = self.static_metadata()
        for field in (' [Requesting program interpreter: /libexec/ld-elf.so.1]\n',
                      ' 0x1 (NEEDED) Shared library: [libc.so.7]\n',
                      ' 0xe (SONAME) Library soname: [bad.so]\n',
                      ' DYNAMIC 0x0 0x0 0x0 0x1 0x1 RW 0x8\n'):
            for a, b in [(static+field,static),(static,static+field)]:
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'static program has dynamic'):
                    self.compare(a, b, static=True)

    def test_static_rejects_wrong_type_or_pie(self):
        static = self.static_metadata()
        for wrong in (static.replace('Type: EXEC', 'Type: DYN'),
                      static+' 0x6ffffffb (FLAGS_1) Flags: PIE\n'):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, 'fixed static executable'):
                self.compare(wrong, static, static=True)

    def test_static_requires_relro(self):
        static = self.static_metadata()
        with self.assertRaisesRegex(ValueError, 'RELRO'):
            self.compare(static.replace('GNU_RELRO', 'OTHER_SEGMENT'), static, static=True)

    def test_static_rejects_runtime_search_paths(self):
        static = self.static_metadata()
        with self.assertRaisesRegex(ValueError, 'unexpected runtime search path'):
            self.compare(static+_PATH, static, static=True)

    def test_static_cannot_allow_an_explicit_runtime_path(self):
        static = self.static_metadata()
        with self.assertRaisesRegex(ValueError, 'static program cannot have runtime search paths'):
            self.compare(static+_PATH, static+_PATH, ['/usr/tests/lib/libc/tls'], static=True)

    def test_static_cannot_be_used_as_shared_object_mode(self):
        with self.assertRaisesRegex(ValueError, 'static program has dynamic'):
            checker.parse_program(self.static_metadata(), program=False, static=True)

    def test_default_no_path_contract_is_preserved(self):
        self.assertEqual(self.compare(_BASE, _BASE)['expected_search_paths'], [])

    def test_default_rejects_even_matching_reference_path(self):
        with self.assertRaisesRegex(ValueError, 'unexpected runtime search path'):
            self.compare(_BASE + _PATH, _BASE + _PATH)

    def test_explicit_matching_path_contract_is_recorded(self):
        result = self.compare(_BASE + _PATH, _BASE + _PATH, ['/usr/tests/lib/libc/tls'])
        self.assertEqual(result['expected_search_paths'], ['/usr/tests/lib/libc/tls'])
        self.assertEqual(result['candidate']['metadata']['search_paths'], [('RUNPATH', '/usr/tests/lib/libc/tls')])

    def test_candidate_or_reference_drift_is_rejected(self):
        wrong = _BASE + _PATH.replace('/usr/tests/lib/libc/tls', '/tmp/build')
        for a, b in [(wrong, _BASE + _PATH), (_BASE + _PATH, wrong)]:
            with self.subTest(candidate=a), self.assertRaisesRegex(ValueError, 'unexpected runtime search path'):
                self.compare(a, b, ['/usr/tests/lib/libc/tls'])

    def test_tag_semantics_must_also_match(self):
        with self.assertRaisesRegex(ValueError, 'search_paths'):
            self.compare(_BASE + _PATH, _BASE + _PATH.replace('RUNPATH', 'RPATH'), ['/usr/tests/lib/libc/tls'])

    def test_additional_dynamic_path_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unexpected runtime search path'):
            self.compare(_BASE + _PATH + _PATH, _BASE + _PATH, ['/usr/tests/lib/libc/tls'])

    def test_hardening_checks_remain_enabled(self):
        with self.assertRaisesRegex(ValueError, 'RELRO and immediate binding'):
            self.compare((_BASE + _PATH).replace('BIND_NOW', '').replace('NOW PIE', 'PIE'),
                         _BASE + _PATH, ['/usr/tests/lib/libc/tls'])

    def test_scalar_contract_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'list or tuple'):
            self.compare(_BASE, _BASE, '/usr/tests/lib/libc/tls')

    def test_valid_path_cannot_hide_an_unparsed_second_tag(self):
        with self.assertRaisesRegex(ValueError, 'unsupported runtime search path'):
            checker.parse_program(_BASE + _PATH + '0x1d (RUNPATH) broken\n')

    def test_unparsed_path_metadata_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unsupported runtime search path'):
            checker.parse_program(_BASE + '0x1d (RUNPATH) broken\n')


if __name__ == '__main__':
    unittest.main()
