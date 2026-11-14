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




class SonameContracts(unittest.TestCase):
    @staticmethod
    def shared():
        return ''.join(line for line in _BASE.splitlines(True)
                       if 'Requesting program interpreter' not in line).replace('NOW PIE', 'NOW')

    def compare(self, candidate, reference, soname=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a, b, tool = (root / name for name in ('candidate', 'reference', 'readelf'))
            for path in (a, b, tool):path.write_bytes(b'inspection fixture')
            def inspect(args):return candidate if Path(args[-1]) == a else reference
            with patch.object(checker, 'run', side_effect=inspect), patch.object(checker, 'sections', return_value={}):
                return checker.compare_shared(tool, 'unused', a, b, soname, root)

    def test_default_still_requires_soname(self):
        with self.assertRaisesRegex(ValueError, 'one SONAME'):
            checker.parse_program(self.shared(), program=False)

    def test_explicit_absence_is_accepted(self):
        result = self.compare(self.shared(), self.shared())
        self.assertIsNone(result['candidate']['metadata']['soname'])
        self.assertFalse(result['runtime_qualified'])

    def test_named_library_still_requires_its_name(self):
        soname = ' 0xe (SONAME) Library soname: [valid.so.1]\n'
        self.compare(self.shared()+soname, self.shared()+soname, 'valid.so.1')
        with self.assertRaisesRegex(ValueError, 'one SONAME'):
            self.compare(self.shared(), self.shared(), 'valid.so.1')

    def test_one_sided_soname_is_rejected(self):
        named = self.shared()+' 0xe (SONAME) Library soname: [surprise.so]\n'
        for a, b in [(named,self.shared()),(self.shared(),named)]:
            with self.subTest(a=a), self.assertRaisesRegex(ValueError, 'incorrect shared-object type or SONAME'):
                self.compare(a,b)

    def test_duplicate_sonames_rejected(self):
        wrong = self.shared()+' 0xe (SONAME) Library soname: [one.so]\n'+' 0xe (SONAME) Library soname: [two.so]\n'
        with self.assertRaisesRegex(ValueError, 'one SONAME'):
            self.compare(wrong, self.shared())

    def test_selection_is_explicit_and_boolean(self):
        with self.assertRaisesRegex(ValueError, 'requires a shared object'):
            checker.parse_program(_BASE, allow_missing_soname=True)
        with self.assertRaisesRegex(ValueError, 'must be boolean'):
            checker.parse_program(self.shared(), program=False, allow_missing_soname='yes')

    def test_absent_soname_preserves_hardening_checks(self):
        good = self.shared()
        bad = [good.replace('Flags: NOW', 'Flags: NOW PIE'),
               good+' [Requesting program interpreter: /bad/loader]\n',
               good.replace('GNU_RELRO', 'OTHER_SEGMENT'),
               good.replace('(FLAGS) BIND_NOW', '(FLAGS) SYMBOLIC').replace('Flags: NOW', 'Flags: NONE'),
               good.replace('0x000 0x000 RW 0x10', '0x000 0x000 RWE 0x10')]
        for wrong in bad:
            for a,b in [(wrong,good),(good,wrong)]:
                with self.subTest(wrong=wrong), self.assertRaises(ValueError):self.compare(a,b)

    def test_duplicate_dynamic_flags_rejected(self):
        for extra in [' 0x1e (FLAGS) SYMBOLIC\n', ' 0x6ffffffb (FLAGS_1) Flags: PIE\n']:
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, 'ambiguous ELF dynamic flags'):
                self.compare(self.shared()+extra, self.shared())

    @staticmethod
    def versions(base, public='API_1.0', index=1):
        return (' 0x0000: Rev: 1 Flags: BASE Index: '+str(index)+' Cnt: 1 Name: '+base+'\n'
                ' 0x001c: Rev: 1 Flags: none Index: 2 Cnt: 1 Name: '+public+'\n')

    def test_base_label_is_retained_separately(self):
        a = self.shared()+self.versions('candidate-output')
        b = self.shared()+self.versions('reference-output')
        result = self.compare(a,b)
        self.assertFalse(result['version_base_names_equal'])
        self.assertEqual(result['candidate']['metadata']['version_base_definition'], 'candidate-output')
        self.assertEqual(result['make_reference']['metadata']['version_base_definition'], 'reference-output')
        self.assertEqual(result['candidate']['metadata']['version_definitions'], ['API_1.0'])

    def test_public_versions_remain_exact(self):
        with self.assertRaisesRegex(ValueError, 'metadata mismatch: version_definitions'):
            self.compare(self.shared()+self.versions('one','API_2.0'),
                         self.shared()+self.versions('two'))

    def test_base_presence_remains_exact(self):
        with self.assertRaisesRegex(ValueError, 'version base presence'):
            self.compare(self.shared()+self.versions('one'),
                         self.shared()+' 0x001c: Rev: 1 Flags: none Index: 2 Cnt: 1 Name: API_1.0\n')

    def test_named_library_base_must_match_soname(self):
        named = self.shared()+' 0xe (SONAME) Library soname: [valid.so.1]\n'
        with self.assertRaisesRegex(ValueError, 'base version identity differs'):
            self.compare(named+self.versions('wrong'),named+self.versions('valid.so.1'),'valid.so.1')

    def test_invalid_base_and_duplicate_public_versions_rejected(self):
        bad = [self.versions('one',index=3),
               self.versions('one')+' 0x0038: Rev: 1 Flags: BASE Index: 1 Cnt: 1 Name: two\n',
               self.versions('one')+' 0x0038: Rev: 1 Flags: none Index: 3 Cnt: 1 Name: API_1.0\n']
        for rows in bad:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.compare(self.shared()+rows,self.shared())

    def test_other_dynamic_flags_remain_exact(self):
        for wrong in [self.shared().replace('BIND_NOW', 'BIND_NOW SYMBOLIC'),
                      self.shared().replace('Flags: NOW', 'Flags: NOW NODELETE')]:
            with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, 'metadata mismatch: dynamic_flags'):
                self.compare(wrong,self.shared())

    def test_dependencies_remain_exact(self):
        wrong = self.shared()+' 0x1 (NEEDED) Shared library: [unexpected.so]\n'
        with self.assertRaisesRegex(ValueError, 'metadata mismatch: needed'):
            self.compare(wrong,self.shared())

if __name__ == '__main__':
    unittest.main()
