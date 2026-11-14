# SPDX-License-Identifier: BSD-2-Clause
"""Real nm must retain DTrace aliases, including AArch64 special symbols."""
import argparse
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


checker = module('archive_checker', 'elf-artifact-check.py')
fixtures = module('elf_fixtures', 'dtrace-relocatable-inventory-test.py')
NM = None


class ActualArchiveSymbols(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def symbols(self, machine, *, alias='$dtrace123.fn', defined=True):
        payload = fixtures.fixture(machine=machine, alias=alias, defined=defined,
                                   kind=260 if machine == 183 else 24, enabled_site=4)
        # One ordinary ar member; no external archiver builds this fixture.
        name = 'probe.nossppico/'
        header = f'{name:<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(payload):<10}`\n'
        assert len(header) == 60
        archive = self.root / ('input-' + str(machine) + '.a')
        archive.write_bytes(b'!<arch>\n' + header.encode('ascii') + payload +
                            (b'\n' if len(payload) % 2 else b''))
        return checker.parse_archive(NM, archive)

    def test_defined_and_undefined_aliases_are_visible_on_both_cpus(self):
        for machine in (62, 183):
            for defined, kind in ((True, 'T'), (False, 'U')):
                with self.subTest(machine=machine, defined=defined):
                    self.assertIn(('$dtrace123.fn', kind),
                                  self.symbols(machine, defined=defined)['probe'])

    def test_changed_function_name_cannot_disappear(self):
        for machine in (62, 183):
            reference = self.symbols(machine)
            candidate = self.symbols(machine, alias='$dtrace123.other')
            with self.subTest(machine=machine), self.assertRaisesRegex(ValueError, 'symbols differ'):
                checker.compare_archive_symbols(candidate, reference)

    def test_definition_cannot_become_an_unresolved_reference(self):
        for machine in (62, 183):
            reference = self.symbols(machine)
            candidate = self.symbols(machine, defined=False)
            with self.subTest(machine=machine), self.assertRaisesRegex(ValueError, 'symbols differ'):
                checker.compare_archive_symbols(candidate, reference)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--nm', type=Path, required=True)
    options, remaining = parser.parse_known_args()
    NM = options.nm.resolve(strict=True)
    unittest.main(argv=[sys.argv[0], *remaining])
