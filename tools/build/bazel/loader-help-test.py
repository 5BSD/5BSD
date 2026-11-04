# SPDX-License-Identifier: BSD-2-Clause
"""Native SDK tool controls; no target executable is run."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import loader_help

parser = argparse.ArgumentParser()
for name in ['awk', 'cat', 'script', 'common', 'fdt']:
    parser.add_argument('--' + name, type=Path, required=True)
args, remaining = parser.parse_known_args()
root = Path(os.environ['TEST_SRCDIR'])
for name, value in vars(args).items():
    setattr(args, name, (root / value).resolve(strict=True))


class HelpTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / 'help'

    def reference(self, sources):
        env = {'LC_ALL': 'C', 'LD_LIBRARY_PATH': os.environ.get('LD_LIBRARY_PATH', '')}
        concatenated = subprocess.run([str(args.cat), *map(str, sources)],
            env=env, capture_output=True, check=True).stdout
        return subprocess.run([str(args.awk), '-f', str(args.script)], input=concatenated,
            env=env, capture_output=True, check=True).stdout

    def generate(self, sources, script=None, output=None):
        loader_help.merge(args.awk, script or args.script, sources,
            output or self.output, [])

    def test_common_recipe(self):
        self.generate([args.common])
        self.assertEqual(self.output.read_bytes(), self.reference([args.common]))

    def test_fdt_then_common_recipe(self):
        self.generate([args.fdt, args.common])
        self.assertEqual(self.output.read_bytes(), self.reference([args.fdt, args.common]))

    def test_unterminated_fragments_concatenate_without_added_bytes(self):
        data = args.common.read_bytes()
        offset = data.index(b'\t') + 5
        first = self.root / 'first'; first.write_bytes(data[:offset])
        second = self.root / 'second'; second.write_bytes(data[offset:])
        self.assertFalse(first.read_bytes().endswith(b'\n'))
        self.generate([first, second])
        self.assertEqual(self.output.read_bytes(), self.reference([args.common]))

    def test_output_cannot_overwrite_input(self):
        source = self.root / 'input'; source.write_bytes(args.common.read_bytes())
        before = source.read_bytes()
        with self.assertRaises(ValueError):
            self.generate([source], output=source)
        self.assertEqual(source.read_bytes(), before)

    def test_missing_source_rejected(self):
        with self.assertRaises(FileNotFoundError):
            self.generate([self.root / 'missing'])
        self.assertFalse(self.output.exists())

    def test_awk_failure_is_not_a_successful_partial_output(self):
        script = self.root / 'broken.awk'; script.write_text('BEGIN { if }\n')
        with self.assertRaises((subprocess.CalledProcessError, BrokenPipeError)):
            self.generate([args.common], script=script)
        self.assertFalse(self.output.exists())

    def test_empty_source_list_rejected(self):
        with self.assertRaises(ValueError):
            self.generate([])
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main(argv=[__file__, *remaining])
