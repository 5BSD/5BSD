# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the real version script with native SDK tools and no host PATH."""
import argparse
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
import loader_version

parser = argparse.ArgumentParser()
for name in ['shell', 'script', 'awk', 'mktemp', 'cat', 'mv', 'rm']:
    parser.add_argument('--' + name, type=Path, required=True)
parser.add_argument('--runtime', type=Path, action='append', default=[])
args, remaining = parser.parse_known_args()
root = Path(os.environ['TEST_SRCDIR'])
for name in ['shell', 'script', 'awk', 'mktemp', 'cat', 'mv', 'rm']:
    setattr(args, name, (root / getattr(args, name)).resolve(strict=True))
args.runtime = [(root / p).resolve(strict=True) for p in args.runtime]


class VersionTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.version = self.root / 'version input'; self.version.write_text('4.12: current\n3.0: old\n')
        self.output = self.root / 'version output.c'
        self.policy = self.root / 'metadata.json'
        self.values = dict(date='Tue Jan  1 08:00:00 UTC 2019', user='builder', host='example.invalid', build_utc='1546329600')
        self.policy.write_text(json.dumps(self.values))

    def generate(self, reproducible=True, policy=None, output=None):
        inputs = argparse.Namespace(**vars(args), version=self.version, output=output or self.output,
            machine='test64', description='loader fixture', reproducible=reproducible, metadata=policy)
        loader_version.generate(inputs)

    def test_reproducible_uses_actual_revision_and_no_host_commands(self):
        self.generate()
        self.assertEqual(self.output.read_text(), 'char bootprog_info[] = "5BSD/test64 loader fixture, Revision 4.12\\n";\nunsigned bootprog_rev = 4 * 1000 + 12;\n')

    def test_metadata_mode_preserves_all_explicit_values(self):
        self.generate(False, self.policy)
        result = self.output.read_text()
        self.assertIn('(Tue Jan  1 08:00:00 UTC 2019 builder@example.invalid)\\n', result)
        self.assertIn('\\0@(#)BUILD_UTC=1546329600', result)
        self.assertIn('Revision 4.12\\n', result)

    def test_changed_revision_and_metadata_are_inputs(self):
        self.generate(False, self.policy); before = self.output.read_bytes()
        self.version.write_text('5.2: changed\n'); self.values['host'] = 'other.invalid'; self.policy.write_text(json.dumps(self.values))
        self.generate(False, self.policy)
        self.assertNotEqual(self.output.read_bytes(), before)
        self.assertIn('Revision 5.2\\n', self.output.read_text())
        self.assertIn('@other.invalid', self.output.read_text())

    def test_metadata_required_and_empty_date_rejected(self):
        with self.assertRaises(ValueError): self.generate(False)
        self.values['date'] = ''; self.policy.write_text(json.dumps(self.values))
        with self.assertRaises(ValueError): self.generate(False, self.policy)
        self.assertFalse(self.output.exists())

    def test_unsafe_and_unknown_metadata_rejected(self):
        for field, value in [('user', 'bad"quote'), ('host', 'bad\\slash'), ('date', 'bad\nline'), ('build_utc', 'nan'), ('extra', 'unknown')]:
            values = dict(self.values); values[field] = value; self.policy.write_text(json.dumps(values))
            with self.subTest(field=field), self.assertRaises(ValueError): self.generate(False, self.policy)
            self.assertFalse(self.output.exists())

    def test_output_cannot_replace_input_or_hardlink(self):
        with self.assertRaises(ValueError): self.generate(output=self.version)
        alias = self.root / 'alias'; alias.hardlink_to(self.version)
        with self.assertRaises(ValueError): self.generate(output=alias)
        self.assertEqual(self.version.read_text(), '4.12: current\n3.0: old\n')

    def test_missing_revision_fails_without_partial_output(self):
        self.version.write_text('invalid revision\n')
        with self.assertRaises(subprocess.CalledProcessError): self.generate()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob('version output.c.*')), [])


if __name__ == '__main__':
    unittest.main(argv=[__file__, *remaining])
