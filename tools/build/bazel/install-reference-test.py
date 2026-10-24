#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""CLI guards for the Make installation reference; never builds or installs."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

p = argparse.ArgumentParser(description=__doc__)
for name in ('src', 'objtop', 'profile', 'work'):
    p.add_argument('--' + name, type=Path, required=True)
a = p.parse_args()
work = a.work.resolve()
if not work.is_relative_to('/usr/obj') or work == Path('/usr/obj') or work.exists():
    p.error('work must be fresh below /usr/obj')
work.mkdir(parents=True)


class Guards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=work)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'output'

    def tearDown(self):
        self.temporary.cleanup()

    def rejected(self, **options):
        settings = dict(src=a.src, objtop=a.objtop, profile=a.profile,
                        component=a.src / 'lib/libmd', output=self.output, jobs=1)
        settings.update(options)
        command = [sys.executable, '-B', str(Path(__file__).with_name('install-reference.py'))]
        for name, value in settings.items():
            command += ['--' + name, str(value)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        return result.stderr

    def test_reused_output_preserved(self):
        self.output.mkdir()
        sentinel = self.output / 'receipt.json'
        sentinel.write_bytes(b'previous evidence')
        self.assertIn('fresh', self.rejected())
        self.assertEqual(sentinel.read_bytes(), b'previous evidence')
        self.assertEqual(list(self.output.iterdir()), [sentinel])

    def test_copied_component_rejected(self):
        copied = self.root / 'copied'
        copied.mkdir(); (copied / 'Makefile').write_text('all:\n')
        self.assertIn('actual source tree', self.rejected(component=copied))
        self.assertFalse(self.output.exists())

    def test_profile_mismatch_before_output(self):
        profile = self.root / 'profile'
        profile.write_text('TARGET=wrong\n')
        self.assertIn('profile differs', self.rejected(profile=profile))
        self.assertFalse(self.output.exists())

    def test_output_symlink_escape(self):
        with tempfile.TemporaryDirectory() as outside:
            alias = self.root / 'alias'
            alias.symlink_to(outside, target_is_directory=True)
            self.assertIn('below /usr/obj', self.rejected(output=alias / 'escaped'))
            self.assertFalse((Path(outside) / 'escaped').exists())

    def test_make_expansion_and_control_paths(self):
        for suffix in ('bad$path', 'bad\npath'):
            with self.subTest(suffix=suffix):
                destination = self.root / suffix
                self.assertIn('control characters or Make expansion', self.rejected(output=destination))
                self.assertFalse(destination.exists())

    def test_invalid_parallelism_before_output(self):
        self.assertIn('positive', self.rejected(jobs=0))
        self.assertFalse(self.output.exists())


unittest.main(argv=['install-reference-test'])
