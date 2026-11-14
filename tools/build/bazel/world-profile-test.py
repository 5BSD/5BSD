# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the maintained source-option profile writer with actual Make."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

MAKE = PRODUCER = None


class WorldProfiles(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR'])
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.objects = self.root / 'objects'
        self.objects.mkdir()
        self.makefile = self.root / 'Makefile'

    def run_make(self, options, *, object_root=True, default_target=False):
        self.makefile.write_text('SRC_OPT_LIST = ' + ' '.join(options) + '\n.include "' + str(PRODUCER) + '"\n')
        if default_target:
            with self.makefile.open('a') as stream:
                stream.write("all:\n\t@printf '%s\\n' done > ${TEST_MARKER:Q}\n")
        argv = [str(MAKE), '-r', '-f', str(self.makefile)]
        if object_root:
            argv += ['OBJTOP=' + str(self.objects)]
        argv += ['TEST_MARKER=' + str(self.root / 'default-target')] if default_target else ['src-options-metadata']
        environment = dict(os.environ)
        for name in ('MAKEFLAGS', 'MFLAGS', 'MAKEOVERRIDES', 'MAKELEVEL', 'MAKEOBJDIRPREFIX', 'OBJTOP'):
            environment.pop(name, None)
        return subprocess.run(argv, cwd=self.root, env=environment, capture_output=True, text=True)

    def test_new_option_export_needs_no_inventory_change(self):
        options = ['TARGET=arm64', 'TARGET_ARCH=aarch64', 'WITH_FUTURE_SERVICE=1',
                   'WITH_MALLOC_PRODUCTION=1', 'WITH_FUTURE_SERVICE=1']
        result = self.run_make(options)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.objects / '.src_opts').read_text().splitlines(), sorted(set(options)))
        self.assertFalse((self.objects / '.src_opts.tmp').exists())

    def test_new_profile_replaces_stale_allocator_selection(self):
        result = self.run_make(['TARGET=arm64', 'TARGET_ARCH=aarch64', 'WITHOUT_MALLOC_PRODUCTION=1'])
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_make(['TARGET=arm64', 'TARGET_ARCH=aarch64', 'WITH_MALLOC_PRODUCTION=1'])
        self.assertEqual(result.returncode, 0, result.stderr)
        text = (self.objects / '.src_opts').read_text()
        self.assertIn('WITH_MALLOC_PRODUCTION=1\n', text)
        self.assertNotIn('WITHOUT_MALLOC_PRODUCTION', text)

    def test_missing_inputs_fail_without_publishing(self):
        for options, object_root in [([], True), (['TARGET=arm64'], False)]:
            with self.subTest(object_root=object_root):
                self.assertNotEqual(self.run_make(options, object_root=object_root).returncode, 0)
                self.assertFalse((self.objects / '.src_opts').exists())

    def test_include_does_not_replace_callers_default_target(self):
        result = self.run_make(['TARGET=arm64'], default_target=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'default-target').read_text(), 'done\n')
        self.assertFalse((self.objects / '.src_opts').exists())

    def test_write_failure_keeps_previous_profile(self):
        profile = self.objects / '.src_opts'
        profile.write_text('old profile\n')
        (self.objects / '.src_opts.tmp').mkdir()
        self.assertNotEqual(self.run_make(['TARGET=arm64']).returncode, 0)
        self.assertEqual(profile.read_text(), 'old profile\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--make', type=Path, required=True)
    parser.add_argument('--producer', type=Path, required=True)
    args, remaining = parser.parse_known_args()
    MAKE, PRODUCER = args.make.resolve(strict=True), args.producer.resolve(strict=True)
    unittest.main(argv=[sys.argv[0], *remaining])
