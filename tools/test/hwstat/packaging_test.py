#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check package selection and staged file ownership without publishing/installing.

Build and stage hwstat first; HWSTAT_STAGE can select an existing staging tree.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[3]
STAGE = Path(os.environ.get('HWSTAT_STAGE', '/usr/obj/usr/src/hwstat-stage'))


class Packaging(unittest.TestCase):
    def packages(self, debug):
        result = subprocess.run([
            'make', '-C', str(SOURCE / 'packages/hwstat-tests'),
            'REPODIR=/usr/obj/usr/src/repo', 'PKG_VERSION=regression',
            'MK_DEBUG_FILES=' + ('yes' if debug else 'no'),
            '-V', '_ALLPACKAGES'], check=True, text=True, capture_output=True)
        return set(result.stdout.split())

    def test_debug_package_selected(self):
        self.assertEqual(self.packages(True), {'hwstat-tests', 'hwstat-tests-dbg'})

    def test_no_debug_package_when_disabled(self):
        self.assertEqual(self.packages(False), {'hwstat-tests'})

    def test_staged_debug_files_have_package(self):
        metalog = STAGE / 'METALOG'
        self.assertTrue(metalog.is_file(), 'Build and stage hwstat before this test')
        files = list((STAGE / 'usr/lib/debug/usr/tests/usr.sbin/hwstat').glob('*.debug'))
        self.assertTrue(files, 'No compiled test debug files in staging tree')
        with tempfile.TemporaryDirectory(prefix='hwstat-packaging-') as temp:
            subprocess.run(['awk', '-f', str(SOURCE / 'release/scripts/mtree-to-plist.awk'),
                            str(metalog)], cwd=temp, check=True)
            plists = {p.stem: p.read_text().splitlines()
                      for p in Path(temp).glob('hwstat-tests*.plist')}
            for package in plists:
                self.assertIn(package, self.packages(True),
                              'Staged files belong to an undeclared package')
            debug = plists['hwstat-tests-dbg']
            for file in files:
                path = '/' + str(file.relative_to(STAGE))
                self.assertTrue(any(line.endswith(' ' + path) for line in debug), path)


if __name__ == '__main__':
    unittest.main()
