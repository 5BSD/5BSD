#!/usr/bin/env python3
"""Exercise metadata-only migration archives through the maintained make rules."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]

class PackageTransition(unittest.TestCase):
    def build(self, directory, metadata):
        (directory/'stage').mkdir()
        (directory/'fixture.plist').write_text('')
        (directory/'fixture.ucl').write_text('comment="fixture"; desc="fixture";')
        (directory/'Makefile').write_text('WORLDPACKAGE=fixture\nSUBPACKAGES=\n'
            + ('PKG_METADATA_ONLY=fixture\nPKG_DEPS.fixture=clibs-dev\n' if metadata else '')
            + '.include <bsd.pkg.mk>\n')
        cmd = ['make', '-m', str(ROOT/'share/mk'), '-C', str(directory),
            'SRCTOP='+str(ROOT), 'REPODIR='+str(directory/'repo'),
            'WSTAGEDIR='+str(directory/'stage'), 'PKG_VERSION=1',
            'PKG_ABI=FreeBSD:16:amd64', 'PKG_OSVERSION=1600000',
            'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
            'FLUA='+os.environ.get('FLUA', '/usr/libexec/flua'), 'stagepackages']
        env = dict(os.environ, MAKEOBJDIR=str(directory))
        return subprocess.run(cmd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def test_normal_empty_package_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            result = self.build(directory, False)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('Refusing to build empty package', result.stdout)
            self.assertFalse(list(directory.rglob('*.pkg')))

    def test_explicit_metadata_archive_and_dependency(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            result = self.build(directory, True)
            self.assertEqual(result.returncode, 0, result.stdout)
            archive = directory/'repo/FreeBSD:16:amd64/1/5BSD-fixture-1.pkg'
            manifest = json.loads(subprocess.check_output(['pkg','info','-F',str(archive), '--raw-format','json','-R'],text=True))
            self.assertFalse(manifest.get('files'))
            self.assertEqual(manifest['deps']['5BSD-clibs-dev']['origin'], 'base/5BSD-clibs-dev')
            self.assertEqual(manifest['deps']['5BSD-clibs-dev']['version'], '1')

    def test_pf_transition_retains_identity(self):
        source = (ROOT/'packages/pf/Makefile').read_text()
        self.assertIn('PKG_METADATA_ONLY=\tpf-dev', source)
        self.assertIn('PKG_DEPS.pf-dev=\tclibs-dev', source)
        self.assertIn('SUBPACKAGES=\tdbg dev man', source)

if __name__ == '__main__':
    unittest.main()
