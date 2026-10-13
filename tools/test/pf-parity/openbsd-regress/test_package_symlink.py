#!/usr/bin/env python3
"""Exercise real pkg dependency scanning through the installed command alias."""
from pathlib import Path
import json
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]

class PackageSymlink(unittest.TestCase):
    def test_alias_is_staging_relative(self):
        source = (ROOT/'usr.sbin/switchboardctl/Makefile').read_text()
        self.assertIn('SYMLINKS+= ../..${BINDIR}/${PROG} /usr/sbin/${PROG}', source)
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp)
            target = stage/'Capabilities/System/SwitchBoardControl.cap/Units/switchboardctl.unit/bin/switchboardctl'
            target.parent.mkdir(parents=True)
            target.write_text('fixture')
            alias = stage/'usr/sbin/switchboardctl'
            alias.parent.mkdir(parents=True)
            alias.symlink_to('../../Capabilities/System/SwitchBoardControl.cap/Units/switchboardctl.unit/bin/switchboardctl')
            self.assertEqual(alias.resolve(), target)

    def test_real_package_has_only_staged_elf_dependencies(self):
        def needed(path):
            data = subprocess.check_output(['readelf', '-d', str(path)], text=True)
            return set(re.findall(r'Shared library: \[(.*?)\]', data))
        expected = needed('/usr/bin/true')
        host_only = needed('/bin/sh') - expected
        self.assertTrue(host_only, 'reference host shell must have distinct dependencies')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for form in ['absolute', 'relative']:
                directory = root/form
                stage = directory/'stage'
                (stage/'bin').mkdir(parents=True)
                (stage/'usr/bin').mkdir(parents=True)
                (directory/'out').mkdir()
                shutil.copy('/usr/bin/true', stage/'bin/sh')
                (stage/'usr/bin/probe').symlink_to('/bin/sh' if form == 'absolute' else '../../bin/sh')
                (directory/'manifest').write_text(json.dumps(dict(name='pf-alias-test', version='1', origin='tests/alias', comment='fixture', desc='fixture', maintainer='test@example.invalid', www='https://example.invalid', prefix='/')))
                (directory/'plist').write_text('/bin/sh\n/usr/bin/probe\n')
                subprocess.run(['pkg', '-o', 'ALLOW_BASE_SHLIBS=yes', 'create', '-r', str(stage), '-M', str(directory/'manifest'), '-p', str(directory/'plist'), '-o', str(directory/'out')], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                archive = next((directory/'out').glob('*.pkg'))
                manifest = json.loads(subprocess.check_output(['pkg', 'info', '-F', str(archive), '--raw-format', 'json', '-R'], text=True))
                actual = set(manifest.get('shlibs_required', []))
                if form == 'relative':
                    self.assertEqual(actual, expected)
                else:
                    # Record both vulnerable and fixed external pkg versions;
                    # the maintained relative alias must always be correct.
                    self.assertIn(actual, [expected, expected | host_only])

if __name__ == '__main__':
    unittest.main()
