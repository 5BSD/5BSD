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
        aliases = [
            ('usr.sbin/switchboardctl/Makefile',
             'SYMLINKS+= ../..${BINDIR}/${PROG} /usr/sbin/${PROG}',
             'SwitchBoardControl.cap/Units/switchboardctl.unit/bin/switchboardctl', 'switchboardctl'),
            ('usr.sbin/capsulectl/Makefile',
             'SYMLINKS+= ../..${BINDIR}/${PROG} /usr/sbin/${PROG}',
             'CapsuleControl.cap/Units/capsulectl.unit/bin/capsulectl', 'capsulectl'),
            ('usr.sbin/bluetooth/BSDBluetooth/Makefile',
             'SYMLINKS=\t../..${BLUED_CAP_BIN}/BSDBluetooth /usr/sbin/blued',
             'Bluetooth.cap/Units/blued.unit/bin/BSDBluetooth', 'blued'),
        ]
        for source, definition, executable, name in aliases:
            with self.subTest(alias=name), tempfile.TemporaryDirectory() as temp:
                self.assertIn(definition, (ROOT/source).read_text())
                stage = Path(temp)
                target = stage/'Capabilities/System'/executable
                target.parent.mkdir(parents=True)
                target.write_text('fixture')
                alias = stage/'usr/sbin'/name
                alias.parent.mkdir(parents=True)
                alias.symlink_to('../../Capabilities/System/' + executable)
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
