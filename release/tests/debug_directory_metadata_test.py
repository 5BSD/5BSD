# SPDX-License-Identifier: BSD-2-Clause
"""Exercise real debug installation and METALOG output without root privileges."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2]


class DebugDirectories(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.root = self.work / 'root'; self.root.mkdir()
        self.log = self.work / 'METALOG'
        (self.work / 'fixture.debug').write_bytes(b'debug input\n')

    def install(self, target, existing=False, file_group="wheel"):
        if existing:
            (self.root / target.lstrip('/')).mkdir(parents=True)
        (self.work / 'Makefile').write_text(
            'MK_DEBUG_FILES= yes\nDEBUG_FLAGS= -g\n'
            'DEBUGDIR= /usr/lib/debug\nDEBUGFILEDIR= ' + target + '\n'
            'DEBUGFILE= fixture.debug\nDEBUGOWN= root\nDEBUGGRP= ' + file_group + '\n'
            'DEBUGDIROWN= root\nDEBUGDIRGRP= wheel\nDEBUGDIRMODE= 0755\n'
            'DEBUGMODE= 0444\nNO_ROOT= yes\nTAG_ARGS= -T package=fixture\n'
            '.include <bsd.debug.mk>\n')
        result = subprocess.run(['make', '-m', str(SOURCE / 'share/mk'),
            '-C', str(self.work), '_debuginstall', 'DESTDIR=' + str(self.root),
            'INSTALL=install -U -M ' + str(self.log) + ' -D ' + str(self.root)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return self.log.read_text().splitlines()

    def check_hierarchy(self, existing):
        target = '/usr/lib/debug/Capabilities/System/Fixture.cap/Units/fixture.unit'
        rows = self.install(target, existing)
        parents = [target]
        while str(Path(parents[-1]).parent) != '/usr/lib/debug':
            parents.append(str(Path(parents[-1]).parent))
        directory_rows = [row for row in rows if ' type=dir ' in row]
        self.assertEqual(len(directory_rows), len(parents))
        self.assertEqual([row.split()[0] for row in directory_rows],
                         ['.' + p for p in reversed(parents)])
        for row in directory_rows:
            for field in ('uname=root', 'gname=wheel', 'mode=0755', 'tags=package=fixture,dbg'):
                self.assertIn(field, row)
        self.assertEqual((self.root / target.lstrip('/') / 'fixture.debug').read_bytes(), b'debug input\n')

    def test_new_hierarchy(self):
        self.check_hierarchy(False)

    def test_existing_hierarchy_is_recorded_again(self):
        self.check_hierarchy(True)

    def test_special_file_group_does_not_change_shared_directory(self):
        rows = self.install('/usr/lib/debug/usr/sbin', file_group='operator')
        for row in rows:
            if ' type=dir ' in row:
                self.assertIn('gname=wheel', row)
        files = [row for row in rows if ' type=file ' in row]
        self.assertEqual(len(files), 1)
        self.assertIn('gname=operator', files[0])

    def test_nonbase_debug_directory_records_leaf(self):
        rows = self.install('/opt/example/.debug', True)
        self.assertEqual(len([r for r in rows if ' type=dir ' in r]), 1)
        self.assertTrue(any(r.startswith('./opt/example/.debug type=dir ') for r in rows))


if __name__ == '__main__':
    unittest.main()
