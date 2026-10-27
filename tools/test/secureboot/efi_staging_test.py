# SPDX-License-Identifier: BSD-2-Clause
"""Native regression of actual loader functions with simulated EFI allocation.

This does not qualify firmware behavior or boot. Large copies are counted;
small-payload relocation executes memmove and checks retained bytes/offsets.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

class Staging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        here = Path(__file__).resolve().parent
        source = (here.parents[2]/'stand/efi/loader/copy.c').read_text()
        start = source.index('static bool\nefi_check_space_exact(')
        functions = source[start:source.index('\nvoid *\nefi_translate(', start)]
        fixture = (here/'efi_staging_fixture.c').read_text()
        assert fixture.count('/* INSERT_LOADER_FUNCTIONS */') == 1
        root = Path(cls.temp.name)
        (root/'test.c').write_text(fixture.replace('/* INSERT_LOADER_FUNCTIONS */', functions))
        cls.binary = root/'test'
        subprocess.run(['/usr/bin/cc','-Wall','-Wextra','-Werror','-O2',
            str(root/'test.c'),'-o',str(cls.binary)],check=True)

    def test_allocation_and_relocation(self):
        for case in ('large','fragmented','unavailable','overflow','after','postexit','contents'):
            with self.subTest(case=case):
                result = subprocess.run([str(self.binary),case],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                if case == 'large': print(result.stdout.strip())

if __name__ == '__main__': unittest.main()
