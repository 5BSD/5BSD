#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Version generation must reject failed metadata producers before publishing C."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[3]

class VersionErrors(unittest.TestCase):
    def test_metadata_producer_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            (source / 'sys/sys').mkdir(parents=True)
            shutil.copyfile(SOURCE / 'sys/sys/param.h', source / 'sys/sys/param.h')
            shutil.copyfile(SOURCE / 'COPYRIGHT', source / 'COPYRIGHT')
            template = source / 'share/examples/etc'
            template.mkdir(parents=True)
            shutil.copyfile(SOURCE / 'share/examples/etc/bsd-style-copyright', template / 'bsd-style-copyright')
            compiler = root / 'compiler'
            make = root / 'make'
            make.write_text('#!/bin/sh\ncase "$2" in\nKERN_IDENT) echo GENERIC; exit "${IDENT_STATUS:-0}";;\nCC) echo "$TEST_COMPILER"; exit "${CC_STATUS:-0}";;\n*) exit 99;;\nesac\n')
            make.chmod(0o755)
            for case, setting, compiler_body in (
                ('ident', {'IDENT_STATUS': '42'}, 'echo "fixture version 1"'),
                ('cc', {'CC_STATUS': '42'}, 'echo "fixture version 1"'),
                ('compiler', {}, 'echo "fixture version 1"; exit 42'),
                ('empty', {}, 'echo "no recognizable banner"'),
                ('valid', {}, 'echo "fixture version 1"'),
            ):
                with self.subTest(case=case):
                    compiler.write_text('#!/bin/sh\n' + compiler_body + '\n')
                    compiler.chmod(0o755)
                    work = source / case
                    work.mkdir()
                    env = {'PATH': '/bin:/usr/bin', 'SYSDIR': str(source / 'sys'),
                           'SOURCE_DATE_EPOCH': '0', 'MAKE': str(make),
                           'TEST_COMPILER': str(compiler), **setting}
                    result = subprocess.run(['/bin/sh', str(SOURCE / 'sys/conf/newvers.sh'), '-r'],
                                            cwd=work, env=env, capture_output=True, timeout=30)
                    if case == 'valid':
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn('const char compiler_version[] = "fixture version 1";',
                                      (work / 'vers.c').read_text())
                    else:
                        self.assertNotEqual(result.returncode, 0, result.stderr)
                        self.assertFalse((work / 'vers.c').exists())

if __name__ == '__main__':
    unittest.main()
