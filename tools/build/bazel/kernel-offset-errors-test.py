#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check failure propagation in maintained kernel include generators."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[3]

class OffsetErrors(unittest.TestCase):
    def test_symbol_reader_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = root / 'invalid.o'
            invalid.write_text('not an object file\n')
            failed = root / 'failed-nm'
            failed.write_text('#!/bin/sh\nprintf "partial output\\n"\nexit 42\n')
            failed.chmod(0o755)
            for name in ('genassym', 'genoffset'):
                for nm, obj in ((str(root / 'missing-nm'), invalid),
                                (str(failed), invalid),
                                ('nm', invalid), ('nm', root / 'missing.o')):
                    for explicit in (False, True):
                        with self.subTest(generator=name, nm=nm, obj=obj.name, explicit=explicit):
                            output = root / 'output.inc'
                            args = ['/bin/sh', str(SOURCE / 'sys/kern' / (name + '.sh'))]
                            if explicit:
                                args += ['-o', str(output)]
                            result = subprocess.run(args + [str(obj)], env=dict(os.environ, NM=nm),
                                                    capture_output=True, timeout=10)
                            self.assertNotEqual(result.returncode, 0)
                            self.assertEqual(output.read_bytes() if explicit else result.stdout, b'')

    def test_transform_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nm = root / 'fixture-nm'
            nm.write_text('#!/bin/sh\nprintf "0000000000000008 C __assym_offset__sample__field__int\\n"\n')
            nm.chmod(0o755)
            for generator, tool in (('genassym', 'awk'), ('genoffset', 'grep'),
                                    ('genoffset', 'sed'), ('genoffset', 'sort')):
                with self.subTest(generator=generator, tool=tool):
                    failed = root / tool
                    failed.write_text('#!/bin/sh\nexit 43\n')
                    failed.chmod(0o755)
                    env = dict(os.environ, NM=str(nm), AWK='awk', PATH=str(root) + ':/bin:/usr/bin')
                    result = subprocess.run(['/bin/sh', str(SOURCE / 'sys/kern' / (generator + '.sh')), 'fixture.o'],
                                            env=env, capture_output=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b'')
                    failed.unlink()

if __name__ == '__main__':
    unittest.main()
