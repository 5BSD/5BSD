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


    def test_explicit_inputs(self):
        with tempfile.TemporaryDirectory(prefix='newvers inputs ') as directory:
            root = Path(directory)
            tools = root / 'tools'
            tools.mkdir()
            # This PATH cannot run Make, Git, date, hostname, touch or dirname.
            for tool in ('awk', 'sed', 'cat'):
                (tools / tool).symlink_to(shutil.which(tool))
            for name, original in [('param.h', SOURCE / 'sys/sys/param.h'),
                                   ('COPYRIGHT', SOURCE / 'COPYRIGHT'),
                                   ('template', SOURCE / 'share/examples/etc/bsd-style-copyright')]:
                shutil.copyfile(original, root / name)
            env = {'PATH': str(tools), 'PARAMFILE': str(root / 'param.h'),
                   'NEWVERS_COPYRIGHT': str(root / 'COPYRIGHT'),
                   'NEWVERS_COPYRIGHT_TEMPLATE': str(root / 'template'),
                   'NEWVERS_IDENT': 'GENERIC', 'NEWVERS_COMPILER_VERSION': 'fixture version 1',
                   'NEWVERS_SOURCE_REVISION': 'dev-n123-abcdef-dirty',
                   'MAKE': '/missing/make', 'SOURCE_DATE_EPOCH': 'invalid',
                   'USER': 'ignored', 'HOSTNAME': 'ignored'}
            script = str(SOURCE / 'sys/conf/newvers.sh')
            first = subprocess.run(['/bin/sh', script, '-e'], cwd=root, env=env,
                                   capture_output=True, timeout=10)
            self.assertEqual(first.returncode, 0, first.stderr)
            content = (root / 'vers.c').read_bytes()
            self.assertIn(b'dev-n123-abcdef-dirty GENERIC', content)
            self.assertFalse((root / 'version').exists())
            second = subprocess.run(['/bin/sh', script, '-e'], cwd=root,
                                    env=dict(env, USER='different', HOSTNAME='different'),
                                    capture_output=True, timeout=10)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(content, (root / 'vers.c').read_bytes())
            cases = [(key, None) for key in ('PARAMFILE', 'NEWVERS_COPYRIGHT',
                      'NEWVERS_COPYRIGHT_TEMPLATE', 'NEWVERS_IDENT',
                      'NEWVERS_COMPILER_VERSION', 'NEWVERS_SOURCE_REVISION')]
            cases += [('NEWVERS_IDENT', 'bad"ident'), ('NEWVERS_COMPILER_VERSION', 'bad\nversion'),
                      ('NEWVERS_SOURCE_REVISION', 'bad\\revision'),
                      ('NEWVERS_COPYRIGHT_TEMPLATE', str(root / 'missing')),
                      ('PARAMFILE', str(root / 'missing'))]
            for key, value in cases:
                with self.subTest(key=key, value=value):
                    (root / 'vers.c').unlink(missing_ok=True)
                    bad = dict(env)
                    if value is None:
                        del bad[key]
                    else:
                        bad[key] = value
                    result = subprocess.run(['/bin/sh', script, '-e'], cwd=root, env=bad,
                                            capture_output=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertFalse((root / 'vers.c').exists())
                    self.assertFalse((root / 'version').exists())
            result = subprocess.run(['/bin/sh', script, '-e'], cwd=root,
                                    env=dict(env, NEWVERS_SOURCE_REVISION=''),
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            (root / 'vers.c').unlink()
            (root / 'vers.c').mkdir()
            result = subprocess.run(['/bin/sh', script, '-e'], cwd=root, env=env,
                                    capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / 'version').exists())

if __name__ == '__main__':
    unittest.main()
