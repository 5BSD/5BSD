# SPDX-License-Identifier: BSD-2-Clause
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class OsreldateTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        self.tools = self.root / 'osreldate-tools'
        self.shell = self.tools / 'sh'
        self.script = self.root / 'include/mk-osreldate.sh'
        self.newvers = self.root / 'sys/conf/newvers.sh'
        self.env = dict(PATH=str(self.tools), LC_ALL='C', NEWVERS_SH=str(self.newvers),
            PARAMFILE=str(self.root / 'sys/sys/param.h'), NEWVERS_COPYRIGHT=str(self.root / 'COPYRIGHT'),
            NEWVERS_COPYRIGHT_TEMPLATE=str(self.root / 'share/examples/etc/bsd-style-copyright'))

    def run_generator(self, directory, env):
        return subprocess.run([str(self.shell), str(self.script), '-s'], cwd=directory,
                              env=env, capture_output=True, timeout=10)

    def test_native_default_and_changed_inputs(self):
        normal = (self.root / 'include/generated/osreldate.h').read_bytes()
        version = re.search(rb'^#define\s+__FreeBSD_version\s+(\d+)',
                            (self.root / 'sys/sys/param.h').read_bytes(), re.M)[1]
        self.assertIn(b'#define __FreeBSD_version ' + version + b'\n', normal)
        fixture = self.root / 'tools/build/bazel/tests/osreldate'
        future = (fixture / 'future/osreldate.h').read_bytes()
        self.assertIn(b'1992-2099 The FreeBSD Project.', future)
        self.assertIn(b'#define __FreeBSD_version 1700042\n', future)
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_generator(directory, dict(self.env, PARAMFILE=str(fixture / 'param.h'),
                                                        NEWVERS_COPYRIGHT=str(fixture / 'COPYRIGHT')))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, future)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_missing_inputs_and_invalid_values_do_not_fall_back(self):
        with tempfile.TemporaryDirectory() as directory:
            for key in ['NEWVERS_SH', 'PARAMFILE', 'NEWVERS_COPYRIGHT', 'NEWVERS_COPYRIGHT_TEMPLATE']:
                env = dict(self.env); del env[key]
                with self.subTest(key=key):
                    result = self.run_generator(directory, env)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b'')
            root = Path(directory)
            bad = root / 'bad.h'; bad.write_text('#define __FreeBSD_version $(bad)\n')
            result = self.run_generator(directory, dict(self.env, PARAMFILE=str(bad)))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')
            bad.write_text('missing copyright year\n')
            result = self.run_generator(directory, dict(self.env, NEWVERS_COPYRIGHT=str(bad)))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')
            result = self.run_generator(directory, dict(self.env, NEWVERS_COPYRIGHT_TEMPLATE=str(root / 'absent')))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')

    def test_minimal_queries_do_not_need_copyright_or_version_files(self):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(PATH=str(self.tools), LC_ALL='C', PARAMFILE=self.env['PARAMFILE'])
            version = subprocess.run([str(self.shell), str(self.newvers), '-V', 'RELDATE'],
                env=env, cwd=directory, capture_output=True, timeout=10)
            self.assertEqual(version.returncode, 0, version.stderr)
            env = {k:v for k,v in self.env.items() if k.startswith('NEWVERS_COPYRIGHT') or k in ['PATH', 'LC_ALL']}
            copyright = subprocess.run([str(self.shell), str(self.newvers), '-C'],
                env=env, cwd=directory, capture_output=True, timeout=10)
            self.assertEqual(copyright.returncode, 0, copyright.stderr)
            self.assertIn(b'The FreeBSD Project.', copyright.stdout)
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
