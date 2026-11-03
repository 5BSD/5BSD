# SPDX-License-Identifier: BSD-2-Clause
"""Only ntptime's help path: exits before reading or changing the host clock."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import unittest


def program_environment():
    parser = argparse.ArgumentParser()
    parser.add_argument('--program-runtime', nargs='+', required=True)
    args, unittest_args = parser.parse_known_args()
    sys.argv[1:] = unittest_args
    libraries = {Path(path).resolve(strict=True) for path in args.program_runtime}
    environment = dict(os.environ)
    environment.pop('LD_PRELOAD', None)
    environment['LD_LIBRARY_PATH'] = ':'.join(sorted({str(path.parent) for path in libraries}))
    return environment, libraries


PROGRAM_ENVIRONMENT, PROGRAM_LIBRARIES = program_environment()


class HelpTest(unittest.TestCase):
    def test_declared_program_libraries(self):
        root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        environment = dict(PROGRAM_ENVIRONMENT, LD_TRACE_LOADED_OBJECTS='1',
                           LD_TRACE_LOADED_OBJECTS_FMT1='%o|%p\\n',
                           LD_TRACE_LOADED_OBJECTS_FMT2='%o|%p\\n')
        result = subprocess.run([str(root / 'usr.sbin/ntp/ntptime/ntptime')], env=environment,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        paths = []
        for line in result.stdout.splitlines():
            name, path = line.split('|')
            if name == path == '[vdso]':
                continue
            loaded = Path(path).resolve(strict=True)
            self.assertIn(loaded, PROGRAM_LIBRARIES)
            paths.append(loaded)
        self.assertTrue(paths)

    def test_help_exits_before_clock_operations(self):
        root=Path(os.environ['TEST_SRCDIR'])/os.environ['TEST_WORKSPACE']
        result=subprocess.run([str(root/'usr.sbin/ntp/ntptime/ntptime'),'-h'],
            env=PROGRAM_ENVIRONMENT, capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,2)
        self.assertEqual(result.stdout,'')
        self.assertIn('usage:',result.stderr)
        self.assertIn('display this help info',result.stderr)


if __name__=='__main__':unittest.main()
