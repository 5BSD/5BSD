# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual installed rescue layout in private test storage only."""
import json
import os
from pathlib import Path
import shlex
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
ARCHIVE = ROOT / 'rescue/rescue/install_archive.tar'
MANIFEST = ROOT / 'rescue/rescue/install_manifest.json'
CONFIG = ROOT / 'rescue/rescue/rescue_dispatch.generated/rescue.conf'

class InstalledRescue(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR'])
        cls.stage = Path(cls.storage.name)
        with tarfile.open(ARCHIVE) as archive:
            # The standard tar filter preserves installed modes; data adds owner-write.
            archive.extractall(cls.stage, filter='tar')
        cls.records = json.loads(MANIFEST.read_text())['files']
        cls.program = cls.stage / 'rescue/rescue'

    @classmethod
    def tearDownClass(cls):
        cls.storage.cleanup()

    def run_app(self, path, *args, argv0=None, data=b''):
        executable = self.stage / 'rescue' / path
        return subprocess.run([argv0 or str(executable), *args], executable=str(executable),
            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            env=dict(os.environ, LC_ALL='C', DTRACE_DOF_INIT_DISABLE='1'), check=False)

    def test_named_dispatch_and_inventory(self):
        names = []
        for line in CONFIG.read_text().splitlines():
            fields = shlex.split(line)
            if fields[0] == 'progs':
                names.extend(fields[1:])
            elif fields[0] == 'ln':
                names.extend(fields[2:])
        p = self.run_app('rescue', '--list')
        self.assertEqual((p.returncode, p.stdout.split(), p.stderr),
            (0, [name.encode() for name in names], b''))
        direct = self.run_app('rescue', 'echo', 'installed rescue')
        link = self.run_app('echo', 'installed rescue')
        self.assertEqual((direct.returncode, direct.stdout, direct.stderr), (0, b'installed rescue\n', b''))
        self.assertEqual((direct.returncode, direct.stdout, direct.stderr),
            (link.returncode, link.stdout, link.stderr))

    def test_hardlinks_and_suppressed_login_names(self):
        binary = self.program.stat()
        for record in self.records:
            path = self.stage / record['destination'].lstrip('/')
            with self.subTest(path=record['destination']):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), int(record['mode'], 8))
                if record['type'] == 'hardlink':
                    self.assertEqual(record['link'], '/rescue/rescue')
                    self.assertEqual((path.stat().st_dev, path.stat().st_ino), (binary.st_dev, binary.st_ino))
        for name in ['-sh', '-csh', '-tcsh']:
            self.assertFalse((self.stage / 'rescue' / name).exists())
        p = self.run_app('rescue', '-c', "printf '%s\\n' login-shell", argv0='-sh')
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b'login-shell\n', b''))

    def test_executable_path_shell_fallback(self):
        # su may replace argv[0]; AT_EXECPATH still names the installed sh link.
        p = self.run_app('sh', '-c', "printf '%s\\n' execpath-shell", argv0='_su')
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b'execpath-shell\n', b''))

    def test_private_binary_stdin(self):
        data = bytes(range(256)) * 8
        p = self.run_app('cat', data=data)
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, data, b''))
        p = self.run_app('[', 'one', '=', 'one', ']')
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b'', b''))

    def test_script_and_no_debug_installation(self):
        path = self.stage / 'rescue/dhclient-script'
        self.assertEqual(path.read_bytes().splitlines()[0], b'#!/rescue/sh')
        self.assertEqual({v['destination'] for v in self.records if v['type'] == 'file'},
            {'/rescue/rescue', '/rescue/dhclient-script'})
        self.assertFalse(any('.debug' in v['destination'] for v in self.records))

    def test_static_installed_elf(self):
        data = self.program.read_bytes()
        h = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
        self.assertEqual(h[0][:5], b'\x7fELF\x02')
        self.assertEqual(h[1:3], (2, 62))
        headers = [struct.unpack_from('<IIQQQQQQ', data, h[5] + i*h[9]) for i in range(h[10])]
        self.assertFalse(any(p[0] in [2, 3] for p in headers))
        self.assertFalse(next(p[1] for p in headers if p[0] == 0x6474e551) & 1)
        self.assertTrue(any(p[0] == 0x6474e552 for p in headers))

if __name__ == '__main__':
    unittest.main()
