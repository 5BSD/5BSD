#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the real Lua installer with isolated package-command fixtures."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / 'usr.sbin/bsdinstall/scripts/pkgbase.in'

class OfflinePkgbase(unittest.TestCase):
    def run_installer(self, mode='', override=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bindir = root / 'bin'
            bindir.mkdir()
            media = root / 'media'
            media.mkdir()
            (media / '5BSD-base-offline.conf').write_text('fixture')
            script = root / 'pkgbase'
            script.write_text(SOURCE.read_text().replace('/usr/5bsd-packages/repos/', str(media) + '/').replace('%%_ALL_libcompats%%', '32'))
            (bindir / 'pkg').write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$TEST_LOG"
case "$*" in
-N) exit 0 ;;
*' update') [ "$TEST_MODE" != update ] ;;
*'rquery '*) printf '%s\\n' 5BSD-set-minimal 5BSD-set-base 5BSD-kernel-generic pkg ;;
*'install -U -F '*) [ "$TEST_MODE" != fetch ] ;;
*) exit 0 ;;
esac
''')
            (bindir / 'bsddialog').write_text('#!/bin/sh\necho UNEXPECTED_DIALOG >> "$TEST_LOG"\nexit 1\n')
            for executable in bindir.iterdir():
                executable.chmod(0o755)
            env = dict(os.environ, PATH=str(bindir) + ':/bin:/usr/bin',
                       BSDINSTALL_CHROOT=str(root / 'target'), COMPONENTS='base',
                       TEST_LOG=str(root / 'calls'), TEST_MODE=mode)
            env.pop('BSDINSTALL_PKG_REPOS_DIR', None)
            if override:
                env['BSDINSTALL_PKG_REPOS_DIR'] = str(root / 'explicit')
            result = subprocess.run(['/usr/libexec/flua', str(script), '--non-interactive'],
                                    env=env, capture_output=True, text=True, timeout=10)
            calls = (root / 'calls').read_text()
            self.assertNotIn('UNEXPECTED_DIALOG', calls)
            expected = root / ('explicit' if override else 'media')
            self.assertIn('--repo-conf-dir ' + str(expected), calls)
            return result.returncode, calls

    def test_media_selected_without_interactive_setup(self):
        code, calls = self.run_installer()
        self.assertEqual(code, 0)
        self.assertIn('install -U -y -r 5BSD-base', calls)

    def test_explicit_repository_wins(self):
        self.assertEqual(self.run_installer(override=True)[0], 0)

    def test_update_failure_exits_without_prompt(self):
        code, calls = self.run_installer('update')
        self.assertEqual(code, 1)
        self.assertEqual(sum(line.endswith(' update') for line in calls.splitlines()), 1)

    def test_fetch_failure_exits_without_prompt(self):
        code, calls = self.run_installer('fetch')
        self.assertEqual(code, 1)
        self.assertEqual(calls.count('install -U -F'), 1)

if __name__ == '__main__':
    unittest.main()
