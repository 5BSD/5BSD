#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run the scripted installer with disposable files and mocked disk operations."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / 'usr.sbin/bsdinstall/scripts'

class ScriptedSigning(unittest.TestCase):
    def run_install(self, signed=True, failure='', media=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('config', 'bin', 'target/etc', 'target/tmp', 'tmp', 'media/repos', 'media/keys'):
                (root / name).mkdir(parents=True, exist_ok=True)
            (root / 'config/common.subr').write_text('''f_dprintf() { :; }
f_include() { :; }
f_getvar() { file=; }
f_quietly() { :; }
SUCCESS=0
''')
            (root / 'target/etc/resolv.conf').touch()
            (root / 'preamble').write_text('PARTITIONS="fixture-only"\n')
            (root / 'key.pub').write_text('fixture key')
            script = SOURCE.joinpath('script').read_text()
            script = script.replace('BSDCFG_SHARE="/usr/share/bsdconfig"', 'BSDCFG_SHARE="' + str(root / 'config') + '"')
            script = script.replace('/usr/libexec/bsdinstall/repository.subr', str(SOURCE / 'repository.subr'))
            script = script.replace('/usr/5bsd-packages', str(root / 'media'))
            (root / 'script').write_text(script)
            (root / 'bin/bsdinstall').write_text('''#!/bin/sh
printf 'bsdinstall %s\\n' "$*" >> "$TEST_LOG"
if [ "$1" = verify-image ] && [ "$TEST_FAILURE" = verify ]; then exit 1; fi
exit 0
''')
            (root / 'bin/capsign').write_text('''#!/bin/sh
printf 'capsign %s\\n' "$*" >> "$TEST_LOG"
[ "$TEST_FAILURE" != key ]
''')
            for file in (root / 'bin').iterdir():
                file.chmod(0o755)
            env = {k: v for k, v in os.environ.items() if not k.startswith('BSDINSTALL_')}
            env.update(PATH=str(root / 'bin') + ':/bin:/usr/bin',
                       TMPDIR=str(root / 'tmp'), BSDINSTALL_TMPETC=str(root / 'tmpetc'),
                       BSDINSTALL_CHROOT=str(root / 'target'), BSDINSTALL_SKIP_FIRMWARE='yes',
                       PATH_FSTAB=str(root / 'fstab'), debugFile=str(root / 'debug'),
                       TEST_LOG=str(root / 'calls'), TEST_FAILURE=failure, ZFSBOOT_DISKS='')
            if signed and not media:
                env['BSDINSTALL_CODE_PUBLIC_KEY'] = str(root / 'key.pub')
            if media:
                (root / 'media/repos/5BSD-base-offline.conf').write_text('fixture')
                (root / 'media/keys/code.pub').write_text('fixture')
                (root / 'media/keys/repository.pub').write_text('fixture')
            result = subprocess.run(['/bin/sh', str(root / 'script'), str(root / 'preamble')],
                                    env=env, capture_output=True, text=True, timeout=10)
            calls = (root / 'calls').read_text() if (root / 'calls').exists() else ''
            return result, calls

    def test_signed_order(self):
        result, calls = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(calls.index('capsign key-id'), calls.index('bsdinstall scriptedpart'))
        self.assertLess(calls.index('bsdinstall pkgbase'), calls.index('bsdinstall verify-image'))
        self.assertLess(calls.index('bsdinstall verify-image'), calls.index('bsdinstall bootconfig'))

    def test_invalid_key_stops_before_disks(self):
        result, calls = self.run_install(failure='key')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('bsdinstall scriptedpart', calls)
        self.assertNotIn('bsdinstall pkgbase', calls)

    def test_bad_signature_stops_before_bootconfig(self):
        result, calls = self.run_install(failure='verify')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bsdinstall verify-image', calls)
        self.assertNotIn('bsdinstall bootconfig', calls)
        self.assertNotIn('bsdinstall config', calls)

    def test_unsigned_install_still_allowed(self):
        result, calls = self.run_install(signed=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('capsign', calls)
        self.assertNotIn('verify-image', calls)
        self.assertIn('bsdinstall bootconfig', calls)

    def test_signed_media_selects_code_key(self):
        result, calls = self.run_install(media=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('/media/keys/code.pub', calls)
        self.assertIn('bsdinstall verify-image', calls)

if __name__ == '__main__':
    unittest.main()
