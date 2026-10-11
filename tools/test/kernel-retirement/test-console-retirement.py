#!/usr/bin/env python3
"""Check retired configurations, retained console behavior and fixture isolation."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

SRC = Path(__file__).resolve().parents[3]


class ConsoleRetirement(unittest.TestCase):
    def test_removed_kernel_selections_fail(self):
        for selection in ['device sc', 'device drm2', 'options SCHED_4BSD',
                          'options MAC_NONE', 'options MAC_STUB',
                          'options SC_PIXEL_MODE', 'options IPI_PREEMPTION']:
            with self.subTest(selection=selection), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                conf = root / 'RETIRED'
                conf.write_text('include GENERIC-NODEBUG\n' + selection + '\n')
                result = subprocess.run(['config', '-d', str(root / 'obj'), str(conf)],
                    cwd=SRC / 'sys/amd64/conf', capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('unknown', result.stderr.lower())

    def test_fixtures_not_in_production_even_with_all_modules(self):
        result = subprocess.run(['make', '-C', str(SRC / 'sys/modules'),
            'WITH_TESTS=yes', 'ALL_MODULES=yes', '-V', 'SUBDIR'],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        modules = result.stdout.split()
        for name in ['syscons', 'splash', 'mac_none', 'mac_stub',
                     'mac_capability_test_kernelstore', 'mac_capability_test_keystore']:
            self.assertNotIn(name, modules)
        self.assertIn('pf', modules)
        self.assertIn('dummynet', modules)
        for directory in ['fixtures', 'fixtures/kernelstore', 'fixtures/keystore']:
            result = subprocess.run(['make', '-C', str(SRC / 'tests/sys/mac_capability' / directory),
                '-n', 'install'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('test', result.stderr.lower())

    def test_vt_keymap_font_and_legacy_keymap_translation(self):
        for keymap in ['us', 'us.iso']:
            with self.subTest(keymap=keymap), tempfile.TemporaryDirectory() as td:
                log = Path(td) / 'commands'
                script = (SRC / 'libexec/rc/rc.d/syscons').read_text()
                script = script.replace('. /etc/rc.subr',
                    'load_rc_config() { :; }\nrun_rc_command() { :; }')
                script += '''
kbdcontrol() {
    echo "kbdcontrol $*" >> "$CALL_LOG"
    if [ "$*" = "-l us.iso" ]; then echo "legacy keymap absent"; return 1; fi
}
vidcontrol() { echo "vidcontrol $*" >> "$CALL_LOG"; }
load_kld() { echo "unexpected module load" >> "$CALL_LOG"; return 1; }
kbddev=/dev/null
viddev=/dev/null
keyboard=
keymap=$TEST_KEYMAP
keyrate=NO
keybell=NO
keychange=NO
font8x16=terminus-b32.fnt
font8x14=NO
font8x8=NO
allscreens_kbdflags=
allscreens_flags=
saver=dragon
syscons_start
'''
                env = dict(os.environ, CALL_LOG=str(log), TEST_KEYMAP=keymap)
                result = subprocess.run(['sh'], input=script, env=env,
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = log.read_text()
                self.assertIn('kbdcontrol -l us\n', calls)
                self.assertIn('vidcontrol -f 8x16 terminus-b32.fnt', calls)
                self.assertNotIn('unexpected module load', calls)
                self.assertIn('Configuring vt:', result.stdout)


if __name__ == '__main__':
    unittest.main()
