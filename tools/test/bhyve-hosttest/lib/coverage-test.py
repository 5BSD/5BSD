#!/usr/bin/env python3
# Unprivileged failure-path checks for actual guest scripts; no VMs/devices.
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest

KIT = Path(__file__).absolute().parents[1]

class Coverage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'],
                        CASE_ROOT=str(self.root), L2_DEVICE_WORKDIR=str(self.root/'state'),
                        SRTOOL=os.environ.get('SRTOOL', str(KIT/'guest-bin/srtool')))
    def stub(self, name, body):
        p = self.bin/name
        p.write_text('#!/bin/sh\n'+body+'\n')
        p.chmod(0o755)
    def run_script(self, name, *args):
        return subprocess.run(['sh', str(KIT/'guest'/name), *args], env=self.env,
                              capture_output=True, text=True, timeout=30)
    def dtrace_stubs(self):
        self.stub('timeout', 'shift 3; exec "$@"')
        self.stub('dtrace', r'''
case "$*" in *'this is invalid'*)
 case "${MODE:-}" in invalid-success) exit 0 ;; timeout) echo timeout >&2; exit 124 ;; missing-tool) echo not-found >&2; exit 127 ;; crash) echo crash >&2; exit 139 ;; esac
 echo 'syntax error' >&2; exit 1 ;;
esac
case "${MODE:-}" in missing) exit 0 ;; fail-output) echo 'HIT 9'; exit 1 ;; esac
echo 'HIT 9'
''')
    def test_dtrace_positive_and_false_passes(self):
        self.dtrace_stubs()
        p = self.run_script('dtrace-cases.sh')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(p.stdout.count(' PASS'), 6)
        for mode in ('missing', 'fail-output', 'invalid-success', 'timeout', 'missing-tool', 'crash'):
            self.env['MODE'] = mode
            p = self.run_script('dtrace-cases.sh')
            self.assertNotEqual(p.returncode, 0, (mode, p.stdout))
    def test_session_deadline_preserves_child_failure(self):
        text = (KIT/'phases/hypertrace.sh').read_text()
        helper = text.split('trace_session_finished()\n', 1)[1].split('for kind in exec exit;', 1)[0]
        helper = 'trace_session_finished()\n' + helper
        for handler, expected in (('sys.exit(0)', 0), ('sys.exit(139)', 139), ('None', 137)):
            code = 'import signal,sys,time; signal.signal(signal.SIGINT, lambda *a: '+handler+'); print("HIT 9", flush=True); time.sleep(30)'
            p = subprocess.run(['timeout', '--preserve-status', '--foreground', '-s', 'INT', '-k', '1', '1', sys.executable, '-c', code],
                               capture_output=True, text=True, timeout=5)
            status = p.returncode if p.returncode >= 0 else 128 - p.returncode
            self.assertEqual(status, expected, p.stderr)
            self.assertIn('HIT 9', p.stdout)
            (self.root/'case.rc').write_text(str(status))
            verdict = subprocess.run(['sh', '-c', helper+'\nO="$1"; trace_session_finished case', 'fixture', str(self.root)])
            self.assertEqual(verdict.returncode == 0, expected == 0)
    def storage_stubs(self):
        self.stub('kenv', 'case "$2" in hosttest.role) echo l2 ;; *) echo storage ;; esac')
        self.stub('pciconf', 'echo test-inventory')
        self.stub('sync', ':')
        self.stub('mount', '[ "${MODE:-}" != mount-error ] || exit 1; [ "${MODE:-}" != mounted ] || echo "/dev/vtbd1p1 /mnt ufs rw 0 0"; exit 0')
        self.stub('diskinfo', 'echo "$1 512 ${CAPACITY:-16777216}"')
        self.stub('dd', r'''
# Map scratch names only. No real /dev path can reach dd.
new=""
for arg in "$@"; do
 case "$arg" in
 if=/dev/*|of=/dev/*)
  dev=${arg#*=/dev/}; case "$dev" in vtbd1|nda0|nvd0|ada0) ;; *) exit 90 ;; esac
  arg="${arg%%=*}=$CASE_ROOT/$dev" ;;
 esac
 new="$new $arg"
done
exec /bin/dd $new
''')
    def test_setup_failure_does_not_start_console(self):
        self.stub('kldstat', 'exit 0')
        self.stub('sysctl', 'echo 1')
        self.stub('top', 'exit 0')
        self.stub('bhyvectl', 'exit 0')
        self.stub('truncate', 'exit 1')
        self.stub('reader', 'touch "$CASE_ROOT/reader-started"; exit 1')
        ctl = self.root/'vmmctl'
        ctl.touch()
        self.env.update(L2_RUNDIR=str(self.root/'l2'), L2_VMMCTL=str(ctl),
                        L2_CONSOLE_READER=str(self.bin/'reader'), L2_LIVE='none')
        for mode in ('invalid', 'storage'):
            self.env['L2_DEVICES'] = mode
            p = self.run_script('l2-boot.sh', 'fixture')
            self.assertEqual(p.returncode, 6, p.stdout+p.stderr)
            self.assertFalse((self.root/'reader-started').exists())
    def test_storage_roundtrip_and_corruption(self):
        self.storage_stubs()
        for stage in ('before', 'after'):
            p = self.run_script('l2-devices.sh', stage)
            self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
            self.assertEqual(p.stdout.count(' PASS'), 3)
        self.assertEqual(self.run_script('l2-devices.sh', 'before').returncode, 0)
        (self.root/'vtbd1').write_bytes(b'corrupt')
        p = self.run_script('l2-devices.sh', 'after')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('L2-DEVICE virtio-blk after FAIL', p.stdout)
    def test_storage_refuses_mount_and_wrong_capacity(self):
        self.storage_stubs()
        self.env['MODE'] = 'mounted'
        p = self.run_script('l2-devices.sh', 'before')
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse((self.root/'vtbd1').exists())
        self.env['MODE'] = 'mount-error'
        self.assertNotEqual(self.run_script('l2-devices.sh', 'before').returncode, 0)
        self.env['MODE'] = ''
        self.env['CAPACITY'] = '17179869184'
        p = self.run_script('l2-devices.sh', 'before')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout.count('unsafe-or-absent'), 3)

if __name__ == '__main__':
    unittest.main()
