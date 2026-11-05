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
    def test_virtqueue_aggregate_validation(self):
        output = self.root / 'virtqueue.out'
        good = 'SUBMIT ht-trace1 0 0 16\nCOMPLETE ht-trace1 0 0 16\n'
        cases = [(good, True), (good.replace(' 0 0 ', ' 0 1 '), False),
                 ('', False), (good.replace('ht-trace1', 'ht-trace2'), False),
                 (good.replace(' 16', ' 0'), False),
                 ('SUBMIT ht-trace1 0 0 16\n', False),
                 (good + 'unexpected output\n', False),
                 (good + 'TRANSPORT ht-trace1 0 0 1\n', False),
                 (good.replace('COMPLETE ht-trace1 0 0', 'COMPLETE ht-trace1 0 1'), False)]
        for text, expected in cases:
            output.write_text(text)
            result = subprocess.run(['sh', str(KIT/'lib/virtqueue-check.sh'), str(output)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, expected, text)

        output.write_text(good.replace(' 0 0 ', ' 0 1 '))
        result = subprocess.run(['sh', str(KIT/'lib/virtqueue-check.sh'), str(output), 'yes'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_virtqueue_mode_and_failures(self):
        self.stub('timeout', 'shift 3; exec "$@"')
        self.stub('dtrace', r'''
case "${MODE:-}" in timeout) exit 124 ;; missing-probes) exit 1 ;; esac
[ "${MODE:-}" = missing-workload ] || echo VIRTQUEUE-WORK-DONE
case "${MODE:-}" in packed) ring=1 ;; *) ring=0 ;; esac
case "${MODE:-}" in zero) count=0 ;; *) count=16 ;; esac
echo "SUBMIT 0 $ring $count"
[ "${MODE:-}" = missing-completion ] || echo "COMPLETE 0 $ring $count"
case "${MODE:-}" in noise) echo unexpected ;; failed-exit) exit 1 ;; esac
exit 0
''')
        for mode in ('', 'packed', 'timeout', 'missing-probes', 'missing-workload',
                     'zero', 'missing-completion', 'noise', 'failed-exit'):
            self.env['MODE'] = mode
            p = self.run_script('virtqueue-local.sh', 'no')
            self.assertEqual(p.returncode == 0, mode == '', (mode, p.stdout, p.stderr))
        self.env['MODE'] = 'packed'
        p = self.run_script('virtqueue-local.sh', 'yes')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(p.stdout.strip(), 'VIRTQUEUE-LOCAL-OK packed=1')
        self.env['MODE'] = ''
        self.assertNotEqual(self.run_script('virtqueue-local.sh', 'yes').returncode, 0)
        self.assertEqual(self.run_script('virtqueue-local.sh', 'invalid').returncode, 2)

    def test_capability_runtime_prerequisites(self):
        self.stub('kenv', 'if [ "$#" -eq 0 ]; then case "${MODE:-}" in denied) exit 1 ;; inconsistent) echo capability_plane=YES ;; *) echo unrelated=yes ;; esac; exit 0; fi; case "${MODE:-}" in unset|denied|inconsistent) exit 255 ;; query-error) exit 1 ;; off) echo NO ;; unknown) echo other ;; *) echo YES ;; esac')
        self.stub('kldstat', '[ "${MODE:-}" != no-module ]')
        self.stub('sysctl', 'case "${MODE:-}" in no-enforcement) echo 0 ;; no-sysctl) exit 1 ;; *) echo 1 ;; esac')
        self.stub('pgrep', '[ "${MODE:-}" != no-broker ]')
        for mode in ('', 'unset', 'denied', 'inconsistent', 'query-error', 'off', 'unknown', 'no-module',
                     'no-enforcement', 'no-sysctl', 'no-broker'):
            self.env['MODE'] = mode
            p = self.run_script('capability-check.sh')
            self.assertEqual(p.returncode == 0, mode in ('', 'unset'), (mode, p.stdout, p.stderr))
            self.assertIn('CAPABILITY-PLANE-ON' if p.returncode == 0 else 'CAPABILITY-PLANE-FAIL', p.stdout)

    def test_capability_failure_prevents_guest_markers(self):
        self.stub('kenv', 'case "$2" in hosttest.role) echo "${ROLE:-l1}" ;; capability_plane) echo YES ;; *) echo no ;; esac')
        self.stub('kldstat', 'exit 0')
        self.stub('sysctl', 'echo 1')
        self.stub('pgrep', '[ "${MODE:-}" != no-broker ]')
        self.stub('timeout', '[ "${MODE:-}" != timeout ] || exit 124; shift 3; exec "$@"')
        self.stub('poweroff', 'exit 0')
        self.stub('sleep', 'exit 0')
        console = self.root/'console'
        boot = (KIT/'images/overlay/rc.local').read_text().replace('/dev/console', str(console)).replace('/root/hosttest', str(KIT/'guest')).replace('> $c', '>> $c')
        script = self.root/'rc.local'
        script.write_text(boot)
        for role, mode in (('l1', ''), ('l1', 'no-broker'), ('l2', 'no-broker'), ('l1', 'timeout'), ('l2', 'timeout')):
            self.env.update(ROLE=role, MODE=mode)
            console.write_text('')
            p = subprocess.run(['sh', str(script)], env=self.env, capture_output=True, text=True, timeout=10)
            output = console.read_text()
            if mode:
                self.assertNotEqual(p.returncode, 0, (role, mode))
                self.assertIn('CAPABILITY-PLANE-FAIL', output)
                self.assertNotIn('HOSTTEST-GUEST-READY', output)
                self.assertNotIn('HOSTTEST-L2-MARKER', output)
            else:
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn('HOSTTEST-GUEST-READY', output)

    def test_capability_manifest_required(self):
        text = (KIT/'lib/common.sh').read_text()
        helper = text[text.index('need_image()'):text.index('# Same digest as images/build-guest.sh')]
        images = self.root/'images'
        (images/'current').mkdir(parents=True)
        disk = images/'guest.img'
        disk.touch()
        out = self.root/'out'
        out.mkdir()
        runner = 'refuse() { echo "$*" >&2; exit 1; }; kit_overlay_sha256() { echo current; }; timeout() { return 0; };\n'+helper+'\nneed_image'
        self.env.update(HT_IMAGES=str(images), HT_GENERATION='16.snapX', HT_OUT=str(out), HT_KIT=str(KIT))
        for plane in ('capability_plane=YES\n', '', 'capability_plane=NO\n',
                      'capability_plane=YES\ncapability_plane=NO\n'):
            (images/'current/guest.manifest').write_text('generation=16.snapX\nimage='+str(disk)+'\nkit_overlay_sha256=current\n'+plane)
            p = subprocess.run(['sh', '-c', runner], env=self.env, capture_output=True, text=True)
            self.assertEqual(p.returncode == 0, plane == 'capability_plane=YES\n', p.stderr)

    def test_candidate_bhyve_selection(self):
        self.stub('bhyve', 'echo "CANDIDATE $*"')
        self.env.update(HT_KIT=str(KIT), HT_BHYVE_DIR=str(self.bin))
        setup = (KIT/'lib/common.sh').read_text().split('# --- results', 1)[0]
        selected = subprocess.run(['sh', '-c', setup+'\ncommand -v bhyve'], env=self.env,
                                  capture_output=True, text=True)
        self.assertEqual(selected.stdout.strip(), str(self.bin/'bhyve'))
        p = subprocess.run(['sh', '-c', setup+'\nbhyve direct; timeout 2 bhyve timed'],
                           env=self.env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.splitlines(), ['CANDIDATE direct', 'CANDIDATE timed'])
        for invalid in ('relative', '/missing/bhyve-candidate', str(self.bin)+':/usr/sbin', str(self.bin)+'\n'):
            self.env['HT_BHYVE_DIR'] = invalid
            p = subprocess.run(['sh', '-c', setup+'\necho UNEXPECTED-FALLBACK'], env=self.env,
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 2, (invalid, p.stderr))
            self.assertNotIn('UNEXPECTED-FALLBACK', p.stdout)
        self.env['HT_BHYVE_DIR'] = str(self.bin)
        (self.bin/'bhyve').chmod(0o644)
        p = subprocess.run(['sh', '-c', setup], env=self.env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 2, p.stderr)

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
    def test_dtrace_independent_verdicts(self):
        self.dtrace_stubs()
        stub = self.bin/'dtrace'
        stub.write_text(stub.read_text().replace('echo \'HIT 9\'\n',
            'case "$*" in *proc:::exec-success*) exit 0 ;; esac\necho \'HIT 9\'\n'))
        p = self.run_script('dtrace-cases.sh')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        output = self.root/'local.txt'
        output.write_text(p.stdout)
        def verdict(rc, probe):
            return subprocess.run(['sh', str(KIT/'lib/dtrace-check.sh'), str(output),
                                   str(rc), probe], capture_output=True).returncode
        self.assertEqual(verdict(1, 'begin-end'), 0)
        self.assertEqual(verdict(1, 'proc-exec'), 1)
        for rc in (0, 124, 139):
            self.assertEqual(verdict(rc, 'begin-end'), 2)
        for text in (p.stdout.replace('DTRACE-CASES-DONE', ''),
                     p.stdout+'DTRACE-CASE begin-end PASS\n',
                     p.stdout.replace('DTRACE-CASE proc-exec FAIL\n', '')):
            output.write_text(text)
            self.assertEqual(verdict(1, 'begin-end'), 2)

    def test_dtrace_target_executes_after_initial_exec(self):
        self.dtrace_stubs()
        stub = self.bin/'dtrace'
        stub.write_text(stub.read_text().replace("echo 'HIT 9'\n", r'''while [ "$#" -gt 0 ]; do
 if [ "$1" = -c ]; then
  shift
  grep -qx 'exec /bin/echo' "$1" || exit 3
  "$1" || exit 4
  break
 fi
 shift
done
echo 'HIT 9'
'''))
        p = self.run_script('dtrace-cases.sh')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)

    def test_nested_clean_snapshots(self):
        before, after, vms = (self.root/n for n in ('before', 'after', 'vms'))
        baseline = 'boot\none\ntwo\nthree\nfour\n'
        before.write_text(baseline)
        cases = [(baseline, '', 0), ('two\nthree\nfour\n', '', 0),
                 (baseline+'benign message\n', '', 0),
                 (baseline+'vmm: fault\n', '', 1),
                 ('two\nthree\nfour\npanic: failure\n', '', 1),
                 (baseline, 'leftover-l2\n', 1),
                 ('unrelated\nnew\nmessages\n', '', 2), ('', '', 2)]
        for text, inventory, expected in cases:
            after.write_text(text); vms.write_text(inventory)
            p = subprocess.run(['sh', str(KIT/'lib/nested-clean.sh'),
                                str(before), str(after), str(vms)], capture_output=True)
            self.assertEqual(p.returncode, expected, (text, inventory, p.stdout, p.stderr))

        after.write_text(baseline)
        vms.unlink()
        p = subprocess.run(['sh', str(KIT/'lib/nested-clean.sh'), str(before),
                            str(after), str(vms)], capture_output=True)
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)

    def test_session_deadline_preserves_child_failure(self):
        text = (KIT/'phases/hypertrace.sh').read_text()
        helper = text.split('trace_session_finished()\n', 1)[1].split('\n}\n', 1)[0] + '\n}\n'
        helper = 'trace_session_finished()\n' + helper
        for handler, expected in (('sys.exit(0)', 0), ('sys.exit(139)', 139), ('None', 137)):
            code = 'import signal,sys,time; signal.signal(signal.SIGINT, lambda *a: '+handler+'); print("HIT 9", flush=True); time.sleep(30)'
            p = subprocess.run(['timeout', '--preserve-status', '--foreground', '-s', 'INT', '-k', '1', '1', sys.executable, '-c', code],
                               capture_output=True, text=True, timeout=5)
            status = p.returncode if p.returncode >= 0 else 128 - p.returncode
            self.assertEqual(status, expected, p.stderr)
            self.assertIn('HIT 9', p.stdout)
            (self.root/'case.rc').write_text(str(status))
            verdict = subprocess.run(['sh', '-c', helper+'\nO="$1"; trace_session_finished case', 'fixture', str(self.root)], capture_output=True, text=True)
            self.assertEqual(verdict.stderr, '')
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
