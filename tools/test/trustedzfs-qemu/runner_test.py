#!/usr/bin/env python3
"""Adversarial checks for the guest runner's result handling, without a VM."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

RUNNER = Path(__file__).with_name('guest-run.sh')
PROGRAMS = (
    'trustedzfs_capsicum_test', 'trustedzfs_limit_test',
    'libbsdfilesystem_protocol_test', 'zfshandle_rights_test',
    'zfshandle_derive_test', 'zfshandle_pin_test', 'zfshandle_phase2_test',
    'zfshandle_mount_test', 'zfshandle_pool_test', 'zfshandle_security_test',
    'zfshandle_verbs_test', 'zfshandle_negative_test',
    'zfshandle_hardening_test', 'bsdfilesystem_test',
)
STUB = r'''#!/bin/sh
# Test fixture: these outcomes never claim to execute ZFS operations.
scenario=${TRUSTEDZFS_RUNNER_SCENARIO}
if [ "$1" = -l ]; then
    [ "$scenario" != discovery_error ] || exit 1
    printf 'Content-Type: application/X-atf-tp; version="1"\n\n'
    [ "$scenario" != empty ] || exit 0
    printf 'ident: check\n'
    [ "$scenario" != cleanup_error ] || printf 'has.cleanup: true\n'
    [ "$scenario" != duplicate ] || printf '\nident: check\n'
    exit 0
fi
[ "$1" = -r ] || exit 2
case "$3" in
    check:cleanup) exit 1;;
    check) ;;
    *) exit 2;;
esac
case "$scenario" in
    skipped) printf 'skipped: unavailable\n' > "$2"; exit 0;;
    missing_result) echo passed; exit 0;;
    misleading_stdout) echo 'skipped: this is just captured output';;
esac
printf 'passed\n' > "$2"
[ "$scenario" != status_error ]
'''

class RunnerTests(unittest.TestCase):
    def run_scenario(self, scenario, expected_success):
        with tempfile.TemporaryDirectory(prefix='trustedzfs-runner-fixture-') as tmp:
            for name in PROGRAMS:
                path = Path(tmp, name)
                path.write_text(STUB)
                path.chmod(0o700)
            env = dict(os.environ, TRUSTEDZFS_RUNNER_SCENARIO=scenario)
            proc = subprocess.run(['sh', str(RUNNER), tmp], env=env,
                                  text=True, capture_output=True, timeout=30)
            try:
                self.assertEqual(proc.returncode == 0, expected_success,
                                 proc.stdout + proc.stderr)
                if expected_success:
                    self.assertIn(f'{len(PROGRAMS)} passed, 0 failed, 0 skipped',
                                  proc.stdout)
            finally:
                for line in proc.stdout.splitlines():
                    if line.startswith('TrustedZFS result directory: '):
                        path = Path(line.split(': ', 1)[1])
                        if path.parent == Path('/tmp') and path.name.startswith('trustedzfs-atf.'):
                            shutil.rmtree(path)

    def test_success(self):
        self.run_scenario('success', True)

    def test_stdout_is_not_result(self):
        self.run_scenario('misleading_stdout', True)

    def test_reject_unqualified_runs(self):
        for scenario in ('discovery_error', 'empty', 'duplicate', 'skipped',
                         'missing_result', 'status_error', 'cleanup_error'):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario, False)

if __name__ == '__main__':
    unittest.main()
