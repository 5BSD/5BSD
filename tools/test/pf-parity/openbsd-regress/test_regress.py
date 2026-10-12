#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Runner accounting tests: no VM, firewall or upstream fixture changes."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('regress', Path(__file__).with_name('regress.py'))
regress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(regress)


class RunnerTests(unittest.TestCase):
    def result(self, console='REGRESS_EXIT 0\n', log='SUCCESS test/one\n',
               ssh_rc=0, log_rc=0, targets=None, prepare=None):
        commands = []

        def transport(host, command, timeout, out=None):
            commands.append(command)
            if out is None:
                return 0
            if str(out).endswith('.regress.log'):
                out.write_text(log)
                return log_rc
            out.write_text(console)
            return ssh_rc

        suite = {'host': 'dut', 'dir': 'regress/test'}
        if targets is not None:
            suite['targets'] = targets
        if prepare is not None:
            suite['prepare'] = prepare
        with tempfile.TemporaryDirectory() as tmp, patch.object(regress, 'ssh', transport):
            result = regress.run_suite('test', suite, Path(tmp), {'dut': 'dut'}, 'make')
        return result, commands

    def test_transport_and_make_failures(self):
        cases = [(0, 0, 'REGRESS_EXIT 0\n', 0),
                 (0, 0, 'REGRESS_EXIT 2\n', 2),
                 (255, 0, 'REGRESS_EXIT 0\n', 255),
                 (124, 0, '', 124), (0, 255, 'REGRESS_EXIT 0\n', 255),
                 (0, 0, '', 125)]
        for ssh_rc, log_rc, console, expected in cases:
            with self.subTest(expected=expected, ssh_rc=ssh_rc, log_rc=log_rc):
                r, _ = self.result(console=console, ssh_rc=ssh_rc, log_rc=log_rc)
                self.assertEqual(r['rc'], expected)
                self.assertEqual(r['ssh_rc'], ssh_rc)
                self.assertEqual(r['log_rc'], log_rc)

    def test_fail_early_no_still_reports_failure(self):
        for status in ['FAIL', 'XPASS']:
            r, _ = self.result(log=status + ' test/one\n')
            self.assertEqual(r['make_rc'], 0)
            self.assertEqual(r['rc'], 1)
        for status in ['SUCCESS', 'SKIP', 'XFAIL']:
            r, _ = self.result(log=status + ' test/one\n')
            self.assertEqual(r['rc'], 0)

    def test_empty_and_missing_results(self):
        r, _ = self.result(log='')
        self.assertEqual(r['rc'], 125)
        r, _ = self.result(log='', console='SKIPPED\nREGRESS_EXIT 0\n')
        self.assertTrue(r['suite_skipped'])
        self.assertEqual(r['rc'], 0)
        r, _ = self.result(targets=['one', 'two'])
        self.assertEqual(r['targets']['two'], 'NOT_RUN')
        self.assertEqual(r['rc'], 1)

    def test_program_rerun_target_uses_log_name(self):
        r, _ = self.result(targets=['run-regress-one'])
        self.assertEqual(r['targets'], {'one': 'SUCCESS'})
        self.assertEqual(r['rc'], 0)

    def test_generated_prerequisite_precedes_regress(self):
        _, commands = self.result(prepare=['pf_print_host.c'])
        self.assertIn('pf_print_host.c && make ', commands[1])
        self.assertIn(' regress; echo REGRESS_EXIT $?', commands[1])

    def test_cli_defaults_and_failure_exit(self):
        for os_name, expected in [('5bsd', 'make -m /usr/local/share/pf-parity/mk -m /usr/share/mk'),
                                  ('openbsd', 'make')]:
            with tempfile.TemporaryDirectory() as tmp:
                result = {'rc': 1, 'seconds': 0, 'suite_skipped': False,
                          'targets': {'one': 'FAIL'}}
                args = ['regress.py', os_name, tmp, '--suite', 'pf_table']
                with patch('sys.argv', args), patch.object(regress, 'run_suite', return_value=result) as run:
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(regress.main(), 1)
                    self.assertEqual(run.call_args.args[-1], expected)


if __name__ == '__main__':
    unittest.main()
