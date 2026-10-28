#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the runner's phase lifecycle with a controlled ATF protocol fixture."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

SOURCE = Path(__file__).with_name('atf_runner.c')

class CleanupLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory(prefix='atf-runner-cleanup-')
        cls.root = Path(cls.storage.name)
        cls.runner = cls.root / 'runner'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', str(SOURCE), '-o', str(cls.runner)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.storage.cleanup()

    def exercise(self, body_exit=0, cleanup_exit=0, result='passed', cleanup='1', signal=False, check_locale=False, xml=False, body_timeout="0", cleanup_timeout="0", hang_body=False, hang_cleanup=False, loader=False, missing_loader=False):
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            root = Path(tmp)
            suite = root / 'workspace/atf-suite'
            suite.mkdir(parents=True)
            body = suite / 'fixture'
            body.write_text('''#!/bin/sh
while [ "$#" -gt 1 ]; do
    case "$1" in -r) result_file=$2;; esac
    shift 2
done
case "$1" in
example:cleanup)
    test -f body-created || exit 33
    printf 'cleanup\\n' > cleanup-ran
    if [ "$HANG_CLEANUP" = yes ]; then /bin/sleep 60; fi
    exit "$CLEANUP_EXIT";;
example)
    if [ "$CHECK_LOCALE" = yes ]; then
        for name in LANG LC_ALL LC_COLLATE LC_CTYPE LC_MESSAGES LC_MONETARY LC_NUMERIC LC_TIME; do
            eval 'present=${'"$name"'+set}'
            test -z "$present" || exit 35
        done
        test "$TZ" = UTC || exit 36
        test "$PATH_LOCALE" = "$TEST_SRCDIR/$TEST_WORKSPACE/atf-runtime/locale" || exit 38
        LC_CTYPE=C.UTF-8
        export LC_CTYPE
        test -z "${LC_ALL+set}" || exit 37
    fi
    printf 'body\\n' > body-created
    printf '%s\\n' "$RESULT" > "$result_file"
    if [ "$HANG_BODY" = yes ]; then /bin/sleep 60; fi
    if [ "$SIGNAL" = yes ]; then kill -TERM $$; fi
    exit "$BODY_EXIT";;
*) exit 34;;
esac
''')
            body.chmod(0o755)
            if loader and not missing_loader:
                launcher = root / 'workspace/atf-loader/loader'
                launcher.parent.mkdir(parents=True)
                launcher.write_text("#!/bin/sh\ntest \"$1\" = -- || exit 81\nshift\nprintf '%s\\n' \"$*\" >> \"$FIXTURE_LOADER_LOG\"\nexec \"$@\"\n")
                launcher.chmod(0o755)
            env = dict(os.environ, TEST_SRCDIR=str(root), TEST_WORKSPACE='workspace',
                       TEST_TMPDIR=str(root), BSD_ATF_CASE='example', BSD_ATF_HARNESS='fixture',
                       BSD_ATF_INTERFACE='program', BSD_ATF_LOADER='1' if loader else '0',
                       FIXTURE_LOADER_LOG=str(root / 'loader-calls'), BSD_ATF_CONFIG_COUNT='0', BSD_ATF_CLEANUP=cleanup,
                       BSD_ATF_BODY_TIMEOUT=str(body_timeout), BSD_ATF_CLEANUP_TIMEOUT=str(cleanup_timeout),
                       HANG_BODY='yes' if hang_body else 'no', HANG_CLEANUP='yes' if hang_cleanup else 'no',
                       BODY_EXIT=str(body_exit), CLEANUP_EXIT=str(cleanup_exit), RESULT=result,
                       SIGNAL='yes' if signal else 'no', CHECK_LOCALE='yes' if check_locale else 'no')
            if xml:
                env['XML_OUTPUT_FILE'] = str(root / 'test.xml')
            if check_locale:
                env.update({name: 'contaminated' for name in ['LANG', 'LC_ALL', 'LC_COLLATE', 'LC_CTYPE', 'LC_MESSAGES', 'LC_MONETARY', 'LC_NUMERIC', 'LC_TIME', 'TZ', 'PATH_LOCALE']})
            run = subprocess.run([str(self.runner)], env=env, capture_output=True, text=True, timeout=10)
            markers = list(root.glob('atf.*/cleanup-ran'))
            if loader and not missing_loader:
                calls = (root / 'loader-calls').read_text().splitlines()
                self.assertEqual(len(calls), 2 if cleanup == '1' else 1)
                self.assertTrue(calls[0].startswith(str(body) + ' -s '))
                self.assertTrue(calls[0].endswith(' example'))
                if cleanup == '1':
                    self.assertTrue(calls[1].endswith(' example:cleanup'))
            if missing_loader:
                self.assertFalse(list(root.glob('atf.*/body-created')))
            if xml:
                report = root / 'test.xml'
                return run, ET.parse(report).getroot() if report.exists() else None
            return run, len(markers)

    def test_explicit_loader_runs_body_and_cleanup(self):
        run, markers = self.exercise(loader=True)
        self.assertEqual((run.returncode, markers), (0, 1), run.stderr)
        self.assertIn('ATF explicit loader:', run.stderr)

    def test_missing_explicit_loader_never_falls_back(self):
        run, markers = self.exercise(loader=True, missing_loader=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(markers, 0)

    def test_timed_out_body_still_runs_cleanup(self):
        # The sleep child inherits captured output. A leaked descendant would
        # keep communicate() blocked until the independent ten-second guard.
        run, markers = self.exercise(hang_body=True, body_timeout="1")
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(markers, 1)
        self.assertIn('body timed out', run.stderr)
        self.assertNotIn(': passed', run.stdout)

    def test_timed_out_cleanup_fails_passing_body(self):
        run, markers = self.exercise(hang_cleanup=True, cleanup_timeout="1")
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(markers, 1)
        self.assertIn('cleanup timed out', run.stderr)

    def test_phase_deadlines_accept_normal_completion(self):
        run, markers = self.exercise(body_timeout="5", cleanup_timeout="5")
        self.assertEqual((run.returncode, markers), (0, 1), run.stderr)

    def test_invalid_deadlines_rejected_before_execution(self):
        for key in ('body_timeout', 'cleanup_timeout'):
            for value in ('', '-1', '+1', '1second', ' 1', '2147483648'):
                with self.subTest(key=key, value=value):
                    run, markers = self.exercise(**{key: value})
                    self.assertNotEqual(run.returncode, 0)
                    self.assertEqual(markers, 0)
                    self.assertIn('invalid phase timeout', run.stderr)

    def test_nonpassing_without_xml_fails_closed(self):
        run, markers = self.exercise(result='expected_failure: known issue')
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(markers, 1)
        self.assertIn('requires XML reporting', run.stderr)

    def test_xml_pass_is_not_skipped(self):
        run, report = self.exercise(xml=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(report.find('testsuite').get('skipped'), '0')
        self.assertIsNone(report.find('.//skipped'))

    def test_nonpassing_outcomes_are_explicit(self):
        for outcome in ('expected_failure', 'skipped'):
            reason = 'known <issue> & "details" ' + 'x' * 10000
            with self.subTest(outcome=outcome):
                run, report = self.exercise(result=outcome + ': ' + reason, xml=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(report.find('testsuite').get('skipped'), '1')
                self.assertEqual(report.find('.//skipped').get('message'), outcome + ': ' + reason)
                self.assertIn(outcome, run.stdout)
                self.assertNotIn(': passed', run.stdout)

    def test_invalid_results_fail(self):
        for result in ('', 'passed extra', 'passed\npassed', 'expected_failure: ',
                       'skipped: ', 'expected_failure: why\npassed',
                       'expected_failure: bad\x01byte', 'failed: unexpected pass',
                       'expected_exit(0): not supported', 'expected_signal(15): not supported',
                       'expected_timeout: not supported'):
            with self.subTest(result=result[:80]):
                run, report = self.exercise(result=result, xml=True)
                self.assertNotEqual(run.returncode, 0)
                self.assertIsNone(report)

    def test_expected_failure_does_not_mask_crash_or_cleanup_failure(self):
        for options in (dict(signal=True), dict(body_exit=1), dict(cleanup_exit=1)):
            with self.subTest(options=options):
                run, report = self.exercise(result='expected_failure: known issue', xml=True, **options)
                self.assertNotEqual(run.returncode, 0)
                self.assertIsNone(report)

    def test_locale_isolation_allows_category_override(self):
        run, markers = self.exercise(check_locale=True)
        self.assertEqual((run.returncode, markers), (0, 1), run.stderr)

    def test_success_runs_cleanup(self):
        run, markers = self.exercise()
        self.assertEqual((run.returncode, markers), (0, 1), run.stderr)

    def test_failed_body_still_runs_cleanup(self):
        run, markers = self.exercise(body_exit=1, result='failed: deliberate')
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(markers, 1)

        self.assertIn('failed: deliberate', run.stderr)

    def test_signaled_body_still_runs_cleanup(self):
        run, markers = self.exercise(signal=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(markers, 1)

    def test_cleanup_failure_fails_test(self):
        run, markers = self.exercise(cleanup_exit=1)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(markers, 1)
        self.assertIn('cleanup failed', run.stderr)

    def test_successful_cleanup_does_not_mask_failed_result(self):
        run, markers = self.exercise(result='failed: deliberate')
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(markers, 1)

    def test_no_cleanup_for_ordinary_case(self):
        run, markers = self.exercise(cleanup='0')
        self.assertEqual((run.returncode, markers), (0, 0), run.stderr)

    def test_invalid_setting_fails_before_body(self):
        run, markers = self.exercise(cleanup='invalid')
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(markers, 0)
        self.assertIn('invalid ATF cleanup', run.stderr)

if __name__ == '__main__':
    unittest.main()
