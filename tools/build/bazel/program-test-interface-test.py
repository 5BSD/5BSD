# SPDX-License-Identifier: BSD-2-Clause
"""Check native and plain result reporting without changing child status."""
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest


class ProgramInterface(unittest.TestCase):
    def exercise(self, interface, status=0, terminate=False):
        runner = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE'] / 'tools/build/bazel/program_test_runner'
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            root = Path(temporary)
            work = root / 'workspace'
            (work / 'program-bin').mkdir(parents=True)
            outputs = root / 'outputs'
            outputs.mkdir()
            fixture = work / 'program-bin/fixture'
            fixture.write_text('#!/bin/sh\nprintf %s \'<testsuite tests="0"/>\' > "$XML_OUTPUT_FILE"\n' +
                               ('kill -TERM $$\n' if terminate else 'exit ' + str(status) + '\n'))
            fixture.chmod(0o755)
            environment = dict(os.environ, TEST_SRCDIR=str(root), TEST_WORKSPACE='workspace',
                               TEST_TMPDIR=str(root), TEST_UNDECLARED_OUTPUTS_DIR=str(outputs),
                               XML_OUTPUT_FILE=str(root / 'outer.xml'), BSD_TEST_PROGRAM='fixture',
                               BSD_TEST_RUNTIME='0')
            if interface is None:
                environment.pop('BSD_TEST_INTERFACE', None)
            else:
                environment['BSD_TEST_INTERFACE'] = interface
            result = subprocess.run([str(runner)], env=environment, capture_output=True, text=True, timeout=10)
            return result, (root / 'outer.xml').exists(), (outputs / 'program.xml').exists()

    def test_native_preserves_child_xml(self):
        result, outer, inner = self.exercise('native')
        self.assertEqual((result.returncode, outer, inner), (0, True, False), result.stderr)

    def test_legacy_runner_environment_preserves_child_xml(self):
        result, outer, inner = self.exercise(None)
        self.assertEqual((result.returncode, outer, inner), (0, True, False), result.stderr)

    def test_plain_retains_empty_child_report_separately(self):
        result, outer, inner = self.exercise('plain')
        self.assertEqual((result.returncode, outer, inner), (0, False, True), result.stderr)

    def test_plain_does_not_mask_failure(self):
        result, outer, inner = self.exercise('plain', status=23)
        self.assertEqual((result.returncode, outer, inner), (23, False, True), result.stderr)

    def test_plain_preserves_signal(self):
        result, outer, inner = self.exercise('plain', terminate=True)
        self.assertEqual((result.returncode, outer, inner), (-signal.SIGTERM, False, True), result.stderr)

    def test_invalid_interface_fails_before_child(self):
        result, outer, inner = self.exercise('invalid')
        self.assertEqual((result.returncode, outer, inner), (126, False, False), result.stderr)


if __name__ == '__main__':
    unittest.main()
