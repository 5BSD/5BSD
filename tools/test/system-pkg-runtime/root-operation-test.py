# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual subprocess completion, failure, deadline and stale-log handling."""
import argparse
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
import root_operation

parser = argparse.ArgumentParser()
parser.add_argument('--shell', type=Path, required=True)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining
shell = (Path(os.environ.get('TEST_SRCDIR', '/')) / args.shell).resolve(strict=True)


class RootOperation(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / 'output'
        self.records = []

    def invoke(self, script, **options):
        values = dict(label='fixture', command=script, output=self.output,
            env={'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'},
            deadline=time.monotonic() + 10, tick=lambda: None,
            publish=self.records.append)
        values.update(options)
        return root_operation.invoke([str(shell), '-c', script], **values)

    def check_record(self):
        self.assertEqual(len(self.records), 1)
        record = self.records[0]
        self.assertTrue(record['output_created'])
        self.assertEqual(record['output_sha256'], hashlib.sha256(self.output.read_bytes()).hexdigest())
        with self.assertRaises(ChildProcessError):
            os.waitpid(record['pid'], os.WNOHANG)
        return record

    def test_success(self):
        record = self.invoke('printf success')
        self.assertEqual(record['status'], 0)
        self.assertNotIn('error', self.check_record())
        self.assertEqual(self.output.read_bytes(), b'success')

    def test_nonzero_exit_is_journaled(self):
        self.assertEqual(self.invoke('printf failure; exit 7')['status'], 7)
        self.assertEqual(self.check_record()['status'], 7)

    def test_timeout_keeps_partial_output_and_reaps_child(self):
        with self.assertRaisesRegex(TimeoutError, 'phase deadline'):
            self.invoke('printf partial; while :; do :; done', deadline=time.monotonic() + 0.3)
        self.assertEqual(self.output.read_bytes(), b'partial')
        record = self.check_record()
        self.assertNotEqual(record['status'], 0)
        self.assertIn('TimeoutError', record['error'])

    def test_monitor_failure_is_journaled(self):
        def fail():
            raise RuntimeError('fixture monitor stop')
        with self.assertRaisesRegex(RuntimeError, 'fixture monitor stop'):
            self.invoke('while :; do :; done', tick=fail)
        self.assertIn('fixture monitor stop', self.check_record()['error'])

    def test_output_limit_is_journaled(self):
        with self.assertRaisesRegex(ValueError, 'evidence budget'):
            self.invoke('printf toolong', max_bytes=2)
        self.assertIn('evidence budget', self.check_record()['error'])

    def test_stale_output_is_not_adopted(self):
        self.output.write_bytes(b'stale')
        with self.assertRaises(FileExistsError):
            self.invoke('printf replacement')
        self.assertEqual(self.output.read_bytes(), b'stale')
        self.assertEqual(len(self.records), 1)
        self.assertFalse(self.records[0]['output_created'])
        self.assertIsNone(self.records[0]['output_sha256'])
        self.assertIsNone(self.records[0]['pid'])

    def test_launch_failure_is_journaled(self):
        with self.assertRaises(FileNotFoundError):
            root_operation.invoke([str(Path(self.directory.name) / 'absent')],
                label='launch', command='absent', output=self.output,
                env={}, deadline=time.monotonic() + 10, tick=lambda: None,
                publish=self.records.append)
        self.assertEqual(len(self.records), 1)
        self.assertIsNone(self.records[0]['status'])
        self.assertIn('FileNotFoundError', self.records[0]['error'])
        self.assertEqual(self.records[0]['output_sha256'], hashlib.sha256(b'').hexdigest())


if __name__ == '__main__':
    unittest.main()
