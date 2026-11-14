# SPDX-License-Identifier: BSD-2-Clause
import json
from pathlib import Path
import tempfile
import unittest
import certificate_runtime as runtime


class Certificates(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / 'policy.json'
        self.policy = dict(format=1, openssl='/usr/bin/openssl', certctl='/usr/sbin/certctl',
                           fetch='/usr/bin/fetch', bundle='/etc/ssl/cert.pem',
                           local_directory='/usr/local/share/certs', port=24443, deadline_seconds=180)
        self.report = dict(payload_sha256={self.policy[key]: 'a' * 64
                           for key in ('openssl', 'certctl', 'fetch', 'bundle')})

    def load(self):
        self.path.write_text(json.dumps(self.policy))
        return runtime.load(self.path, self.report)

    def test_policy_binds_installed_inputs_and_maintained_probe(self):
        loaded = self.load()
        self.assertEqual(loaded['policy'], self.policy)
        self.assertEqual(set(loaded['bindings']), {str(self.path), str(loaded['script'])})

    def test_absent_image_inputs_and_unsafe_policy_are_refused(self):
        for key in ('openssl', 'certctl', 'fetch', 'bundle'):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'absent'):
                saved = self.report['payload_sha256'].pop(self.policy[key])
                try:
                    self.load()
                finally:
                    self.report['payload_sha256'][self.policy[key]] = saved
        for key, value in [('port', True), ('port', 0), ('port', 65536),
                           ('deadline_seconds', 0), ('deadline_seconds', 601),
                           ('local_directory', '/'), ('local_directory', '/etc/../var'),
                           ('local_directory', 'relative')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                saved = self.policy[key]
                try:
                    self.policy[key] = value
                    self.load()
                finally:
                    self.policy[key] = saved

    def test_evidence_requires_complete_ordered_lifecycle_and_cleans_work(self):
        loaded = self.load()
        for markers in [runtime.MARKERS[:-1], list(reversed(runtime.MARKERS)), runtime.MARKERS * 2]:
            calls = []
            def invoke(label, command, source=None):
                calls.append(label)
                return ('\n'.join(markers) + '\n').encode()
            with self.subTest(markers=markers), self.assertRaisesRegex(ValueError, 'evidence'):
                runtime.exercise(loaded, invoke, self.root, 'ordinary', 2001)
            self.assertEqual(calls[-1], 'certificate-work-cleanup')
            self.assertFalse((self.root / 'certificate-proof.json').exists())

    def test_failed_guest_operation_never_reports_success(self):
        calls = []
        def invoke(label, command, source=None):
            calls.append(label)
            if label == 'certificate-default-trust':
                raise RuntimeError('actual client refused')
            return b''
        with self.assertRaisesRegex(RuntimeError, 'client refused'):
            runtime.exercise(self.load(), invoke, self.root, 'ordinary', 2001)
        self.assertEqual(calls[-1], 'certificate-work-cleanup')
        self.assertFalse((self.root / 'certificate-proof.json').exists())


if __name__ == '__main__':
    unittest.main()
