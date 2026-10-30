# SPDX-License-Identifier: BSD-2-Clause
import copy
import hashlib
import unittest
import tempfile
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch
import configuration_compose as c


class NativeSelectionReceipt(unittest.TestCase):
    def test_cli_publishes_receipt_only_after_validation(self):
        report = c.encode(dict(format=2, scope='capsule-effective-manager',
            service_manager='', boot_configuration='/etc/capsule.conf',
            normal_boot_configuration='/etc/capsule.conf')).decode()
        cases = {
            'accepted': ("printf '%s\\n' '" + report + "'\n", True),
            'rejected': ("echo rejected >&2\nexit 1\n", False),
            'bad-report': ("echo '{}'\n", False),
            'changed-input': ("echo '{}' > \"$4\"\nprintf '%s\\n' '" + report + "'\n", False),
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            base, changes = directory / 'base', directory / 'changes'
            original = b'{"storage":[]}'
            base.write_bytes(original)
            changes.write_bytes(c.encode(dict(format=1,
                base_sha256=hashlib.sha256(original).hexdigest(),
                replace={}, add={}, remove={})))
            for name, (body, accepted) in cases.items():
                with self.subTest(case=name):
                    validator = directory / ('validator-' + name)
                    validator.write_text('#!/bin/sh\n' + body)
                    validator.chmod(0o700)
                    output = directory / ('output-' + name)
                    result = subprocess.run([sys.executable, '-B', c.__file__,
                        '--base', str(base), '--changes', str(changes),
                        '--output', str(output), '--capsule-validator', str(validator),
                        '--capsule-validator-sha256', hashlib.sha256(validator.read_bytes()).hexdigest()],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    self.assertEqual((output / 'receipt.json').exists(), accepted)
                    self.assertEqual(base.read_bytes(), original)
                    if accepted:
                        receipt = c.decode((output / 'receipt.json').read_bytes())
                        self.assertEqual(receipt['capsule_static_validation']['result'], 'PASS')
                        self.assertEqual(receipt['output_sha256'],
                            hashlib.sha256((output / 'configuration.json').read_bytes()).hexdigest())
                    # Failed output remains diagnostic; even a retry must not
                    # adopt its directory or publish a receipt over it.
                    before = {p.name: p.read_bytes() for p in output.iterdir()}
                    retry = subprocess.run(result.args, capture_output=True, timeout=10)
                    self.assertNotEqual(retry.returncode, 0)
                    self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, before)

    def test_report_is_required_and_bound_to_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            validator, config = directory / 'validator', directory / 'config'
            validator.write_bytes(b'selected validator')
            config.write_bytes(b'{}')
            digest = hashlib.sha256(validator.read_bytes()).hexdigest()
            def validate(output):
                result = subprocess.CompletedProcess([], 0, output, '')
                with patch.object(c.subprocess, 'run', return_value=result) as run:
                    receipt = c.validate_capsule(config, validator, digest)
                    self.assertEqual(run.call_args.args[0],
                        [str(validator), '-n', '-j', '-f', str(config)])
                    return receipt
            for manager in ('/alternate/manager', '', '/quoted/"manager'):
                report = dict(format=2, scope='capsule-effective-manager',
                              service_manager=manager, boot_configuration='/etc/capsule.conf',
                              normal_boot_configuration='/etc/capsule.conf')
                receipt = validate(c.encode(report).decode())
                self.assertEqual(receipt['effective_manager'], report)
                self.assertEqual(receipt['configuration_sha256'],
                                 hashlib.sha256(b'{}').hexdigest())
                self.assertEqual(receipt['validator_sha256'], digest)
                self.assertFalse(receipt['configured_manager_coverage_complete'])
            legacy = dict(report, format=1)
            legacy.pop('normal_boot_configuration')
            with self.assertRaises(ValueError):
                validate(c.encode(legacy).decode())
            for output in ('configuration valid', '{}',
                    '{"format":true,"scope":"capsule-effective-manager","service_manager":""}',
                    '{"format":1,"scope":"capsule-effective-manager","service_manager":null}',
                    '{"format":1,"format":1,"scope":"capsule-effective-manager","service_manager":""}'):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    validate(output)


class Composition(unittest.TestCase):
    def setUp(self):
        self.base = b'{"crypto_recipient":"example.Crypto/service","storage":[],"integrity":{"ptrace":true}}'
        self.changes = {'format': 1, 'base_sha256': hashlib.sha256(self.base).hexdigest(),
                        'replace': {}, 'add': {}, 'remove': {}}

    def run_changes(self):
        return c.compose(self.base, self.changes)

    def test_storage_override_preserves_unrelated_policy(self):
        before = copy.deepcopy(self.changes)
        self.changes['replace']['storage'] = {'expected': [], 'value': [{'pool': 'explicit'}]}
        output, receipt = self.run_changes()
        self.assertEqual(c.decode(output)['crypto_recipient'], 'example.Crypto/service')
        self.assertEqual(c.decode(output)['integrity'], {'ptrace': True})
        self.assertEqual(receipt['preserved_keys'], ['crypto_recipient', 'integrity'])
        self.assertFalse(receipt['runtime_authority_assigned'])
        self.assertEqual(before['replace'], {})

    def test_empty_grant_and_removal_are_intentional(self):
        self.changes['replace']['crypto_recipient'] = {'expected': 'example.Crypto/service', 'value': ''}
        self.assertEqual(c.decode(self.run_changes()[0])['crypto_recipient'], '')
        self.changes['replace'] = {}
        self.changes['remove']['crypto_recipient'] = 'example.Crypto/service'
        self.assertNotIn('crypto_recipient', c.decode(self.run_changes()[0]))

    def test_changed_base_requires_review(self):
        self.base += b' '
        with self.assertRaisesRegex(ValueError, 'base differs'):
            self.run_changes()

    def test_preconditions_do_not_coerce_types(self):
        self.changes['replace']['integrity'] = {'expected': {'ptrace': 1}, 'value': {}}
        with self.assertRaisesRegex(ValueError, 'precondition'):
            self.run_changes()

    def test_existing_addition_missing_removal_and_conflict(self):
        for fields in ({'add': {'storage': []}}, {'remove': {'missing': None}},
                       {'add': {'new': 1}, 'remove': {'new': 1}}):
            with self.subTest(fields=fields):
                changes = copy.deepcopy(self.changes); changes.update(fields)
                with self.assertRaises(ValueError): c.compose(self.base, changes)

    def test_duplicate_nested_keys_and_nonfinite_rejected(self):
        for data in (b'{"a":{"b":1,"b":2}}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(data=data), self.assertRaises(ValueError): c.decode(data)

    def test_unknown_fields_and_boolean_version_rejected(self):
        for update in ({'unexpected': True}, {'format': True}):
            changes = dict(self.changes, **update)
            with self.assertRaises(ValueError): c.compose(self.base, changes)

    def test_object_replacement_is_not_recursive_merge(self):
        self.changes['replace']['integrity'] = {'expected': {'ptrace': True}, 'value': {}}
        self.assertEqual(c.decode(self.run_changes()[0])['integrity'], {})

    def test_output_hash_and_inputs_unchanged(self):
        before = copy.deepcopy(self.changes)
        output, receipt = self.run_changes()
        self.assertEqual(receipt['output_sha256'], hashlib.sha256(output).hexdigest())
        self.assertEqual(self.changes, before)


if __name__ == '__main__': unittest.main()
