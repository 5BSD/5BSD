#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Checks that incomplete or stale VM evidence cannot pass the FUSE gate."""
import importlib.util
from pathlib import Path
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load('qemu-fuse-protocol')
manifest_tool = load('fuse-protocol-manifest')


class GateTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            'version': 1, 'artifacts': {'kernel': 'a' * 64, 'fusefs': 'b' * 64},
            'programs': {'readdir': {'sha256': 'c' * 64,
                         'cases': ['Plus.cache', 'Lengths/Bounds.bad/0'], 'disabled': []}}}
        self.console = '\n'.join([
            'FUSE_PROTOCOL_ARTIFACT kernel ' + 'a' * 64,
            'FUSE_PROTOCOL_ARTIFACT fusefs ' + 'b' * 64,
            'FUSE_PROTOCOL_BEGIN readdir',
            'FUSE_PROTOCOL_ARTIFACT readdir ' + 'c' * 64,
            '[       OK ] Plus.cache (1 ms)',
            '[       OK ] Lengths/Bounds.bad/0 (0 ms)',
            'FUSE_PROTOCOL_END readdir 0',
            'all pools are healthy', 'FUSE_PROTOCOL_DONE',
            'FUSE_PROTOCOL_EXIT 0', 'Powering system off using ACPI', ''])

    def test_complete_matching_evidence(self):
        result = gate.evaluate(self.console.replace('\n', '\r\n'), self.manifest, 0)
        self.assertTrue(result['passed'], result['errors'])
        self.assertEqual(2, result['passed_case_count'])

    def test_incomplete_or_wrong_evidence_fails(self):
        variants = {
            'missing new case': self.console.replace('[       OK ] Plus.cache (1 ms)\n', ''),
            'same count wrong case': self.console.replace('Plus.cache', 'Old.unrelated'),
            'duplicate case': self.console.replace('Lengths/Bounds.bad/0', 'Plus.cache'),
            'old module': self.console.replace('b' * 64, 'd' * 64),
            'old test binary': self.console.replace('c' * 64, 'd' * 64),
            'missing kernel hash': self.console.replace(
                'FUSE_PROTOCOL_ARTIFACT kernel ' + 'a' * 64 + '\n', ''),
            'failed program': self.console.replace('END readdir 0', 'END readdir 1'),
            'skip': self.console + '[  SKIPPED ] Some.test\n',
            'witness': self.console + 'lock order reversal:\n',
            'no clean exit': self.console.replace('FUSE_PROTOCOL_EXIT 0', ''),
            'duplicate program': self.console + 'FUSE_PROTOCOL_BEGIN readdir\n',
            'case outside program': self.console + '[       OK ] Plus.cache (0 ms)\n',
        }
        for name, console in variants.items():
            with self.subTest(name=name):
                self.assertFalse(gate.evaluate(console, self.manifest, 0)['passed'])
        self.assertFalse(gate.evaluate(self.console, self.manifest, -9)['passed'])

    def test_linux_artifacts_are_required_together(self):
        extra = {'linux64': 'd' * 64, 'linux_common': 'e' * 64,
                 'linux_rename_probe': 'f' * 64}
        self.manifest['artifacts'].update(extra)
        console = self.console + ''.join(
            f'FUSE_PROTOCOL_ARTIFACT {name} {digest}\n'
            for name, digest in extra.items())
        self.assertTrue(gate.evaluate(console, self.manifest, 0)['passed'])
        for name, digest in extra.items():
            with self.subTest(name=name):
                self.assertFalse(gate.evaluate(console.replace(
                    f'FUSE_PROTOCOL_ARTIFACT {name} {digest}\n', ''),
                    self.manifest, 0)['passed'])
        del self.manifest['artifacts']['linux64']
        with self.assertRaises(ValueError):
            gate.validate_manifest(self.manifest)

    def test_manifest_rejects_missing_or_duplicate_requirements(self):
        self.manifest['programs']['readdir']['cases'].append('Plus.cache')
        with self.assertRaises(ValueError):
            gate.validate_manifest(self.manifest)
        self.manifest['programs'] = {}
        with self.assertRaises(ValueError):
            gate.validate_manifest(self.manifest)

    def test_parameterized_and_disabled_listing(self):
        active, disabled = manifest_tool.cases_from_listing(
            'Readdir.\n  normal\n  DISABLED_known\n'
            'Lengths/Bounds.\n  bad/0  # GetParam() = (0, 152)\n')
        self.assertEqual(['Readdir.normal', 'Lengths/Bounds.bad/0'], active)
        self.assertEqual(['Readdir.DISABLED_known'], disabled)

    def test_bad_listing_fails(self):
        for listing in ('', 'Error: cannot execute', 'Suite.\n  duplicate\n  duplicate\n'):
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                manifest_tool.cases_from_listing(listing)


if __name__ == '__main__':
    unittest.main()
