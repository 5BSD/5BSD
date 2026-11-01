# SPDX-License-Identifier: BSD-2-Clause
"""Reject stale, corrupted, escaping and ambiguous qualification captures."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import qualification_artifacts as artifacts


class CapturedArtifactsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.capture = self.root / 'artifacts'
        (self.capture / 'files').mkdir(parents=True)
        self.payload = self.capture / 'files/payload'
        self.payload.write_bytes(b'captured source output')
        self.output = {'file': 'files/payload', 'name': 'bin/component/libcomponent.a',
                       'size': self.payload.stat().st_size,
                       'sha256': artifacts.digest(self.payload)}
        self.manifest = {'format': 1, 'targets': [
            {'target': {'label': '//component:archive'}, 'outputs': [self.output]}]}
        self.write_manifest()

    def write_manifest(self):
        path = self.capture / 'manifest.json'
        path.write_text(json.dumps(self.manifest))
        self.receipt = {'status': 'passed', 'artifacts': {
            'manifest': 'artifacts/manifest.json', 'sha256': artifacts.digest(path)}}
        self.write_receipt()

    def write_receipt(self):
        (self.root / 'receipt.json').write_text(json.dumps(self.receipt))

    def resolve(self, target='//component:archive', suffix='.a'):
        return artifacts.resolve(self.root, target, suffix)

    def test_captured_payload_has_receipt_manifest_and_output_binding(self):
        path, binding = self.resolve()
        self.assertEqual(path, self.payload)
        self.assertEqual(binding['sha256'], artifacts.digest(path))
        self.assertEqual(binding['receipt_sha256'], artifacts.digest(self.root/'receipt.json'))
        self.assertEqual(binding['manifest_sha256'], artifacts.digest(self.capture/'manifest.json'))
        self.assertEqual(binding['source'], 'qualification-capture')

    def test_mutable_output_tree_is_not_selected(self):
        alias = self.root / 'bazel-bin'
        alias.mkdir()
        (alias / 'libcomponent.a').write_bytes(b'new configuration')
        self.assertEqual(self.resolve()[0].read_bytes(), b'captured source output')

    def test_payload_corruption_rejected(self):
        self.payload.write_bytes(b'x' * self.payload.stat().st_size)
        with self.assertRaisesRegex(ValueError, 'content mismatch'):
            self.resolve()

    def test_manifest_corruption_rejected(self):
        (self.capture/'manifest.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'manifest mismatch'):
            self.resolve()

    def test_unfinished_qualification_rejected(self):
        self.receipt['status'] = 'running'
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, 'completed'):
            self.resolve()

    def test_noncanonical_paths_rejected(self):
        for path in ['../outside', '/outside', 'files/../payload', 'files//payload',
                     './files/payload', 'files/'+chr(10)+'payload']:
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'canonical relative'):
                artifacts.relative(path)
        self.receipt['artifacts']['manifest'] = '../outside'
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, 'canonical relative'):
            self.resolve()

    def test_payload_escape_or_symlink_rejected(self):
        outside = self.root / 'outside'
        outside.write_bytes(self.payload.read_bytes())
        self.payload.unlink()
        self.payload.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'regular contained'):
            self.resolve()

    def test_manifest_escape_rejected_even_with_matching_hash(self):
        outside = self.root / 'outside.json'
        outside.write_bytes((self.capture/'manifest.json').read_bytes())
        path = self.capture / 'manifest.json'
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'manifest mismatch or escape'):
            self.resolve()

    def test_duplicate_target_configuration_rejected(self):
        self.manifest['targets'].append(copy.deepcopy(self.manifest['targets'][0]))
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'one target configuration'):
            self.resolve()

    def test_duplicate_output_selection_rejected(self):
        self.manifest['targets'][0]['outputs'].append(copy.deepcopy(self.output))
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'one selected captured output'):
            self.resolve()

    def test_explicit_unique_selection_required(self):
        for target, suffix in [('', '.a'), ('//component:archive', ''),
                               ('//missing:archive', '.a'), ('//component:archive', '.so')]:
            with self.subTest(target=target, suffix=suffix), self.assertRaises(ValueError):
                self.resolve(target, suffix)

    def test_payload_size_is_part_of_binding(self):
        self.output['size'] += 1
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'content mismatch'):
            self.resolve()


if __name__ == '__main__':
    unittest.main()
