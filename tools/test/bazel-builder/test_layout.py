#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import layout

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('generation', HERE.parents[1] / 'build/capimage/generation_check.py')
generation = importlib.util.module_from_spec(spec); spec.loader.exec_module(generation)


class Layout(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((HERE / 'pkg-parent-policy.json').read_text())
        self.initial = {'format': 1, 'entries': {'/': dict(self.policy['defaults'], source='explicit root', replaces=[])}}
        self.inventory = {'format': 1, 'scope': 'package-payload-inventory', 'packages': [
            {'name': 'pkg', 'version': '2.8.4_8', 'archive_sha256': 'a'*64,
             'directories': {}, 'manifest': {}, 'entries': {
                 '/software/deep/app': {'type': 'file', 'size': 0, 'sha256': 'b'*64}}}]}

    def derive(self):
        return layout.derive(self.inventory, self.initial, self.policy, generation)

    def test_ancestor_closure_preserves_input(self):
        before = copy.deepcopy(self.initial)
        result, added = self.derive()
        self.assertEqual(added, ['/software', '/software/deep'])
        self.assertEqual(self.initial, before)
        self.assertEqual(result['entries']['/'], before['entries']['/'])
        self.assertEqual(result['entries']['/software']['replaces'], [])

    def test_preserves_custom_initial_directory(self):
        self.initial['entries']['/software'] = dict(self.initial['entries']['/'], mode=0o700)
        result, added = self.derive()
        self.assertEqual(added, ['/software/deep'])
        self.assertEqual(result['entries']['/software']['mode'], 0o700)

    def test_non_directory_ancestor(self):
        self.inventory['packages'][0]['entries']['/software'] = {'type': 'symlink', 'target': '/elsewhere'}
        with self.assertRaises(ValueError): self.derive()

    def test_no_package_replacement(self):
        self.inventory['packages'][0]['entries']['/software'] = dict(self.policy['defaults'])
        self.initial['entries']['/software'] = dict(self.initial['entries']['/'], replaces=['a'*64])
        with self.assertRaises(ValueError): self.derive()

    def test_policy_and_engine_version(self):
        self.inventory['packages'][0]['version'] = '2.9.0'
        with self.assertRaises(ValueError): self.derive()
        self.inventory['packages'][0]['version'] = '2.8.4'
        self.policy['defaults']['mode'] = 0o777
        with self.assertRaises(ValueError): self.derive()

    def test_root_and_duplicate_json(self):
        self.initial['entries'] = {}
        with self.assertRaises(ValueError): self.derive()
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'input.json'; p.write_text('{"format":1,"format":2}')
            with self.assertRaises(ValueError): layout.read_json(p)


if __name__ == '__main__':
    unittest.main()
