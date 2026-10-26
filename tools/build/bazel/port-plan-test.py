#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('port_plan', Path(__file__).with_name('port-plan.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.port = self.root / 'devel/example'
        self.port.mkdir(parents=True)
        self.config = {'format': 1, 'origin': 'devel/example',
                       'package': 'example-1.0', 'java_origin': 'java/examplejdk'}
        (self.port / 'Makefile').write_text('PKGNAME=example-1.0\nJAVA_PORT=java/examplejdk\n')

    def test_evaluates_without_building(self):
        with (self.port / 'Makefile').open('a') as stream:
            stream.write('all:\n\t@false\n')
        result = module.plan(self.root, self.config, Path('/usr/bin/make'))
        self.assertFalse(result['built'])
        self.assertEqual(result['variables']['PKGNAME'], 'example-1.0')

    def test_package_drift_rejected(self):
        self.config['package'] = 'example-2.0'
        with self.assertRaisesRegex(ValueError, 'pinned package'):
            module.plan(self.root, self.config, Path('/usr/bin/make'))

    def test_java_drift_rejected(self):
        self.config['java_origin'] = 'java/newjdk'
        with self.assertRaisesRegex(ValueError, 'Java port'):
            module.plan(self.root, self.config, Path('/usr/bin/make'))

    def test_config_rejects_unknown_and_traversal(self):
        for changed in [dict(extra=True), dict(origin='../example'), dict(format=True)]:
            config = dict(self.config, **changed)
            path = self.root / 'config.json'
            path.write_text(json.dumps(config))
            with self.assertRaises(ValueError):
                module.load_config(path)

    def test_duplicate_rejected(self):
        path = self.root / 'config.json'
        path.write_text('{"format":1,"format":1}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            module.load_config(path)


if __name__ == '__main__':
    unittest.main()
