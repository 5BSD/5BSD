# SPDX-License-Identifier: BSD-2-Clause
"""Allocation input checks before any pool or dataset mutation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec); spec.loader.exec_module(obj)
    return obj

here = Path(__file__).resolve().parent
allocation = load('state_allocation', here / 'state_allocation.py')
state = load('state_storage', here.parents[1] / 'build/capimage/state_storage.py')


class Plans(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.layout = Path(tmp.name) / 'layout.json'
        self.layout.write_text(json.dumps(dict(format=1, boundaries=[])))
        self.plan = dict(format=2, parent='selected/providers', bindings=[],
            layout=dict(path=str(self.layout), sha256=hashlib.sha256(self.layout.read_bytes()).hexdigest()),
            providers=[dict(recipient='system.Filesystem/bsdfilesystem', dataset='selected/providers/filesystem')])

    def test_provider_without_global_attachment(self):
        parent, bindings, providers = allocation.validate_plan(self.plan, state)
        self.assertEqual(parent, 'selected/providers')
        self.assertEqual(bindings, [])
        self.assertEqual(providers, self.plan['providers'])

    def test_duplicate_dataset_rejected(self):
        row = dict(self.plan['providers'][0], recipient='system.Other/provider')
        self.plan['providers'].append(row)
        with self.assertRaisesRegex(ValueError, 'duplicate provider dataset'):
            allocation.validate_plan(self.plan, state)

    def test_duplicate_recipient_rejected(self):
        row = dict(self.plan['providers'][0], dataset='selected/providers/other')
        self.plan['providers'].append(row)
        with self.assertRaisesRegex(ValueError, 'duplicate provider recipient'):
            allocation.validate_plan(self.plan, state)

    def test_outside_parent_rejected(self):
        self.plan['providers'][0]['dataset'] = 'other/providers/filesystem'
        with self.assertRaisesRegex(ValueError, 'outside selected parent'):
            allocation.validate_plan(self.plan, state)

    def test_null_execution_rejected(self):
        self.plan['providers'][0]['execution'] = None
        with self.assertRaisesRegex(ValueError, 'cannot be null'):
            allocation.validate_plan(self.plan, state)

    def test_layout_digest_still_required(self):
        self.layout.write_text('{}')
        with self.assertRaises(ValueError):
            allocation.validate_plan(self.plan, state)

    def test_format_one_attachment_unchanged(self):
        self.layout.write_text(json.dumps(dict(format=1, boundaries=[dict(path='/var', content='ordinary')])))
        self.plan['layout']['sha256'] = hashlib.sha256(self.layout.read_bytes()).hexdigest()
        self.plan['format'] = 1; del self.plan['providers']
        self.plan['bindings'] = [dict(path='/var', dataset='selected/providers/var', execution=dict(exec='on', setuid='on'))]
        _, bindings, providers = allocation.validate_plan(self.plan, state)
        self.assertEqual(bindings, self.plan['bindings']); self.assertEqual(providers, [])


if __name__ == '__main__':
    unittest.main()
