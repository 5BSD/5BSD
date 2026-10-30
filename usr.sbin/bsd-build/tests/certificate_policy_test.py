# SPDX-License-Identifier: BSD-2-Clause
"""Policy and bounded-plan parsing tests; real execution is qualified in the VM."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

helper = os.environ.get('BSD_BUILD_CONSTRUCTION_HELPER') or str(
    Path(__file__).resolve().parents[3] / 'tools/build/capimage/construction.py')
spec = importlib.util.spec_from_file_location('construction', helper)
construction = importlib.util.module_from_spec(spec); spec.loader.exec_module(construction)
certificates = construction.certificates


class Policy(unittest.TestCase):
    def setUp(self):
        self.inventory = {'packages': [{'name': 'fixture', 'archive_sha256': 'a' * 64,
            'entries': {'/tool': {'type': 'file', 'mode': 0o555, 'sha256': 'b' * 64},
                        '/roots/a.pem': {'type': 'file', 'mode': 0o444, 'sha256': 'c' * 64}}}]}
        self.observed = {'/tool': {'type': 'file', 'sha256': 'b' * 64},
                         '/roots/a.pem': {'type': 'file', 'sha256': 'c' * 64},
                         '/site.pem': {'type': 'file', 'sha256': 'd' * 64},
                         '/store': {'type': 'directory'}, '/store/trusted': {'type': 'directory'},
                         '/store/denied': {'type': 'directory'}}
        self.policy = {'format': 1, 'name': 'certificates', 'program': '/tool',
            'selections': [{'package': 'fixture', 'prefix': '/roots', 'role': 'trusted'}],
            'files': [], 'overrides': [], 'outputs': {'trusted_directory': '/store/trusted',
            'untrusted_directory': '/store/denied', 'bundle': '/store/bundle.pem',
            'uid': 0, 'gid': 0, 'mode': 0o444, 'flags_set': 0}}
        self.plan = (b'./store/trusted/1234abcd.0 type=file uname=root gname=wheel mode=0444 size=123\n'
                     b'./store/bundle.pem type=file uname=root gname=wheel mode=0444 size=123\n')

    def prepare(self):
        return certificates.prepare(self.inventory, self.observed, self.policy)

    def test_package_selection_and_explicit_site_input(self):
        self.policy['files'] = [{'path': '/site.pem', 'role': 'untrusted'}]
        prepared = self.prepare()
        self.assertEqual([item['path'] for item in prepared['selection']], ['/roots/a.pem', '/site.pem'])
        self.assertEqual(prepared['executable_payload']['archive_sha256'], 'a' * 64)
        self.assertIn('-X', prepared['argv'])
        outputs, sizes = certificates.parse_plan(self.plan, prepared)
        self.assertEqual(sizes['/store/bundle.pem'], 123)
        self.assertFalse(outputs['/store/bundle.pem']['replace'])

    def test_override_changes_bound_selection(self):
        before = self.prepare()
        self.policy['overrides'] = [{'path': '/roots/a.pem', 'role': 'untrusted'}]
        after = self.prepare()
        self.assertNotEqual(before['selection_sha256'], after['selection_sha256'])
        self.assertNotEqual(before['policy_sha256'], after['policy_sha256'])

    def test_invalid_policy_shapes(self):
        original = copy.deepcopy(self.policy)
        for bad in ([], {}, dict(original, format=True), dict(original, extra=1), dict(original, name='../x')):
            self.policy = bad
            with self.subTest(policy=bad), self.assertRaises(ValueError): self.prepare()

    def test_unknown_empty_and_ambiguous_selectors(self):
        original = copy.deepcopy(self.policy)
        for rule in ({'package': 'absent', 'prefix': '/roots', 'role': 'trusted'},
                     {'package': 'fixture', 'prefix': '/absent', 'role': 'trusted'},
                     {'package': 'fixture', 'prefix': '/roots', 'role': 'unknown'}):
            self.policy['selections'] = [rule]
            with self.subTest(rule=rule), self.assertRaises(ValueError): self.prepare()
        self.policy = original
        self.policy['selections'] *= 2
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.prepare()

    def test_nonregular_aliased_or_changed_inputs(self):
        for change in ({'type': 'symlink'}, {'hardlinks': ['/alias']}):
            old = dict(self.observed['/roots/a.pem'])
            self.observed['/roots/a.pem'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare()
            self.observed['/roots/a.pem'] = old
        self.observed['/tool']['sha256'] = 'e' * 64
        with self.assertRaisesRegex(ValueError, 'differs'): self.prepare()

    def test_override_must_name_selected_input_once(self):
        for overrides in ([{'path': '/site.pem', 'role': 'trusted'}],
                          [{'path': '/roots/a.pem', 'role': 'unknown'}],
                          [{'path': '/roots/a.pem', 'role': 'untrusted'}] * 2):
            self.policy['overrides'] = overrides
            with self.subTest(overrides=overrides), self.assertRaises(ValueError): self.prepare()

    def test_output_policy_requires_distinct_empty_verified_locations(self):
        original = dict(self.policy['outputs'])
        for key, value in [('bundle', '/store/trusted/bundle'), ('trusted_directory', '/store'),
                           ('bundle', '/store/a b'), ('mode', True), ('uid', -1), ('flags_set', 2**64)]:
            self.policy['outputs'] = dict(original, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): self.prepare()
        self.policy['outputs'] = original
        self.observed['/store/trusted/stale'] = {'type': 'file'}
        with self.assertRaisesRegex(ValueError, 'empty'): self.prepare()

    def test_plan_rejects_namespace_escape_aliases_duplicates_and_missing_bundle(self):
        prepared = self.prepare()
        for data in (self.plan.replace(b'/store/trusted/', b'/etc/'),
                     self.plan.replace(b'1234abcd.0', b'../bad'),
                     self.plan.replace(b'1234abcd.0', b'1234abcd.00'),
                     self.plan.replace(b'type=file', b'type=link'),
                     self.plan.replace(b'size=123', b'size=-1'),
                     self.plan.replace(b' mode=0444', b' mode=0777'),
                     self.plan + self.plan, self.plan.splitlines(keepends=True)[0],
                     b'x' * (certificates.MAX_PLAN + 1)):
            with self.subTest(data=data[:80]), self.assertRaises(ValueError):
                certificates.parse_plan(data, prepared)

    def test_planning_must_leave_candidate_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / 'plan'
            def execute(root, argv, output, timeout):
                output.write_bytes(self.plan)
                self.assertIn('-n', argv)
            changed = dict(self.observed, unexpected={'type': 'file'})
            with self.assertRaisesRegex(ValueError, 'modified'):
                certificates.compile_recipe(Path(temporary), self.inventory, self.observed,
                    self.policy, log, 10, execute, lambda root: changed)

    def test_policy_file_rejects_duplicates_symlinks_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'policy'
            for data in (b'{"format":1,"format":1}', b'x' * (certificates.MAX_POLICY + 1)):
                path.write_bytes(data)
                with self.assertRaises(ValueError): certificates.read_policy(path, construction.pkg)
            link = Path(temporary) / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError): certificates.read_policy(link, construction.pkg)


if __name__ == '__main__':
    unittest.main()
