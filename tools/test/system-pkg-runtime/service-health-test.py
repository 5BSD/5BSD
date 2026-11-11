# SPDX-License-Identifier: BSD-2-Clause
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
root = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"] if "TEST_SRCDIR" in os.environ else Path(__file__).resolve().parents[3]
sys.path.insert(0, str(root / "tools/build/bazel"))
from service_health import inventory, manager_states, required_services, load


def document():
    return {'format': 1, 'bundles': [{'path': '/caps/Test.cap', 'id': 'org.test',
        'services': [{'label': 'org.test/daemon', 'program': '/caps/Test.cap/Units/daemon.unit/bin/daemon',
                      'boot': True, 'endpoints': ['test.Endpoint']},
                     {'label': 'org.test/lazy', 'program': '/caps/Test.cap/Units/lazy.unit/bin/lazy',
                      'boot': False, 'endpoints': []}]}]}


def status(rows):
    return ('switchboard: running\nservices: ' + str(len(rows)) + ' loaded\n'
            'fd-budget: soft=1024 hard=1024 reserve=4 denied=0 control-shed=0\n' +
            ''.join('  ' + row + '\n' for row in rows)).encode()


class ServiceCoverage(unittest.TestCase):
    def test_manifest_drives_required_set(self):
        services = inventory(json.dumps(document()), ['/caps'])
        states = manager_states(status(['org.test/daemon running  pid 42 restart=on-failure mgmt=core by=system',
                                        'org.test/lazy stopped  restart=never mgmt=user']))
        self.assertEqual(required_services(services, states), ['org.test/daemon'])
        # A newly packaged boot service becomes required automatically.
        added = copy.deepcopy(services['org.test/daemon'])
        added['label'] = 'org.future/new'
        services[added['label']] = added
        with self.assertRaisesRegex(ValueError, 'org.future/new'):
            required_services(services, states)
        states['org.future/new'] = dict(state='running', pid=43, cleanup=False)
        self.assertEqual(required_services(services, states), ['org.future/new', 'org.test/daemon'])

    def test_missing_stopped_or_cleaning_service_fails(self):
        services = inventory(json.dumps(document()), ['/caps'])
        for row in ('org.test/daemon stopped  restart=on-failure mgmt=core',
                    'org.test/daemon starting  pid 42 restart=on-failure mgmt=core',
                    'org.test/daemon running  restart=on-failure mgmt=core',
                    'org.test/daemon running  pid 42 restart=on-failure mgmt=core cleanup=blocked'):
            with self.subTest(row=row), self.assertRaises(ValueError):
                required_services(services, manager_states(status([row])))
        with self.assertRaises(ValueError):
            required_services(services, {})

    def test_truncation_duplicates_and_malformed_status_fail(self):
        valid = status(['org.test/daemon running  pid 42 restart=on-failure mgmt=core'])
        cases = [valid[:-1], valid.replace(b'1 loaded', b'2 loaded'), b'',
                 valid + b'  org.test/daemon running pid 43 restart=never mgmt=core\n',
                 valid.replace(b'mgmt=core', b'mgmt=c'),
                 valid.replace(b' running  pid', b' unknown  pid'),
                 valid + b'switchboard: running\n']
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValueError):
                manager_states(data)

    def test_inventory_rejects_omissions_and_foreign_objects(self):
        cases = []
        d = document();d['bundles'] *= 2;cases.append(d)
        d = document();d['bundles'][0]['services'] *= 2;cases.append(d)
        d = document();d['bundles'][0]['path'] = '/foreign/Test.cap';cases.append(d)
        d = document();d['bundles'][0]['services'][0]['program'] = '/elsewhere/program';cases.append(d)
        d = document();d['bundles'][0]['services'][0]['boot'] = 1;cases.append(d)
        d = document();del d['bundles'][0]['services'][0]['boot'];cases.append(d)
        cases.append({'format': 1, 'bundles': []})
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValueError):
                inventory(json.dumps(data), ['/caps'])

    def test_policy_rejects_implicit_roots_and_invalid_deadlines(self):
        good = dict(format=1, qualification='/missing-qualification', target='//test:inventory',
                    output='inventory', roots=['/caps'], control_program='/caps/control', deadline_seconds=10)
        cases = [dict(good, roots=[]), dict(good, roots=['/caps', '/caps']),
                 dict(good, roots=['relative']), dict(good, roots='/caps'),
                 dict(good, deadline_seconds=0), dict(good, deadline_seconds=True),
                 dict(good, control_program='/unpackaged/control'), dict(good, format=True)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            for policy in cases:
                path.write_text(json.dumps(policy))
                with self.subTest(policy=policy), self.assertRaises(ValueError):
                    load(path, {'payload_sha256': {'/caps/control': 'declared-test-input'}})
            path.write_text(json.dumps(good))
            # A structurally valid policy still cannot substitute an uncaptured tool.
            with self.assertRaises(FileNotFoundError):
                load(path, {'payload_sha256': {'/caps/control': 'declared-test-input'}})

    def test_no_boot_service_is_not_full_base_qualification(self):
        services = inventory(json.dumps(document()), ['/caps'])
        for service in services.values():service['boot'] = False
        with self.assertRaises(ValueError):required_services(services, {})


if __name__ == '__main__':unittest.main()
