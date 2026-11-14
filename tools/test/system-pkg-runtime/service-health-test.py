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
from service_health import operation_settings, operation_result, inventory, manager_states, required_services, load, exercise, installed_settings, installed_result


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

    def test_operations_reject_wrong_context_and_unbounded_inputs(self):
        good=dict(qualification='/capture',target='//test:client',output='client',guest_directory='/tmp',cases=['time','device-denied'])
        self.assertEqual(operation_settings(good),good)
        self.assertEqual(operation_settings(dict(good,cases=['log']))['cases'],['log'])
        for bad in [dict(good,cases=['device']),dict(good,cases=[]),
                    dict(good,cases=['time','time']),dict(good,cases='time'),
                    dict(good,cases=['unknown']),dict(good,guest_directory='/tmp/../root'),
                    dict(good,qualification=''),dict(good,unexpected=True)]:
            with self.subTest(bad=bad),self.assertRaises(ValueError):operation_settings(bad)

    def test_operations_require_matching_complete_success(self):
        good=dict(format=1,operation='notify',status='passed')
        self.assertEqual(operation_result(json.dumps(good),'notify'),good)
        for bad in [dict(good,format=True),dict(good,operation='time'),
                    dict(good,status='failed'),dict(good,extra=True),{},[]]:
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                operation_result(json.dumps(bad),'notify')

    def test_operation_policy_requires_an_ordinary_callback(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError,'ordinary-session'):
                exercise({'policy':{},'operations':{'cases':['time']}},
                         lambda *args:self.fail('guest mutation before callback validation'),
                         Path(directory),'fixture')

    def test_failed_operation_fails_the_whole_service_check(self):
        loaded={'policy':dict(roots=['/caps'],control_program='/caps/control',deadline_seconds=1),
                'helper':Path('/fixture/inventory'),'helper_binding':{'fixture':True},
                'operation_helper':Path('/fixture/operations'),'operation_helper_binding':{'fixture':True},
                'operations':dict(guest_directory='/tmp',cases=['time'])}
        def invoke(name,command,source=None):
            if name.endswith('-inventory'):return json.dumps(document()).encode()
            if '-status-' in name:
                return status(['org.test/daemon running  pid 42 restart=on-failure mgmt=core'])
            return b''
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                exercise(loaded,invoke,Path(directory),'fixture',
                         user_invoke=lambda *args:json.dumps(dict(format=1,operation='time',status='failed')))
            report=json.loads((Path(directory)/'fixture-service-health.json').read_text())
            self.assertEqual(report['status'],'failed')
            self.assertFalse(report['all_provider_operations_qualified'])

    def test_every_selected_operation_runs_and_coverage_stays_explicit(self):
        loaded={'policy':dict(roots=['/caps'],control_program='/caps/control',deadline_seconds=1),
                'helper':Path('/fixture/inventory'),'helper_binding':{'fixture':True},
                'operation_helper':Path('/fixture/operations'),'operation_helper_binding':{'fixture':True},
                'operations':dict(guest_directory='/tmp',cases=['time','notify'])}
        seen=[]
        def invoke(name,command,source=None):
            if name.endswith('-inventory'):return json.dumps(document()).encode()
            if '-status-' in name:
                return status(['org.test/daemon running  pid 42 restart=on-failure mgmt=core'])
            return b''
        def ordinary(name,command):
            case=name.rsplit('-',1)[-1];seen.append(case)
            return json.dumps(dict(format=1,operation=case,status='passed'))
        with tempfile.TemporaryDirectory() as directory:
            report=exercise(loaded,invoke,Path(directory),'fixture',user_invoke=ordinary)
            self.assertEqual(seen,['time','notify'])
            self.assertEqual(len(report['ordinary_operations']),2)
            self.assertEqual(report['status'],'passed')
            self.assertFalse(report['all_provider_operations_qualified'])


    def test_installed_operator_selection_requires_image_payload(self):
        good = [dict(operation='network-resolve', program='/caps/network operator')]
        self.assertEqual(installed_settings(good, {'/caps/network operator': 'image-hash'}), good)
        for bad in ([], good * 2, [dict(good[0], program='/unpackaged')],
                    [dict(good[0], operation='configtest')], [dict(good[0], session='root')]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                installed_settings(bad, {'/caps/network operator': 'image-hash'})

    def test_numeric_network_reply_is_complete_and_matches_input(self):
        good = (b'count=1 ttl_seconds=0 canonname=192.0.2.1\n'
                b'result[0].family=inet4 address=192.0.2.1 port=443 scope_id=0 socket_type=1 protocol=6\n')
        self.assertEqual(installed_result(good, 'network-resolve')['results'],
                         [dict(socket_type=1, protocol=6)])
        for bad in (b'', good[:-1], good.replace(b'count=1', b'count=2'),
                    good.replace(b'count=1', b'count=0'), good.replace(b'result[0]', b'result[1]'),
                    good.replace(b'192.0.2.1 port', b'192.0.2.2 port'),
                    good.replace(b'port=443', b'port=80'), good.replace(b'protocol=6', b'protocol=99'),
                    good + b'unexpected\n'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                installed_result(bad, 'network-resolve')

    def test_extension_enumeration_requires_ready_consistent_provider_records(self):
        good = (b'example: allowed, boot=enabled, loaded=no, installed=yes, policy=default\n'
                b'other: denied, boot=blocked, loaded=undisclosed, installed=no, policy=override\n')
        self.assertEqual(set(installed_result(good, 'system-extension-config')['modules']),
                         {'example', 'other'})
        for bad in (b'', good[:-1], good + good,
                    good.replace(b'loaded=undisclosed', b'loaded=yes'),
                    good.replace(b'boot=enabled', b'boot=blocked'),
                    good.replace(b'policy=default', b'policy=default (bootstrap; persistent policy not ready)'),
                    b'configuration valid\n'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                installed_result(bad, 'system-extension-config')

    def test_installed_tools_use_required_context_and_quote_program(self):
        loaded = {'policy': dict(roots=['/caps'], control_program='/caps/control', deadline_seconds=1),
                  'helper': Path('/fixture/inventory'), 'helper_binding': {'fixture': True},
                  'installed_payload_sha256': {'/caps/network operator': 'network-hash', '/caps/ext': 'extension-hash'},
                  'installed_operations': [dict(operation='network-resolve', program='/caps/network operator'),
                                           dict(operation='system-extension-config', program='/caps/ext')]}
        calls = []
        def root(name, command, source=None):
            calls.append(('root', name, command))
            if name.endswith('-inventory'):return json.dumps(document()).encode()
            if '-status-' in name:return status(['org.test/daemon running  pid 42 restart=on-failure mgmt=core'])
            if name.endswith('-operator-system-extension-config'):
                return b'example: allowed, boot=enabled, loaded=no, installed=yes, policy=default\n'
            return b''
        def ordinary(name, command):
            calls.append(('ordinary', name, command))
            return ('count=1 ttl_seconds=0 canonname=192.0.2.1\n'
                    'result[0].family=inet4 address=192.0.2.1 port=443 scope_id=0 socket_type=1 protocol=6\n')
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'ordinary-session'):
                exercise(loaded, root, Path(directory), 'missing-callback')
            self.assertEqual(calls, [])
            report = exercise(loaded, root, Path(directory), 'fixture', user_invoke=ordinary)
            self.assertEqual(report['status'], 'passed')
            self.assertFalse(report['all_provider_operations_qualified'])
            self.assertEqual([item['session'] for item in report['installed_operations']], ['ordinary', 'root'])
            self.assertIn(('ordinary', 'fixture-operator-network-resolve',
                           "'/caps/network operator' resolve -4 192.0.2.1 443"), calls)
            self.assertIn(('root', 'fixture-service-operator-system-extension-config', '/caps/ext config'), calls)

    def test_failed_installed_operator_fails_service_phase(self):
        loaded = {'policy': dict(roots=['/caps'], control_program='/caps/control', deadline_seconds=1),
                  'helper': Path('/fixture/inventory'), 'helper_binding': {'fixture': True},
                  'installed_payload_sha256': {'/caps/ext': 'extension-hash'},
                  'installed_operations': [dict(operation='system-extension-config', program='/caps/ext')]}
        def root(name, command, source=None):
            if name.endswith('-inventory'):return json.dumps(document()).encode()
            if '-status-' in name:return status(['org.test/daemon running  pid 42 restart=on-failure mgmt=core'])
            return b''
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):exercise(loaded, root, Path(directory), 'fixture')
            report = json.loads((Path(directory) / 'fixture-service-health.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertFalse(report['all_provider_operations_qualified'])


if __name__ == '__main__':unittest.main()
