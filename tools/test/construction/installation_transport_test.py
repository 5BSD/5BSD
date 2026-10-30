# SPDX-License-Identifier: BSD-2-Clause
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def module(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj

transport=module('installation_transport')
fixtures=module('fixture_stage')


class Transport(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.extra=self.base/'extra';self.extra.mkdir()
        self.fixture=fixtures.Fixture(self.base,self.base,self.extra)
        self.input=self.base/'input';self.input.write_bytes(b'explicit installation input')
        self.policy=dict(format=1,entries={'/etc/example.conf':dict(source=str(self.input),
            size=self.input.stat().st_size,sha256=hashlib.sha256(self.input.read_bytes()).hexdigest(),
            uid=0,gid=0,mode=0o600,replaces=['a'*64])})
        self.path=self.base/'policy.json';self.write_policy()

    def write_policy(self):self.path.write_text(json.dumps(self.policy))
    def stage(self):return transport.stage(self.path,self.fixture)

    def test_transport_only_changes_source_paths(self):
        report=self.stage(); translated,checked=transport.verify(self.extra/'tests')
        self.assertEqual(report,checked)
        expected=json.loads(json.dumps(self.policy));expected['entries']['/etc/example.conf']['source']='/tests/installation-inputs/0'
        self.assertEqual(expected,translated)
        self.assertEqual(self.fixture.source_hashes[str(self.input)],self.policy['entries']['/etc/example.conf']['sha256'])
        self.assertEqual(self.input.read_bytes(),b'explicit installation input')

    def test_creation_operation_survives_transport(self):
        self.policy['format'] = 2
        self.policy['entries']['/etc/example.conf'].update(operation='create', replaces=[])
        self.write_policy()
        self.stage()
        translated, _ = transport.verify(self.extra/'tests')
        self.assertEqual(translated['format'], 2)
        self.assertEqual(translated['entries']['/etc/example.conf']['operation'], 'create')
        self.assertEqual(translated['entries']['/etc/example.conf']['replaces'], [])

    def test_template_policy_preserves_operations_and_owners(self):
        self.policy['format'] = 5
        entry = self.policy['entries'].pop('/etc/example.conf')
        entry['operation'] = 'replace-template'
        self.policy['entries']['/boot/capsule.conf'] = entry
        move = dict(operation='relocate', target='/state/account',
                    package='runtime', requirement='account')
        self.policy['entries']['/etc/account'] = move
        self.write_policy()
        self.stage()
        translated, _ = transport.verify(self.extra/'tests')
        expected = json.loads(json.dumps(self.policy))
        expected['entries']['/boot/capsule.conf']['source'] = '/tests/installation-inputs/0'
        self.assertEqual(translated, expected)
        self.assertFalse((self.extra/'tests/installation-inputs/1').exists())
        # A refreshed transport digest must not authorize changing the operation.
        path = self.extra/'tests/system-installation-policy.json'
        translated['entries']['/boot/capsule.conf']['operation'] = 'replace'
        path.write_text(json.dumps(translated))
        receipt_path = self.extra/'tests/system-installation-transport.json'
        receipt = json.loads(receipt_path.read_text())
        receipt['translated_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        receipt_path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'beyond source paths'):
            transport.verify(self.extra/'tests')

    def test_duplicate_json_keys(self):
        self.path.write_text('{"format":1,"format":1,"entries":{}}')
        with self.assertRaisesRegex(ValueError,'duplicate'):self.stage()

    def test_alias_and_file_transport_preserves_candidate_target(self):
        self.policy['format'] = 3
        self.policy['entries']['/etc/example.conf']['operation'] = 'replace'
        alias = dict(operation='alias', target='/nonexistent-candidate/socket',
                     package='daemon-package', requirement='socket')
        self.policy['entries']['/a-socket'] = alias
        self.write_policy()
        self.stage()
        translated, _ = transport.verify(self.extra/'tests')
        self.assertEqual(translated['entries']['/a-socket'], alias)
        self.assertEqual(translated['entries']['/etc/example.conf']['source'],
                         '/tests/installation-inputs/1')
        self.assertFalse((self.extra/'tests/installation-inputs/0').exists())

    def test_relocation_transport_never_reads_candidate_paths_on_host(self):
        self.policy = dict(format=4, entries={'/etc/account': dict(operation='relocate',
            target='/state/account', package='runtime', requirement='account')})
        self.write_policy()
        self.stage()
        translated, _ = transport.verify(self.extra/'tests')
        self.assertEqual(translated, self.policy)
        self.assertFalse((self.extra/'tests/installation-inputs').exists())
        self.assertTrue(transport.is_candidate_path(self.policy, self.policy['entries']['/etc/account']))

    def test_alias_only_has_no_source_inputs(self):
        self.policy = dict(format=3, entries={'/socket': dict(operation='alias',
            target='/state/socket', package='daemon-package', requirement='socket')})
        self.write_policy()
        self.stage()
        translated, _ = transport.verify(self.extra/'tests')
        self.assertEqual(translated, self.policy)
        self.assertFalse((self.extra/'tests/installation-inputs').exists())
        policy_path = self.extra/'tests/system-installation-policy.json'
        translated['entries']['/socket']['target'] = '/different/socket'
        policy_path.write_text(json.dumps(translated))
        receipt_path = self.extra/'tests/system-installation-transport.json'
        receipt = json.loads(receipt_path.read_text())
        receipt['translated_sha256'] = hashlib.sha256(policy_path.read_bytes()).hexdigest()
        receipt_path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'beyond source paths'):
            transport.verify(self.extra/'tests')

    def test_alias_cannot_smuggle_source_fields(self):
        self.policy['format'] = 3
        self.policy['entries']['/etc/example.conf']['operation'] = 'alias'
        self.write_policy()
        with self.assertRaisesRegex(ValueError, 'transport alias'): self.stage()

    def test_source_alias(self):
        alias=self.base/'alias';alias.symlink_to(self.input)
        self.policy['entries']['/etc/example.conf']['source']=str(alias);self.write_policy()
        with self.assertRaisesRegex(ValueError,'unaliased'):self.stage()

    def test_changed_source(self):
        self.input.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'size differs'):self.stage()
        self.assertFalse((self.extra/'tests/system-installation-transport.json').exists())

    def test_copied_content_corruption(self):
        self.stage();(self.extra/'tests/installation-inputs/0').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'size differs'):transport.verify(self.extra/'tests')

    def test_translation_cannot_change_authority_fields(self):
        self.stage();path=self.extra/'tests/system-installation-policy.json'
        data=json.loads(path.read_text());data['entries']['/etc/example.conf']['mode']=0o666
        path.write_text(json.dumps(data))
        receipt=self.extra/'tests/system-installation-transport.json';report=json.loads(receipt.read_text())
        report['translated_sha256']=hashlib.sha256(path.read_bytes()).hexdigest();receipt.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError,'beyond source paths'):transport.verify(self.extra/'tests')

    def test_copied_source_alias(self):
        self.stage();path=self.extra/'tests/installation-inputs/0';path.unlink();path.symlink_to(self.input)
        with self.assertRaisesRegex(ValueError,'unaliased'):transport.verify(self.extra/'tests')

    def test_existing_output_refused(self):
        self.stage()
        with self.assertRaisesRegex(ValueError,'already exists'):self.stage()


if __name__=='__main__':unittest.main()
