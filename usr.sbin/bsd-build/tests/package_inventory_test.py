# SPDX-License-Identifier: BSD-2-Clause
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

helper = os.environ.get('BSD_BUILD_INVENTORY_HELPER') or str(
    Path(__file__).resolve().parents[3] / 'tools/build/capimage/package_inventory.py')
spec = importlib.util.spec_from_file_location('package_inventory', helper)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class PackageFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_capture_exact_payload(self):
        path = self.package()
        result = inventory.inventory_archive(path, capture={'/sbin/custom': 7})
        self.assertEqual(result.pop('captured_payloads'), {'/sbin/custom': b'payload'})
        self.assertEqual(result, inventory.inventory_archive(path))

    def test_capture_bound_and_missing(self):
        path = self.package()
        with self.assertRaisesRegex(ValueError, 'invalid captured payload'):
            inventory.inventory_archive(path, capture={'/sbin/custom': 6})
        with self.assertRaisesRegex(ValueError, 'missing'):
            inventory.inventory_archive(path, capture={'/absent': 64})
        with self.assertRaisesRegex(ValueError, 'full inventory'):
            inventory.inventory_archive(path, manifest_only=True, capture={'/sbin/custom': 7})

    def package(self, name='custom-os', entries=None, files=None, directories=None, raw_manifest=None, compact=None):
        if entries is None:
            entries = [('/sbin/custom', tarfile.REGTYPE, b'payload', '', {})]
        if files is None:
            files = {p: {'sum': 'pkg-owned-checksum-format'} for p,t,_,_,_ in entries if t != tarfile.DIRTYPE}
        manifest = {'name': name, 'version': '42', 'files': files,
                    'directories': directories or {}, 'config': ['/sbin/custom']}
        path = self.root / (name + '.pkg')
        with tarfile.open(path, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            data = raw_manifest if raw_manifest is not None else json.dumps(manifest).encode()
            info = tarfile.TarInfo('+MANIFEST'); info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            if compact is not None:
                compact_data = json.dumps(compact).encode()
                compact_info = tarfile.TarInfo('+COMPACT_MANIFEST'); compact_info.size = len(compact_data)
                archive.addfile(compact_info, io.BytesIO(compact_data))
            for p,kind,data,target,pax in entries:
                info = tarfile.TarInfo(p); info.type = kind
                info.linkname = target; info.uid = 23; info.gid = 24
                info.uname = 'package-user'; info.gname = 'package-group'
                info.mode = 0o4510; info.mtime = 1700000000
                info.pax_headers = pax
                if kind == tarfile.REGTYPE:
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
                else:
                    archive.addfile(info)
        return path


class Inventory(PackageFixture):
    def test_compact_manifest_catalogue_fields(self):
        full = {'name': 'custom-os', 'version': '42',
                'files': {'/sbin/custom': {'sum': 'pkg-owned-checksum-format'}},
                'deps': {'runtime': {'origin': 'test/runtime', 'version': '1'}},
                'abi': 'FreeBSD:16:amd64', 'origin': 'test/custom',
                'shlibs_required': ['libexample.so.1'], 'annotations': {'FreeBSD_version': '1600018'}}
        compact = {k: v for k, v in full.items() if k != 'files'}
        inventory.inventory_archive(self.package(raw_manifest=json.dumps(full).encode(), compact=compact))
        for key in ('deps', 'abi', 'origin', 'shlibs_required', 'annotations'):
            with self.subTest(field=key):
                changed = dict(compact); changed.pop(key)
                with self.assertRaisesRegex(ValueError, 'metadata disagree'):
                    inventory.inventory_archive(self.package(raw_manifest=json.dumps(full).encode(), compact=changed))
        changed = dict(compact, shlibs_required=['libother.so.1'])
        with self.assertRaisesRegex(ValueError, 'metadata disagree'):
            inventory.inventory_archive(self.package(raw_manifest=json.dumps(full).encode(), compact=changed))
        changed = dict(compact, conflicts=['another-package'])
        with self.assertRaisesRegex(ValueError, 'metadata disagree'):
            inventory.inventory_archive(self.package(raw_manifest=json.dumps(full).encode(), compact=changed))

    def test_payload_metadata_and_scope(self):
        result = inventory.inventory_packages([self.package()])
        self.assertFalse(result['filesystem_reconciled'])
        self.assertFalse(result['bip_policy_applied'])
        self.assertEqual(result['authentication'], 'not-performed-by-inventory-reader')
        package = result['packages'][0]
        self.assertEqual(package['name'], 'custom-os')
        item = package['entries']['/sbin/custom']
        self.assertEqual((item['uid'], item['gid'], item['mode']), (23, 24, 0o4510))
        self.assertEqual((item['uname'], item['gname']), ('package-user', 'package-group'))
        self.assertEqual(item['mtime'], 1700000000)
        self.assertEqual(item['sha256'], inventory.hashlib.sha256(b'payload').hexdigest())
        self.assertEqual(item['size'], 7)
        self.assertEqual(package['config'], ['/sbin/custom'])

    def test_inputs_determine_inventory(self):
        package = self.package('hardware-example', entries=[('/boot/firmware/custom', tarfile.REGTYPE, b'firmware', '', {})])
        result = inventory.inventory_packages([package])['packages'][0]
        self.assertEqual(result['name'], 'hardware-example')
        self.assertEqual(list(result['entries']), ['/boot/firmware/custom'])

    def test_links_are_recorded_without_following(self):
        entries = [('/a', tarfile.REGTYPE, b'file', '', {}),
                   ('/b', tarfile.LNKTYPE, b'', '/a', {}),
                   ('/c', tarfile.SYMTYPE, b'', '../ordinary/data', {})]
        items = inventory.inventory_archive(self.package(entries=entries))['entries']
        self.assertEqual(items['/b']['type'], 'hardlink')
        self.assertEqual(items['/b']['target'], '/a')
        self.assertEqual(items['/c']['target'], '../ordinary/data')

    def test_manifest_percent_encoding(self):
        for raw, encoded in [('/ARABIC%UCS', '/ARABIC%25UCS'),
                             ('/literal%2e', '/literal%252e'),
                             ('/a+b', '/a+b'), ('/caf\u00e9', '/caf%c3%a9'),
                             ('/literal%zz', '/literal%zz')]:
            with self.subTest(raw=raw):
                package = self.package(entries=[(raw, tarfile.REGTYPE, b'x', '', {})],
                                       files={encoded: {}})
                self.assertIn(raw, inventory.inventory_archive(package)['entries'])

    def test_encoded_directory_and_config(self):
        manifest = {'name': 'custom-os', 'version': '42', 'files': {},
                    'directories': {'/d%25': {}}, 'config': ['/d%25/config%25']}
        package = self.package(entries=[('/d%', tarfile.DIRTYPE, b'', '', {})],
                               raw_manifest=json.dumps(manifest).encode())
        result = inventory.inventory_archive(package)
        self.assertEqual(result['directories'], {'/d%': {}})
        self.assertEqual(result['config'], ['/d%/config%'])

    def test_encoded_unsafe_paths(self):
        for encoded in ['/a/%2e%2e/b', '/a%00b', '/a%0ab', '/%2fb']:
            with self.subTest(encoded=encoded), self.assertRaises(ValueError):
                inventory.inventory_archive(self.package(files={encoded: {}}))

    def test_encoded_alias_duplicates(self):
        package = self.package(entries=[('/a', tarfile.REGTYPE, b'x', '', {})],
                               files={'/a': {}, '/%61': {}})
        with self.assertRaisesRegex(ValueError, 'disagree'):
            inventory.inventory_archive(package)

    def test_non_json_number_rejected(self):
        with self.assertRaisesRegex(ValueError, 'non-JSON'):
            inventory.inventory_archive(self.package(raw_manifest=b'{"name":"a","version":"1","x":NaN}'))

    def test_missing_declared_payload(self):
        with self.assertRaisesRegex(ValueError, 'disagree'):
            inventory.inventory_archive(self.package(files={'/absent': {}}))

    def test_unlisted_payload(self):
        with self.assertRaisesRegex(ValueError, 'disagree'):
            inventory.inventory_archive(self.package(files={}))

    def test_duplicate_payload(self):
        entry = ('/duplicate', tarfile.REGTYPE, b'file', '', {})
        with self.assertRaisesRegex(ValueError, 'duplicate package payload'):
            inventory.inventory_archive(self.package(entries=[entry, entry]))

    def test_path_alias_duplicate(self):
        entries = [('/a', tarfile.REGTYPE, b'a', '', {}), ('./a', tarfile.REGTYPE, b'a', '', {})]
        with self.assertRaisesRegex(ValueError, 'duplicate package payload'):
            inventory.inventory_archive(self.package(entries=entries))

    def test_duplicate_manifest_key(self):
        with self.assertRaisesRegex(ValueError, 'duplicate package manifest key'):
            inventory.inventory_archive(self.package(raw_manifest=b'{"name":"a","name":"b"}'))

    def test_directory_file_collision(self):
        with self.assertRaisesRegex(ValueError, 'conflicting package directory'):
            inventory.inventory_archive(self.package(directories={'/sbin/custom': {}}))

    def test_cross_package_owner_collision(self):
        with self.assertRaisesRegex(ValueError, 'conflicting package ownership'):
            inventory.inventory_packages([self.package('a'), self.package('b')])

    def test_shared_directory_metadata(self):
        first = self.package('a', entries=[('/a', tarfile.REGTYPE, b'a', '', {})], directories={'/shared': {'perm': '0755'}})
        second = self.package('b', entries=[('/b', tarfile.REGTYPE, b'b', '', {})], directories={'/shared': {'perm': '0755'}})
        self.assertEqual(len(inventory.inventory_packages([first, second])['packages']), 2)
        second = self.package('b', entries=[('/b', tarfile.REGTYPE, b'b', '', {})], directories={'/shared': {'perm': '0777'}})
        with self.assertRaisesRegex(ValueError, 'conflicting package directory metadata'):
            inventory.inventory_packages([first, second])

    def test_traversal(self):
        for path in ['../escape', '/a/../escape', '//escape', '/a//b', '/a/./b', '/bad\nname']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                inventory.inventory_archive(self.package(entries=[(path, tarfile.REGTYPE, b'bad', '', {})]))

    def test_special_file_refused(self):
        with self.assertRaisesRegex(ValueError, 'unsupported package object type'):
            inventory.inventory_archive(self.package(entries=[('/pipe', tarfile.FIFOTYPE, b'', '', {})]))

    def test_extended_attributes_not_silently_discarded(self):
        with self.assertRaisesRegex(ValueError, 'ACL/xattr inventory support required'):
            inventory.inventory_archive(self.package(entries=[('/attr', tarfile.REGTYPE, b'a', '', {'SCHILY.xattr.user.test': 'value'})]))

    def test_archive_symlink_refused(self):
        path = self.package(); link = self.root / 'alias.pkg'; link.symlink_to(path)
        with self.assertRaises(OSError):
            inventory.inventory_archive(link)

    def test_undeclared_directory(self):
        with self.assertRaisesRegex(ValueError, 'undeclared package directory'):
            inventory.inventory_archive(self.package(entries=[('/dir', tarfile.DIRTYPE, b'', '', {})]))

    def test_nondirectory_ancestor(self):
        entries = [('/a', tarfile.SYMTYPE, b'', '/elsewhere', {}),
                   ('/a/b', tarfile.REGTYPE, b'data', '', {})]
        with self.assertRaisesRegex(ValueError, 'nondirectory ancestor'):
            inventory.inventory_packages([self.package(entries=entries)])

    def test_hardlink_missing_target(self):
        with self.assertRaisesRegex(ValueError, 'lacks a regular payload target'):
            inventory.inventory_packages([self.package(entries=[('/a', tarfile.LNKTYPE, b'', '/missing', {})])])

    def test_hardlink_cycle(self):
        entries = [('/a', tarfile.LNKTYPE, b'', '/b', {}), ('/b', tarfile.LNKTYPE, b'', '/a', {})]
        with self.assertRaisesRegex(ValueError, 'cyclic package hardlink'):
            inventory.inventory_packages([self.package(entries=entries)])

    def test_hardlink_target_in_another_package(self):
        first = self.package('a', entries=[('/a', tarfile.LNKTYPE, b'', '/b', {})])
        second = self.package('b', entries=[('/b', tarfile.REGTYPE, b'data', '', {})])
        self.assertEqual(len(inventory.inventory_packages([first, second])['packages']), 2)

    def test_empty_inventory_refused(self):
        with self.assertRaises(ValueError):
            inventory.inventory_packages([])

    def test_directory_manifest_cannot_contradict_header(self):
        header = [('/shared', tarfile.DIRTYPE, b'', '', {})]
        for metadata in ({'perm': '0755'}, {'uname': 'different-owner'},
                         {'gname': 'different-group'}, {'fflags': 'schg'}):
            with self.subTest(metadata=metadata), self.assertRaisesRegex(ValueError, 'directory metadata'):
                inventory.inventory_archive(self.package(entries=header, directories={'/shared': metadata}))

    def test_directory_metadata_is_validated_even_with_header(self):
        header = [('/shared', tarfile.DIRTYPE, b'', '', {})]
        for metadata in ({'perm': True}, {'perm': '0999'}, {'unknown': 1},
                         {'fflags': 'not-a-file-flag'}, {'fflags': 'schg,noschg'},
                         {'fflags': 'schg\0ignored'}, {'uname': ''}, True):
            with self.subTest(metadata=metadata), self.assertRaisesRegex(ValueError, 'directory metadata'):
                inventory.inventory_archive(self.package(entries=header, directories={'/shared': metadata}))

    def test_shared_header_flags_cannot_disagree(self):
        first = self.package('a', entries=[('/shared', tarfile.DIRTYPE, b'', '', {})],
                             directories={'/shared': {}})
        second = self.package('b', entries=[('/shared', tarfile.DIRTYPE, b'', '', {'SCHILY.fflags': 'uchg'})],
                              directories={'/shared': {}})
        with self.assertRaisesRegex(ValueError, 'directory metadata'):
            inventory.inventory_packages([first, second])

    def test_agreeing_directory_header_and_declaration(self):
        metadata = {'uname': 'package-user', 'gname': 'package-group', 'perm': '4510', 'fflags': 'uchg'}
        package = self.package(entries=[('/shared', tarfile.DIRTYPE, b'', '', {'SCHILY.fflags': 'uchg'})],
                               directories={'/shared': metadata})
        self.assertEqual(inventory.inventory_archive(package)['directories']['/shared'], metadata)

    def test_directory_declaration_permissions_are_compared_semantically(self):
        first = self.package('a', entries=[('/a', tarfile.REGTYPE, b'a', '', {})],
                             directories={'/shared': {'perm': '0755'}})
        second = self.package('b', entries=[('/b', tarfile.REGTYPE, b'b', '', {})],
                              directories={'/shared': {'perm': '755'}})
        self.assertEqual(len(inventory.inventory_packages([first, second])['packages']), 2)



class Construction(PackageFixture):
    def contract(self, name='make-db', program='/bin/make-db', source='/etc/input', output='/etc/output'):
        return {'format': 1, 'actions': [{'name': name, 'argv': [program, source],
            'inputs': [source], 'outputs': {output: {'type': 'file', 'uid': 0, 'gid': 0,
                'mode': 0o644, 'flags_set': 0, 'replace': False}}}]}

    def archive(self, contract, name='producer', entries=None):
        if entries is None:
            entries = [('/bin/make-db', tarfile.REGTYPE, b'generator', '', {}),
                       ('/etc/input', tarfile.REGTYPE, b'input', '', {})]
        manifest = {'name': name, 'version': '1', 'files': {e[0]: {} for e in entries},
                    'annotations': {inventory.CONSTRUCTION_ANNOTATION:
                        json.dumps(contract) if not isinstance(contract, str) else contract}}
        return self.package(name=name, entries=entries, raw_manifest=json.dumps(manifest).encode())

    def plan(self, contract):
        return inventory.inventory_packages([self.archive(contract)])['construction']

    def test_construction_payload_binding(self):
        result = self.plan(self.contract())
        self.assertEqual(result['status'], 'declared-not-executed')
        self.assertFalse(result['outputs_approved'])
        action = result['actions'][0]
        self.assertEqual(action['executable_payload']['path'], '/bin/make-db')
        self.assertEqual(action['executable_payload']['sha256'], inventory.hashlib.sha256(b'generator').hexdigest())
        self.assertEqual(action['input_sources']['/etc/input']['payload']['sha256'], inventory.hashlib.sha256(b'input').hexdigest())
        self.assertEqual(action['package_sha256'], action['executable_payload']['archive_sha256'])
        self.assertEqual(action['argv'], ['/bin/make-db', '/etc/input'])

    def test_construction_rejects_unknown_fields_and_types(self):
        bad = [None, [], {}, {'format': True, 'actions': []}, {'format': 1, 'actions': []},
               {'format': 2, 'actions': []}, {'format': 1, 'actions': [], 'extra': 1}]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.plan(value)
        for field in ('unknown', 'package', 'package_sha256', 'executable_payload'):
            c = self.contract(); c['actions'][0][field] = 'supplied'
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.plan(c)

    def test_construction_duplicate_annotation_keys(self):
        for raw in ('{"format":1,"format":1,"actions":[]}',
                    '{"format":NaN,"actions":[]}', 'not json'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.plan(raw)

    def test_construction_unsafe_paths(self):
        for path in ('relative', '/', '/etc//x', '/etc/../x', '/etc/x/', '/etc/x\0y'):
            for field in ('program', 'source', 'output'):
                with self.subTest(path=path, field=field), self.assertRaises(ValueError):
                    self.plan(self.contract(**{field: path}))

    def test_construction_argv_and_identity(self):
        for argv in ([], ['/bin/make-db', None], ['/bin/make-db', ''], ['/bin/make-db', 'a\nb']):
            c = self.contract(); c['actions'][0]['argv'] = argv
            with self.subTest(argv=argv), self.assertRaises(ValueError): self.plan(c)
        for name in ('', '../escape', 'bad/name', 'x' * 65):
            with self.subTest(name=name), self.assertRaises(ValueError): self.plan(self.contract(name=name))
        c = self.contract(); c['actions'] *= 2
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.plan(c)

    def test_construction_argument_count_and_byte_bounds(self):
        c = self.contract()
        c['actions'][0]['argv'] = ['/bin/make-db'] + ['argument'] * 336
        self.assertEqual(len(self.plan(c)['actions'][0]['argv']), 337)
        for argv in (['/bin/make-db'] + ['a'] * 4096,
                     ['/bin/make-db'] + ['x' * 4096] * 32):
            c['actions'][0]['argv'] = argv
            with self.assertRaisesRegex(ValueError, 'argv'):
                self.plan(c)

    def test_construction_output_metadata(self):
        for key, value in [('mode', 0o10000), ('mode', True), ('uid', -1), ('gid', 2**32-1),
                           ('flags_set', -1), ('type', 'directory'), ('replace', 0)]:
            c = self.contract(); c['actions'][0]['outputs']['/etc/output'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): self.plan(c)
        c = self.contract(); del c['actions'][0]['outputs']['/etc/output']['mode']
        with self.assertRaises(ValueError): self.plan(c)

    def test_construction_missing_sources(self):
        for field in ('program', 'source'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.plan(self.contract(**{field: '/missing'}))
        c = self.contract(); c['actions'][0]['inputs'] *= 2
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.plan(c)

    def test_construction_replacement_is_explicit(self):
        c = self.contract(output='/etc/input')
        with self.assertRaises(ValueError): self.plan(c)
        c = self.contract(); c['actions'][0]['outputs']['/etc/output']['replace'] = True
        with self.assertRaisesRegex(ValueError, 'replacement'): self.plan(c)
        # An action may replace its own separate payload, with explicit consent.
        entries = [('/bin/make-db', tarfile.REGTYPE, b'generator', '', {}),
                   ('/etc/input', tarfile.REGTYPE, b'input', '', {}),
                   ('/etc/output', tarfile.REGTYPE, b'old', '', {})]
        plan = inventory.inventory_packages([self.archive(c, entries=entries)])['construction']
        self.assertTrue(plan['actions'][0]['outputs']['/etc/output']['replace'])

    def test_construction_output_ancestor(self):
        for output in ('/etc/input/child', '/bin', '/etc'):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, 'ancestor'):
                self.plan(self.contract(output=output))

    def test_construction_dependency_order(self):
        a = self.archive(self.contract(output='/etc/first'), name='z-producer')
        b = self.archive(self.contract(program='/bin/second', source='/etc/first', output='/etc/second'),
            name='a-consumer', entries=[('/bin/second', tarfile.REGTYPE, b'second', '', {})])
        actions = inventory.inventory_packages([b, a])['construction']['actions']
        self.assertEqual([a['package'] for a in actions], ['z-producer', 'a-consumer'])
        self.assertEqual(actions[1]['input_sources']['/etc/first'],
                         {'producer_package': 'z-producer', 'producer_action': 'make-db'})

    def test_construction_cycle_and_conflict(self):
        a = self.archive(self.contract(source='/etc/second', output='/etc/first'), name='a',
            entries=[('/bin/make-db', tarfile.REGTYPE, b'generator', '', {})])
        b = self.archive(self.contract(program='/bin/second', source='/etc/first', output='/etc/second'), name='b',
            entries=[('/bin/second', tarfile.REGTYPE, b'generator2', '', {})])
        with self.assertRaisesRegex(ValueError, 'cyclic'): inventory.inventory_packages([a,b])
        a = self.archive(self.contract(), name='a')
        b = self.archive(self.contract(program='/bin/second'), name='b',
            entries=[('/bin/second', tarfile.REGTYPE, b'generator2', '', {})])
        with self.assertRaisesRegex(ValueError, 'conflicting construction output'):
            inventory.inventory_packages([a,b])

    def test_construction_rejects_foreign_replacement(self):
        c = self.contract(); c['actions'][0]['outputs']['/etc/output']['replace'] = True
        a = self.archive(c, name='a')
        b = self.package('b', entries=[('/etc/output', tarfile.REGTYPE, b'foreign', '', {})])
        with self.assertRaisesRegex(ValueError, 'replacement'): inventory.inventory_packages([a,b])

    def test_construction_hardlink_replacement_rejected(self):
        # An output with aliases has more effects than its declared pathname.
        # This also covers aliases used as commands or inputs, including chains.
        for target in ('/bin/make-db', '/etc/input', '/etc/output'):
            c = self.contract(output=target)
            c['actions'][0]['argv'][0] = '/alias-command'
            c['actions'][0]['inputs'] = ['/alias-input']
            c['actions'][0]['outputs'][target]['replace'] = True
            entries = [('/bin/make-db', tarfile.REGTYPE, b'generator', '', {}),
                       ('/etc/input', tarfile.REGTYPE, b'input', '', {}),
                       ('/etc/output', tarfile.REGTYPE, b'old', '', {}),
                       ('/alias-command', tarfile.LNKTYPE, b'', '/bin/make-db', {}),
                       ('/alias-input', tarfile.LNKTYPE, b'', '/etc/input', {}),
                       ('/alias-first', tarfile.LNKTYPE, b'', target, {}),
                       ('/alias-second', tarfile.LNKTYPE, b'', '/alias-first', {})]
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'hardlink'):
                inventory.inventory_packages([self.archive(c, entries=entries)])

    def test_construction_long_hardlink_chain(self):
        entries = [('/bin/make-db', tarfile.REGTYPE, b'generator', '', {}),
                   ('/etc/input', tarfile.REGTYPE, b'input', '', {})]
        target = '/etc/input'
        for index in range(1100):
            path = '/link-' + str(index)
            entries.append((path, tarfile.LNKTYPE, b'', target, {}))
            target = path
        c = self.contract(source=target)
        plan = inventory.inventory_packages([self.archive(c, entries=entries)])['construction']
        self.assertEqual(plan['actions'][0]['input_sources'][target]['payload']['path'], '/etc/input')

    def test_construction_hardlink_inputs_bind_payload(self):
        c = self.contract(program='/alias-command', source='/alias-input')
        entries = [('/bin/make-db', tarfile.REGTYPE, b'generator', '', {}),
                   ('/etc/input', tarfile.REGTYPE, b'input', '', {}),
                   ('/alias-command', tarfile.LNKTYPE, b'', '/bin/make-db', {}),
                   ('/alias-input', tarfile.LNKTYPE, b'', '/etc/input', {})]
        plan = inventory.inventory_packages([self.archive(c, entries=entries)])['construction']
        self.assertEqual(plan['actions'][0]['executable_payload']['path'], '/bin/make-db')
        self.assertEqual(plan['actions'][0]['input_sources']['/alias-input']['payload']['path'], '/etc/input')

    def test_construction_symlink_input_rejected(self):
        for path in ('/etc/input', '/bin/make-db'):
            entries = [('/bin/make-db', tarfile.REGTYPE, b'generator', '', {}),
                       ('/etc/input', tarfile.REGTYPE, b'input', '', {})]
            entries = [(p, tarfile.SYMTYPE, b'', '/elsewhere', {}) if p == path else (p,t,d,l,x)
                       for p,t,d,l,x in entries]
            with self.subTest(path=path), self.assertRaises(ValueError):
                inventory.inventory_packages([self.archive(self.contract(), entries=entries)])


class SelectionCLI(PackageFixture):
    def selection(self, archive=None):
        archive = archive or self.package()
        path = self.root / 'selection.json'
        path.write_text(json.dumps({'format': 1, 'archives': [
            {'path': str(archive), 'sha256': inventory.hashlib.sha256(archive.read_bytes()).hexdigest()}]}))
        return path

    def invoke(self, selection):
        import subprocess, sys
        return subprocess.run([sys.executable, '-B', helper, '--selection', str(selection),
            '--output', str(self.root / 'inventory.json')], capture_output=True, text=True, timeout=10)

    def test_real_cli_binds_selection_and_preserves_existing_output(self):
        selection = self.selection()
        result = self.invoke(selection)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / 'inventory.json'
        original = output.read_bytes(); record = json.loads(original)
        self.assertEqual(record['selection_sha256'], inventory.hashlib.sha256(selection.read_bytes()).hexdigest())
        self.assertEqual(record['authentication'], 'not-performed-by-inventory-reader')
        self.assertEqual(record['packages'][0]['name'], 'custom-os')
        self.assertNotEqual(self.invoke(selection).returncode, 0)
        self.assertEqual(output.read_bytes(), original)

    def test_changed_archive_has_no_output(self):
        selection = self.selection()
        record = json.loads(selection.read_text()); record['archives'][0]['sha256'] = '0' * 64
        selection.write_text(json.dumps(record))
        result = self.invoke(selection)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('hash mismatch', result.stderr)
        self.assertFalse((self.root / 'inventory.json').exists())

    def test_incomplete_dependencies_have_no_output(self):
        manifest = {'name': 'custom-os', 'version': '42', 'files': {'/sbin/custom': {}},
                    'deps': {'missing': {'origin': 'test/missing', 'version': '1'}}}
        selection = self.selection(self.package(raw_manifest=json.dumps(manifest).encode()))
        result = self.invoke(selection)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('lacks dependencies', result.stderr)
        self.assertFalse((self.root / 'inventory.json').exists())

    def test_selected_conflict_has_no_output(self):
        manifest = {'name': 'custom-os', 'version': '42', 'files': {'/sbin/custom': {}},
                    'conflicts': ['custom-os']}
        selection = self.selection(self.package(raw_manifest=json.dumps(manifest).encode()))
        result = self.invoke(selection)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('declare package conflicts', result.stderr)
        self.assertFalse((self.root / 'inventory.json').exists())

    def test_selection_schema_and_duplicate_keys(self):
        selection = self.selection(); valid = json.loads(selection.read_text())
        cases = ['{"format":1,"format":1,"archives":[]}',
                 json.dumps(dict(valid, format=True)),
                 json.dumps(dict(valid, archives=valid['archives'] * 2)),
                 json.dumps(dict(valid, archives=[])),
                 json.dumps(dict(valid, unexpected=True))]
        for text in cases:
            with self.subTest(selection=text):
                selection.write_text(text)
                with self.assertRaises(ValueError):
                    inventory.selected_inventory(selection)

    def test_fifo_input_and_archive_do_not_wait(self):
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        self.assertNotEqual(self.invoke(fifo).returncode, 0)
        selection = self.root / 'selection.json'
        selection.write_text(json.dumps({'format': 1, 'archives': [{'path': str(fifo), 'sha256': '0' * 64}]}))
        result = self.invoke(selection)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not a regular file', result.stderr)
        self.assertFalse((self.root / 'inventory.json').exists())

    def repository_selection(self, roots=None):
        selection = self.root / 'selection.json'
        selection.write_text(json.dumps({'format': 2, 'repository': str(self.root),
                                        'roots': ['chosen-base'] if roots is None else roots}))
        return selection

    def metadata_package(self, name, **fields):
        manifest = dict(name=name, version='1', origin='test/' + name, files={})
        manifest.update(fields)
        return self.package(name=name, entries=[], files={}, raw_manifest=json.dumps(manifest).encode())

    def test_repository_roots_derive_exact_transitive_set(self):
        self.metadata_package('chosen-base', deps={'chosen-runtime': {'origin': 'test/chosen-runtime', 'version': '1'}},
                              shlibs_required=['libchosen.so.1'])
        self.metadata_package('chosen-runtime', deps={'chosen-base': {'origin': 'test/chosen-base', 'version': '1'}},
                              shlibs_provided=['libchosen.so.1'])
        # Unselected payloads are not claimed as inventoried or usable.
        self.metadata_package('unselected', files={'/missing-payload': {}})
        result = self.invoke(self.repository_selection())
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads((self.root / 'inventory.json').read_text())
        self.assertEqual([p['name'] for p in record['packages']], ['chosen-base', 'chosen-runtime'])
        self.assertEqual(record['repository_selection']['roots'], ['chosen-base'])
        self.assertEqual(record['authentication'], 'not-performed-by-inventory-reader')

    def test_repository_missing_roots_dependencies_and_duplicates(self):
        selection = self.repository_selection()
        with self.assertRaisesRegex(ValueError, 'lacks selected root'):
            inventory.selected_inventory(selection)
        package = self.metadata_package('chosen-base', deps={'absent': {'origin': 'test/absent', 'version': '1'}})
        with self.assertRaisesRegex(ValueError, 'lacks selected root or dependency'):
            inventory.selected_inventory(selection)
        (self.root / 'duplicate.pkg').write_bytes(package.read_bytes())
        with self.assertRaisesRegex(ValueError, 'duplicate repository package'):
            inventory.selected_inventory(selection)
        self.assertFalse((self.root / 'inventory.json').exists())

    def test_repository_selection_schema(self):
        self.metadata_package('chosen-base')
        for roots in ([], ['chosen-base', 'chosen-base'], [None], 'chosen-base'):
            with self.subTest(roots=roots), self.assertRaises(ValueError):
                inventory.selected_inventory(self.repository_selection(roots))
        path = self.repository_selection()
        record = json.loads(path.read_text()); record['repository'] += '/.'
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'canonical'):
            inventory.selected_inventory(path)

    def test_repository_manifest_change_rejected(self):
        from unittest.mock import patch
        self.metadata_package('chosen-base')
        real = inventory.inventory_archive
        def change_after_selection(path, **kwargs):
            result = real(path, **kwargs)
            if kwargs.get('manifest_only'):
                self.metadata_package('chosen-base', version='2')
            return result
        with patch.object(inventory, 'inventory_archive', side_effect=change_after_selection):
            with self.assertRaisesRegex(ValueError, 'manifest changed'):
                inventory.selected_inventory(self.repository_selection())
        self.assertFalse((self.root / 'inventory.json').exists())


if __name__ == '__main__':
    unittest.main()
