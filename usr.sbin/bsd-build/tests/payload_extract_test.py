# SPDX-License-Identifier: BSD-2-Clause
"""Adversarial preflight for private package payload reconstruction."""
import io
import json
import tarfile
import copy
import os
import importlib.util
from pathlib import Path
import tempfile
import unittest

source = os.environ.get('BSD_BUILD_EXTRACTION_HELPER') or (Path(__file__).resolve().parents[3] / 'tools/build/capimage/payload_extract.py')
spec = importlib.util.spec_from_file_location('payload_extract', source)
helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)


class AccountPlanning(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.archive = Path(self.temp.name) / 'accounts.pkg'

    def fixture(self, uid=0, duplicate=False):
        passwd = f'root:*:{uid}:0::0:0:root:/root:/bin/sh\n'.encode()
        if duplicate:
            passwd += passwd
        payloads = {'/etc/master.passwd': passwd, '/etc/group': b'wheel:*:0:root\n'}
        manifest = dict(name='accounts', version='1', files={n:'unused' for n in payloads},
                        directories={'/lib':dict(uname='root', gname='wheel', perm='0755')})
        with tarfile.open(self.archive, 'w:gz') as tar:
            for name, data in {'+MANIFEST':json.dumps(manifest).encode(), **payloads}.items():
                info=tarfile.TarInfo(name); info.size=len(data)
                info.uid=info.gid=65534; info.uname='root'; info.gname='wheel'
                tar.addfile(info, io.BytesIO(data))
        package=helper.generation.pkg.inventory_archive(self.archive)
        expected=copy.deepcopy(package['entries'])
        expected['/lib']=dict(type='directory', uid=65534, gid=65534, uname='root', gname='wheel', mode=0o755, flags_set=0)
        return dict(packages=[package]), expected

    def test_named_root_uses_candidate_not_archive_numeric_ids(self):
        inventory, expected=self.fixture()
        result=helper.planning_objects(inventory, expected)
        self.assertEqual((result['/lib']['uid'],result['/lib']['gid']),(0,0))
        self.assertEqual(expected['/lib']['uid'],65534)

    def test_nonzero_candidate_root_is_not_replaced_with_host_root(self):
        inventory, expected=self.fixture(uid=29)
        result=helper.planning_objects(inventory,expected)
        self.assertEqual(result['/lib']['uid'],29)

    def test_duplicate_account_rejected(self):
        inventory, expected=self.fixture(duplicate=True)
        with self.assertRaisesRegex(ValueError,'ambiguous or invalid'):
            helper.planning_objects(inventory,expected)

    def test_changed_archive_rejected(self):
        inventory, expected=self.fixture()
        self.fixture(uid=29)
        with self.assertRaisesRegex(ValueError,'package changed'):
            helper.planning_objects(inventory,expected)

    def test_unknown_account_rejected(self):
        inventory, expected=self.fixture()
        expected['/lib']['uname']='absent'
        with self.assertRaisesRegex(ValueError,'unknown generation account'):
            helper.planning_objects(inventory,expected)


class Preflight(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.root = self.base / 'root'; self.root.mkdir()
        entry = dict(type='file', uid=0, gid=0, mode=0o644, flags_set=0, size=0, sha256='0'*64)
        self.inventory = dict(format=1, scope='package-payload-inventory', packages=[dict(
            name='fixture', archive=str(self.base/'fixture.pkg'), archive_sha256='1'*64,
            entries={name:dict(entry) for name in ('/etc/master.passwd', '/etc/group')},
            directories={'/etc':dict(uname='root', gname='wheel', perm='0755')})])
        self.layout = dict(format=1, entries={'/':dict(type='directory', uid=0, gid=0,
            mode=0o755, flags_set=0, source='explicit test root layout', replaces=[])})

    def test_complete_layout(self):
        root, expected = helper.prepare(self.root,self.inventory,self.layout)
        self.assertEqual(root,self.root)
        self.assertEqual(set(expected),{'/','/etc','/etc/master.passwd','/etc/group'})
        self.assertEqual(list(root.iterdir()),[])

    def test_missing_parent(self):
        self.inventory['packages'][0]['directories']={}
        with self.assertRaisesRegex(ValueError,'missing declared parent'):
            helper.prepare(self.root,self.inventory,self.layout)

    def test_existing_payload_refused_without_change(self):
        sentinel=self.root/'sentinel';sentinel.write_bytes(b'retain')
        with self.assertRaisesRegex(ValueError,'must be empty'):
            helper.prepare(self.root,self.inventory,self.layout)
        self.assertEqual(sentinel.read_bytes(),b'retain')

    def test_symlink_root(self):
        alias=self.base/'alias';alias.symlink_to(self.root)
        with self.assertRaisesRegex(ValueError,'alternate root'):
            helper.prepare(alias,self.inventory,self.layout)

    def test_extra_generated_approval_refused(self):
        self.layout['entries']['/etc']=copy.deepcopy(self.layout['entries']['/'])
        with self.assertRaisesRegex(ValueError,'exact package inputs'):
            helper.prepare(self.root,self.inventory,self.layout)

    def test_explicit_unowned_directories(self):
        for name in ('/home', '/work', '/work/src'):
            self.layout['entries'][name]=copy.deepcopy(self.layout['entries']['/'])
        _, expected=helper.prepare(self.root,self.inventory,self.layout)
        self.assertEqual(expected['/work/src']['mode'],0o755)
        self.assertIn('/home',expected)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_layout_missing_parent_refused(self):
        self.layout['entries']['/missing/child']=copy.deepcopy(self.layout['entries']['/'])
        with self.assertRaisesRegex(ValueError,'missing declared parent'):
            helper.prepare(self.root,self.inventory,self.layout)

    def test_layout_replacement_even_with_exact_provenance_refused(self):
        item=copy.deepcopy(self.layout['entries']['/'])
        item['replaces']=['1'*64]
        self.layout['entries']['/etc']=item
        with self.assertRaisesRegex(ValueError,'cannot replace package objects'):
            helper.prepare(self.root,self.inventory,self.layout)

    def test_layout_non_directory_refused(self):
        for kind, fields in (('file',dict(size=0,sha256='0'*64)),
                             ('symlink',dict(target='/etc'))):
            with self.subTest(kind=kind):
                item=copy.deepcopy(self.layout['entries']['/'])
                item.update(type=kind,**fields)
                self.layout['entries']['/extra']=item
                with self.assertRaisesRegex(ValueError,'only directories'):
                    helper.prepare(self.root,self.inventory,self.layout)

    def test_layout_requires_explicit_root(self):
        self.layout['entries']={}
        with self.assertRaisesRegex(ValueError,'explicit root layout'):
            helper.prepare(self.root,self.inventory,self.layout)

    def test_layout_requires_provenance(self):
        item=copy.deepcopy(self.layout['entries']['/']); item['source']=''
        self.layout['entries']['/extra']=item
        with self.assertRaisesRegex(ValueError,'provenance/metadata'):
            helper.prepare(self.root,self.inventory,self.layout)

    def test_account_symlink_refused(self):
        self.inventory['packages'][0]['entries']['/etc/group']=dict(type='symlink',target='/host/group')
        with self.assertRaisesRegex(ValueError,'account inputs required'):
            helper.prepare(self.root,self.inventory,self.layout)

    def test_archive_inside_destination_refused(self):
        self.inventory['packages'][0]['archive']=str(self.root/'future.pkg')
        with self.assertRaisesRegex(ValueError,'outside extraction root'):
            helper.prepare(self.root,self.inventory,self.layout)


if __name__ == '__main__':
    unittest.main()
