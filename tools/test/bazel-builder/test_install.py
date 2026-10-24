#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import copy
import importlib.util
from pathlib import Path
import tempfile
import stat
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('builder_install', Path(__file__).with_name('install.py'))
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)

setup_spec = importlib.util.spec_from_file_location('builder_setup', Path(__file__).with_name('setup.py'))
setup = importlib.util.module_from_spec(setup_spec); setup_spec.loader.exec_module(setup)

class Guards(unittest.TestCase):
    def setUp(self):
        self.transport = {'format':1, 'scope':'offline-builder-package-transport',
                          'packages':[{'name':'example','version':'1','file':'archives/0000.pkg','sha256':'a'*64}]}

    def test_valid_transport(self):
        self.assertEqual(len(fixture.package_rows(self.transport)), 1)

    def test_archive_escape_and_duplicates(self):
        for value in ('../escape.pkg', '/archives/a.pkg', 'archives/../a.pkg',
                      'archives/a/b.pkg', 'archives//a.pkg', 'archives/a.pkg\n'):
            changed = copy.deepcopy(self.transport); changed['packages'][0]['file'] = value
            with self.assertRaises(ValueError): fixture.package_rows(changed)
        changed = copy.deepcopy(self.transport); changed['packages'] *= 2
        with self.assertRaises(ValueError): fixture.package_rows(changed)

    def test_version_and_hash_required(self):
        for key, value in [('version',''), ('sha256','Z'*64), ('name','')]:
            changed = copy.deepcopy(self.transport); changed['packages'][0][key] = value
            with self.assertRaises(ValueError): fixture.package_rows(changed)
        self.transport['format'] = 2
        with self.assertRaises(ValueError): fixture.package_rows(self.transport)

    def test_real_path_guards(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            source, target, output = [root / name for name in ('source','target','output')]
            for path in (source,target,output): path.mkdir()
            fixture.boundaries(source,target,output)
            with self.assertRaises(ValueError): fixture.boundaries(Path('/'),target,output)
            with self.assertRaises(ValueError): fixture.boundaries(source,source,output)
            nested = source/'child'; nested.mkdir()
            with self.assertRaises(ValueError): fixture.boundaries(source,nested,output)
            link = root/'link'; link.symlink_to(source)
            with self.assertRaises(ValueError): fixture.boundaries(link,target,output)
            (target/'existing').write_text('preserve')
            with self.assertRaises(ValueError): fixture.boundaries(source,target,output)
            self.assertEqual((target/'existing').read_text(),'preserve')

    def test_disk_guards(self):
        mounts = [['/dev/vtbd0p2','/','ufs','rw']]
        setup.validate_devices('/dev/vtbd1','/dev/vtbd2',mounts)
        for source, target in [('/dev/vtbd1','/dev/vtbd1'),
                               ('/dev/vtbd1','/dev/vtbd0'),
                               ('/dev/vtbd0','/dev/vtbd2'),
                               ('/dev/vtbd1','/dev/vtbd2p1'),
                               ('/dev/vtbd1','/dev/ada0')]:
            with self.assertRaises(ValueError): setup.validate_devices(source,target,mounts)
        with self.assertRaises(ValueError):
            setup.validate_devices('/dev/vtbd1','/dev/vtbd2',
                mounts + [['/dev/vtbd2','/other','ufs','rw']])

    def test_mountpoint_metadata(self):
        for mode in (0o500, 0o550, 0o555, 0o700, 0o750, 0o755):
            setup.mountpoint_metadata(SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | mode))
        for uid, mode in ((1001, stat.S_IFDIR | 0o700), (0, stat.S_IFDIR | 0o777),
                          (0, stat.S_IFREG | 0o700), (0, stat.S_IFDIR | 0o775),
                          (0, stat.S_IFDIR | 0o757), (0, stat.S_IFDIR | 0o400),
                          (0, stat.S_IFDIR | 0o100), (0, stat.S_IFDIR | 0o1755),
                          (0, stat.S_IFDIR | 0o2755), (0, stat.S_IFDIR | 0o4755)):
            with self.assertRaises(ValueError):
                setup.mountpoint_metadata(SimpleNamespace(st_uid=uid, st_mode=mode))

    def test_mountpoint_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            new = root / 'new'
            self.assertTrue(setup.validate_mountpoint(new, []))
            self.assertFalse(new.exists())
            with self.assertRaises(ValueError): setup.validate_mountpoint(Path('/'), [])
            with self.assertRaises(ValueError):
                setup.validate_mountpoint(new, [['/dev/vtbd1', str(new), 'ufs', 'ro']])
            link = root / 'link'; link.symlink_to(root)
            with self.assertRaises(ValueError): setup.validate_mountpoint(link, [])
            with self.assertRaises(ValueError): setup.validate_mountpoint(link / 'child', [])
            existing = root / 'existing'; existing.mkdir(mode=0o700)
            (existing / 'keep').write_text('preserved')
            with self.assertRaises(ValueError): setup.validate_mountpoint(existing, [])
            self.assertEqual((existing / 'keep').read_text(), 'preserved')

    def test_longest_mount_match(self):
        rows=[['/dev/root','/','ufs','rw'],['tmpfs','/mnt/tmp','tmpfs','rw'],
              ['/dev/vtbd1p1','/mnt','ufs','ro']]
        self.assertEqual(fixture.mounted_filesystem(Path('/mnt/tmp/file'),rows)[2],'tmpfs')
        self.assertEqual(fixture.mounted_filesystem(Path('/mnt/file'),rows)[3],'ro')

if __name__ == '__main__': unittest.main()
