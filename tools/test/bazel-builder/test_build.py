#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import build


class BuildGuards(unittest.TestCase):
    def test_three_distinct_unmounted_disks(self):
        config = dict(input_device='/dev/vtbd1', root_device='/dev/vtbd2', workspace_device='/dev/vtbd3')
        build.validate_devices(config, [['/dev/vtbd0', '/', 'ufs', 'ro']])
        for key, value in [('workspace_device', '/dev/vtbd2'), ('root_device', '/dev/vtbd0'),
                           ('workspace_device', '/dev/vtbd3p1'), ('input_device', '/dev/ada1')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                build.validate_devices(dict(config, **{key: value}), [['/dev/vtbd0', '/', 'ufs', 'ro']])
        with self.assertRaises(ValueError):
            build.validate_devices(config, [['/dev/vtbd3p1', '/other', 'ufs', 'rw']])

    def test_relative_paths(self):
        self.assertEqual(build.relative('ports/devel/bazel9'), 'ports/devel/bazel9')
        for name in ('', '/ports', '../ports', 'ports/../escape', './ports', 'ports//a'):
            with self.subTest(name=name), self.assertRaises(ValueError): build.relative(name)

    def test_input_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); (root/'file').write_text('input')
            self.assertEqual(build.inside(root, 'file'), root/'file')
            (root/'alias').symlink_to('file')
            with self.assertRaises(ValueError): build.inside(root, 'alias')

    def archive(self, root, name, kind=tarfile.REGTYPE, target=''):
        p = root/'ports.tar'
        with tarfile.open(p, 'w') as stream:
            entry = tarfile.TarInfo(name); entry.type = kind; entry.linkname = target
            stream.addfile(entry, io.BytesIO(b''))
        return p

    def test_safe_source_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            build.validate_archive(self.archive(root, 'ports/Mk/bsd.port.mk'))
            build.validate_archive(self.archive(root, 'ports/category/link', tarfile.SYMTYPE, '../other'))

    def test_archive_alias_ancestors_and_hardlink_cycles(self):
        cases = [
            [('ports/alias', tarfile.SYMTYPE, 'real'), ('ports/alias/file', tarfile.REGTYPE, '')],
            [('ports/alias/file', tarfile.REGTYPE, ''), ('ports/alias', tarfile.SYMTYPE, 'real')],
            [('a', tarfile.SYMTYPE, 'dir'), ('b', tarfile.LNKTYPE, 'a/file')],
            [('a', tarfile.LNKTYPE, 'b'), ('b', tarfile.LNKTYPE, 'a')],
            [('dir/alias', tarfile.SYMTYPE, '..'), ('dir/link', tarfile.SYMTYPE, 'alias/../../outside')],
        ]
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)/'ports.tar'
            for members in cases:
                with tarfile.open(p, 'w') as stream:
                    for name, kind, target in members:
                        entry = tarfile.TarInfo(name); entry.type = kind; entry.linkname = target
                        stream.addfile(entry, io.BytesIO(b''))
                with self.subTest(members=members), self.assertRaises(ValueError):
                    build.validate_archive(p)

    def test_archive_escape_and_special_types(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, kind, target in [('.. /file', tarfile.FIFOTYPE, ''), ('../file', tarfile.REGTYPE, ''),
                                       ('/file', tarfile.REGTYPE, ''), ('link', tarfile.SYMTYPE, '../outside'),
                                       ('link', tarfile.LNKTYPE, '/outside'), ('ports/device', tarfile.CHRTYPE, '')]:
                with self.subTest(name=name, target=target), self.assertRaises(ValueError):
                    build.validate_archive(self.archive(root, name, kind, target))


if __name__ == '__main__':
    unittest.main()
