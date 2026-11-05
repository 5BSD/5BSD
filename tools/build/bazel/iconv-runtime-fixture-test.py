#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Fixture boundary tests, independent of VM/root availability."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import runtime_profile

spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('iconv-runtime-fixture.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

class CheckerInputsTest(unittest.TestCase):
    def test_explicit_input_files_and_nested_names(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'input';p.write_text('plan input')
            value={'plan.json':str(p),'helper/module.py':str(p)}
            self.assertEqual(fixture.validate_checker_inputs(value),value)
    def test_unsafe_names_sources_and_collisions_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'input';p.write_text('plan input')
            for value in [[], {'../escape':str(p)}, {'/absolute':str(p)}, {'a//b':str(p)}, {'a\nb':str(p)},
                          {'a':str(p),'a/b':str(p)}, {'a':'relative'}, {'a':directory}, {'a':str(p)+'missing'}]:
                with self.subTest(value=value),self.assertRaises(ValueError):
                    fixture.validate_checker_inputs(value)

class FixtureBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'root'
        self.root.mkdir()
        self.archive = Path(self.temp.name) / 'data.tar'

    def archive_with(self, entries):
        with tarfile.open(self.archive, 'w') as stream:
            for name, kind, content in entries:
                entry = tarfile.TarInfo(name)
                if kind == 'symlink':
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = content
                    stream.addfile(entry)
                else:
                    payload = content.encode()
                    entry.size = len(payload)
                    entry.mode = 0o444
                    stream.addfile(entry, io.BytesIO(payload))

    def test_valid_versioned_module_link(self):
        self.archive_with([('usr/lib/i18n/libUTF8.so.5', 'file', 'module'),
                           ('usr/lib/i18n/libUTF8.so', 'symlink', 'libUTF8.so.5')])
        fixture.unpack(self.archive, self.root)
        records = fixture.inventory(self.root)
        self.assertEqual(records['usr/lib/i18n/libUTF8.so']['target'], 'libUTF8.so.5')
        self.assertEqual(records['usr/lib/i18n/libUTF8.so.5']['mode'], '0444')

    def test_archive_traversal_rejected(self):
        for name in ('../outside', '/absolute', 'nested/../../outside'):
            with self.subTest(name=name):
                self.archive_with([(name, 'file', 'x')])
                with self.assertRaises(ValueError):
                    fixture.unpack(self.archive, self.root)

    def test_symlink_escape_rejected(self):
        for target in ('/etc/passwd', '../../outside'):
            with self.subTest(target=target):
                self.archive_with([('link', 'symlink', target)])
                with self.assertRaises(ValueError):
                    fixture.unpack(self.archive, self.root)

    def test_duplicate_payload_rejected(self):
        self.archive_with([('file', 'file', 'first'), ('file', 'file', 'second')])
        with self.assertRaises(ValueError):
            fixture.unpack(self.archive, self.root)

    def test_write_through_archive_symlink_rejected(self):
        self.archive_with([('link', 'symlink', 'dir'), ('link/file', 'file', 'x')])
        with self.assertRaises(ValueError):
            fixture.unpack(self.archive, self.root)

    def test_boot_defaults_preserved_host_policy_and_seed_excluded(self):
        boot = Path(self.temp.name) / 'boot'
        (boot / 'defaults').mkdir(parents=True)
        (boot / 'defaults/loader.conf').write_text('maintained defaults')
        (boot / 'loader.conf').write_text('host policy')
        (boot / 'entropy').write_text('host secret seed')
        destination = Path(self.temp.name) / 'copied'
        fixture.copy_boot(boot, destination)
        self.assertEqual((destination / 'defaults/loader.conf').read_text(), 'maintained defaults')
        self.assertFalse((destination / 'loader.conf').exists())
        self.assertFalse((destination / 'entropy').exists())

    def test_profile_rejects_case_exceptions_and_non_integer_values(self):
        self.assertEqual(runtime_profile.validate({'timeout_scale':1}),{'timeout_scale':1})
        for invalid in [{'timeout_scale':0}, {'timeout_scale':21}, {'timeout_scale':True},
                        {'timeout_scale':3,'case':'compression'}, {'timeout_scale':'3'}]:
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):runtime_profile.validate(invalid)

    def test_explicit_kernel_module_hash_and_build_binding(self):
        kernel = self.root / 'kernel'
        kernel.write_bytes(b'selected-kernel')
        module = self.root / 'modules/zfs/zfs.ko'
        module.parent.mkdir(parents=True)
        module.write_bytes(b'selected-module')
        entry = {'path': str(module), 'sha256': fixture.digest(module), 'kernel_sha256': fixture.digest(kernel)}
        self.assertEqual(fixture.kernel_modules({'zfs.ko': entry}, kernel)['zfs.ko']['path'], str(module))
        for field in ['sha256', 'kernel_sha256']:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'hash mismatch'):
                fixture.kernel_modules({'zfs.ko': {**entry, field: '0'*64}}, kernel)
        outside = self.root / 'other.ko'
        outside.write_bytes(b'selected-module')
        with self.assertRaisesRegex(ValueError, 'selected kernel build'):
            fixture.kernel_modules({'zfs.ko': {**entry, 'path': str(outside)}}, kernel)
        with self.assertRaisesRegex(ValueError, 'basename'):
            fixture.kernel_modules({'../zfs.ko': entry}, kernel)

    def test_explicit_copy_collision_rejected(self):
        source = Path(self.temp.name) / 'source'
        source.write_text('payload')
        fixture.put(source, self.root / 'file', 0o555)
        with self.assertRaises(ValueError):
            fixture.put(source, self.root / 'file', 0o555)

if __name__ == '__main__':
    unittest.main()
