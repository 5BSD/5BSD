#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Refuse unsafe private-stage destinations before even parsing source ELF."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from assemble_capsule import assemble, policy_destination, write_metalog, install_switchboard_policy

class Destinations(unittest.TestCase):


    def test_retired_session_inputs_rejected(self):
        for option, value in (('session_storage_principals', ['a', 'b', 'c']),
                              ('provider_lifecycle', True), ('session_policy', self.outside / 'old.ucl')):
            with self.subTest(option=option), self.assertRaises(TypeError):
                assemble(self.root, self.obj, self.system, **{option: value})

    def test_crash_fixture_requires_provider_inputs(self):
        with self.assertRaisesRegex(ValueError, 'requires filesystem policy'):
            assemble(self.root, self.obj, self.system, provider_crash=True)

    def test_policy_replaces_readonly_entry_without_changing_linked_source(self):
        import os
        source = self.outside / 'identities.ucl'
        source.write_bytes(b'new input')
        old = self.outside / 'old-policy'
        old.write_bytes(b'old input')
        old.chmod(0o444)
        target = self.system / 'Capabilities/Config/switchboard/boot-authority.ucl'
        target.parent.mkdir(parents=True)
        os.link(old, target)
        install_switchboard_policy(self.system, source, 'boot-authority.ucl')
        self.assertEqual(old.read_bytes(), b'old input')
        self.assertEqual(old.stat().st_mode & 0o777, 0o444)
        self.assertEqual(target.read_bytes(), b'new input')
        self.assertNotEqual(old.stat().st_ino, target.stat().st_ino)

    def test_switchboard_policy_input(self):
        source = self.outside / 'deployment.ucl'
        source.write_bytes(b'authorities=[];\n')
        self.assertEqual(install_switchboard_policy(self.system, source, 'boot-authority.ucl'), source.resolve())
        target = self.system / 'Capabilities/Config/switchboard/boot-authority.ucl'
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertEqual(target.stat().st_mode & 0o777, 0o444)
        with self.assertRaisesRegex(ValueError, 'outside the image'):
            install_switchboard_policy(self.system, target, 'boot-authority.ucl')
        target.unlink()
        target.symlink_to(source)
        with self.assertRaises(ValueError):
            install_switchboard_policy(self.system, source, 'boot-authority.ucl')
        self.assertEqual(source.read_bytes(), b'authorities=[];\n')

    def test_switchboard_policy_rejects_nonfile_and_oversize(self):
        with self.assertRaises(ValueError):
            install_switchboard_policy(self.system, self.outside, 'boot-authority.ucl')
        source = self.outside / 'large.ucl'
        source.write_bytes(b'x' * (1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            install_switchboard_policy(self.system, source, 'boot-authority.ucl')

    def test_metalog_preserves_symlink_without_following(self):
        (self.system / 'alias').symlink_to('missing target#')
        metalog = self.system / 'METALOG'
        write_metalog(self.system, metalog)
        self.assertIn('./alias link=missing\\040target\\043 type=link ', metalog.read_text())
        self.assertFalse((self.system / 'missing target#').exists())

    def test_metalog_quotes_path_bytes(self):
        name = 'custom policy#\\.ucl'
        (self.system / name).write_text('policy bytes')
        metalog = self.system / 'METALOG'
        write_metalog(self.system, metalog)
        self.assertIn('./custom\\040policy\\043\\134.ucl type=file ', metalog.read_text())

    def test_policy_destination_is_an_input(self):
        root = self.system
        self.assertEqual(policy_destination(root, '/Config/custom storage.ucl'),
                         root / 'Config/custom storage.ucl')
        for name in ('relative', '/', '/a//b', '/a/../b', '/a/./b', '/a/', '/a\nb'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                policy_destination(root, name)

    def test_policy_destination_rejects_symlinks(self):
        (self.system / 'Config').symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            policy_destination(self.system, '/Config/policy.ucl')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root, self.obj, self.system = [base / name for name in ('world', 'obj', 'image')]
        for path in (self.root, self.obj, self.system):
            path.mkdir()
        source = self.obj / 'usr.sbin/capsule/capsule'
        source.parent.mkdir(parents=True)
        source.write_bytes(b'inert source; rejection must precede ELF parsing')
        self.outside = base / 'outside'
        self.outside.mkdir()
        (self.outside / 'capsule').write_bytes(b'preserve')

    def refused(self):
        with self.assertRaisesRegex(ValueError, 'fixture destination'):
            assemble(self.root, self.obj, self.system)
        self.assertEqual((self.outside / 'capsule').read_bytes(), b'preserve')

    def test_nonexecutable_program_rejected_before_dependencies(self):
        source = self.obj / 'usr.sbin/capsule/capsule'
        for elf_type, headers in ((2, ''), (3, 'Requesting program interpreter: /libexec/ld-elf.so.1')):
            with self.subTest(elf_type=elf_type):
                header = bytearray(18)
                header[:4] = b'\x7fELF'
                header[5] = 1
                header[16:18] = elf_type.to_bytes(2, 'little')
                source.write_bytes(header)
                source.chmod(0o644)
                with patch('assemble_capsule.subprocess.check_output', return_value=headers) as readelf:
                    with self.assertRaisesRegex(ValueError, 'lacks execute permission'):
                        assemble(self.root, self.obj, self.system)
                    self.assertEqual(readelf.call_count, 1)
                self.assertEqual(source.stat().st_mode & 0o777, 0o644)

    def test_symlink_leaf(self):
        (self.system / 'sbin').mkdir()
        (self.system / 'sbin/capsule').symlink_to(self.outside / 'capsule')
        self.refused()
        self.assertTrue((self.system / 'sbin/capsule').is_symlink())

    def test_directory_leaf(self):
        (self.system / 'sbin/capsule').mkdir(parents=True)
        self.refused()
        self.assertTrue((self.system / 'sbin/capsule').is_dir())

    def test_symlink_parent(self):
        (self.system / 'sbin').symlink_to(self.outside, target_is_directory=True)
        self.refused()

    def test_dangling_symlink(self):
        (self.system / 'sbin').mkdir()
        (self.system / 'sbin/capsule').symlink_to(self.outside / 'missing')
        self.refused()
        self.assertFalse((self.outside / 'missing').exists())

if __name__ == '__main__':
    unittest.main()
