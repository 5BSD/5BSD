#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Validate selected compiler identity through the aliases used by Make."""
from pathlib import Path
import tempfile
import unittest

from libmd_environment import same_executable, world_compiler_identity, compiler_metadata, system_compiler_version, bind_inputs


class CompilerIdentityTests(unittest.TestCase):
    def test_symlink_and_hardlink_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler = root / 'clang'
            compiler.write_bytes(b'compiler')
            symlink = root / 'clang-symlink'
            symlink.symlink_to(compiler.name)
            hardlink = root / 'cc'
            hardlink.hardlink_to(compiler)
            other = root / 'other'
            other.write_bytes(b'other executable')

            self.assertTrue(same_executable(symlink, compiler))
            self.assertTrue(same_executable(hardlink, compiler))
            self.assertFalse(same_executable(other, compiler))
            self.assertFalse(same_executable(root / 'missing', compiler))


    def fixture(self, root):
        staged = root/'world/tmp/usr/bin/clang'
        staged.parent.mkdir(parents=True)
        staged.write_bytes(b'staged')
        resource = root/'world/tmp/usr/lib/clang/21'
        (resource/'include').mkdir(parents=True)
        system = root/'system/bin/clang'
        system.parent.mkdir(parents=True)
        system.write_bytes(b'system')
        external = root/'system/lib/clang/21'
        (external/'include').mkdir(parents=True)
        return staged, resource, system, external

    def test_staged_mode_requires_its_own_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            staged, resource, system, external = self.fixture(Path(directory))
            self.assertEqual(world_compiler_identity(staged, staged, 'no', resource, {}), ('staged', staged))
            with self.assertRaisesRegex(ValueError, 'resource directory escapes'):
                world_compiler_identity(staged, staged, 'yes', external, {})

    def test_system_mode_is_explicit_and_resolves_make_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged, resource, system, external = self.fixture(root)
            alias = root/'make-cc'
            alias.symlink_to(system)
            metadata = {'X_COMPILER_TYPE':'clang', 'X_COMPILER_RESOURCE_DIR':str(external)}
            self.assertEqual(world_compiler_identity(alias, staged, 'yes', external, metadata), ('system', system))
            for mode in ['no', '', 'auto']:
                with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'requires Make SYSTEM_COMPILER'):
                    world_compiler_identity(alias, staged, mode, external, metadata)

    def test_system_metadata_and_clang_identity_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged, resource, system, external = self.fixture(root)
            good = {'X_COMPILER_TYPE':'clang', 'X_COMPILER_RESOURCE_DIR':str(external)}
            for metadata in [{}, dict(good, X_COMPILER_TYPE='gcc'), dict(good, X_COMPILER_RESOURCE_DIR=str(resource))]:
                with self.subTest(metadata=metadata), self.assertRaisesRegex(ValueError, 'recorded world toolchain'):
                    world_compiler_identity(system, staged, 'yes', external, metadata)
            impostor = system.parent/'other'
            impostor.write_bytes(b'different compiler')
            with self.assertRaisesRegex(ValueError, 'declared Clang executable'):
                world_compiler_identity(impostor, staged, 'yes', external, good)

    def test_resources_and_metadata_must_be_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged, resource, system, external = self.fixture(root)
            with self.assertRaisesRegex(ValueError, 'builtin headers'):
                world_compiler_identity(system, staged, 'yes', root/'missing', {})
            metadata = root/'toolchain-metadata.mk'
            metadata.write_text('.info cached\nX_COMPILER_TYPE=clang\n.export X_COMPILER_TYPE\n')
            self.assertEqual(compiler_metadata(metadata), {'X_COMPILER_TYPE':'clang'})
            metadata.write_text('X_COMPILER_TYPE=clang\nX_COMPILER_TYPE=gcc\n')
            with self.assertRaisesRegex(ValueError, 'duplicate recorded'):
                compiler_metadata(metadata)


    def test_system_version_must_match_cached_world(self):
        macros={'__clang_major__':'21','__clang_minor__':'1','__clang_patchlevel__':'8','__FreeBSD_cc_version':'1600002'}
        metadata={'X_COMPILER_VERSION':'210108','X_COMPILER_FREEBSD_VERSION':'1600002'}
        self.assertEqual(system_compiler_version(macros, metadata), {'clang':210108,'freebsd':'1600002'})
        for changed in [dict(macros, __clang_patchlevel__='9'), dict(macros, __FreeBSD_cc_version='1600003'), {}]:
            with self.subTest(macros=changed), self.assertRaises(ValueError):
                system_compiler_version(changed, metadata)


    def test_world_capture_never_rolls_forward_an_input_hash(self):
        inputs={'/source/Makefile':'old'}
        bind_inputs(inputs, {'/source/Makefile':'old'})
        with self.assertRaisesRegex(ValueError, 'world input changed during export'):
            bind_inputs(inputs, {'/source/new':'new', '/source/Makefile':'changed'})
        self.assertEqual(inputs, {'/source/Makefile':'old'})


if __name__ == '__main__':
    unittest.main()
