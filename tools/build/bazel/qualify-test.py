#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Input-boundary tests; real compiler/Make behavior is covered by qualify.py."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('qualify', Path(__file__).with_name('qualify.py'))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
t = q.bsd_toolchain


def fake_bazel(directory, output):
    path = Path(directory) / 'bazel'
    path.write_text("#!/bin/sh\nprintf '%%s\\n' %s\n" % output)
    path.chmod(0o755)
    return path


def offline_inputs(root):
    """A minimal valid repository cache and distdir under `root`."""
    blob = b'module archive\n'
    digest = hashlib.sha256(blob).hexdigest()
    entry = root / 'cache/content_addressable/sha256' / digest
    entry.mkdir(parents=True)
    (entry / 'file').write_bytes(blob)
    (entry / ('id-' + '0' * 64)).write_bytes(b'')
    distdir = root / 'distdir'
    distdir.mkdir()
    (distdir / 'a.tar.gz').write_bytes(b'archive\n')
    inputs = root / 'inputs.json'
    inputs.write_text(json.dumps({'repository_cache': str(root / 'cache'),
                                  'distdirs': [str(distdir)]}))
    return inputs, entry

class Inputs(unittest.TestCase):
    def test_path_boundaries(self):
        for value in ('relative', '/tmp/a\nb', '/tmp/a$b'):
            with self.assertRaises(ValueError):
                q.safe_path(Path(value), exists=False)
        for value in ('/tmp/out', '/usr/obj', '/usr/obj/../../tmp/out'):
            with self.assertRaises(ValueError):
                q.safe_path(Path(value), exists=False, object_path=True)

    def test_symlink_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / 'link'
            link.symlink_to('/tmp')
            with self.assertRaises(ValueError):
                q.safe_path(link / 'output', exists=False, object_path=True)

    def test_make_identity(self):
        objtop = Path('/usr/obj/usr/src/amd64.amd64')
        valid = f'Entering world for amd64:amd64\n{objtop}\namd64\namd64\n'
        q.parse_identity(valid, objtop)
        for text in (valid.replace(str(objtop), '/usr/obj/other'),
                     valid.replace('amd64', 'aarch64'), valid + 'noise\n'):
            with self.assertRaises(ValueError):
                q.parse_identity(text, objtop)

    def test_resource_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            resource = root / 'usr/lib/clang/21'
            (resource / 'include').mkdir(parents=True)
            (resource / 'include/builtin.h').write_text('/* fixture */\n')
            self.assertEqual(q.toolchain_identity('x86_64-unknown-freebsd16.0\n', str(resource), root),
                             ('x86_64-unknown-freebsd16.0', '21'))
            for target in ('aarch64-unknown-freebsd16.0', 'x86_64-linux-gnu', 'x86_64-unknown-freebsd16.0\nnoise'):
                with self.assertRaises(ValueError):
                    q.toolchain_identity(target, str(resource), root)
            with self.assertRaises(ValueError):
                q.toolchain_identity('x86_64-unknown-freebsd16.0', str(root), root)
            (resource / 'include/builtin.h').unlink()
            with self.assertRaises(ValueError):
                q.toolchain_identity('x86_64-unknown-freebsd16.0', str(resource), root)

class BazelContract(unittest.TestCase):
    def test_version_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(t.check_bazel_version(fake_bazel(directory, "'bazel 9.3.1'")), '9.3.1')
            self.assertEqual(t.check_bazel_version(fake_bazel(directory, "'bazel 10.0.0rc1'")), '10.0.0rc1')
            for output in ("'bazel 5.4.1'", "'bazel 8.8.0'", "'bazel no_version'", "''"):
                with self.assertRaises(SystemExit) as caught:
                    t.check_bazel_version(fake_bazel(directory, output))
                self.assertIn('Bazel', str(caught.exception))
            with self.assertRaises(SystemExit):
                t.check_bazel_version(Path(directory) / 'missing')

    def test_default_executable(self):
        self.assertEqual(t.DEFAULT_BAZEL, Path('/usr/local/bin/bazel'))
        self.assertTrue(t.PINNED_LOCKFILE.is_file())

    def test_offline_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs, entry = offline_inputs(root)
            loaded = t.load_bzlmod_inputs(inputs)
            self.assertEqual(loaded['modules'], t.PINNED_MODULES)
            self.assertEqual(loaded['lockfile'], str(t.PINNED_LOCKFILE))
            self.assertIsNone(loaded['java_home'])
            self.assertEqual((loaded['repository_cache_entries'], loaded['distdir_files']), (1, 1))
            loaded['staged_repository_cache'] = str(root / 'staged')
            flags = t.build_flags(4, loaded)
            for flag in ('--lockfile_mode=error', '--repository_disable_download',
                         '--repository_cache=' + str(root / 'staged'),
                         '--distdir=' + str(root / 'distdir'), '--platforms=//toolchain:native'):
                self.assertIn(flag, flags)
            self.assertFalse(any('crosstool' in x or x.startswith('--cpu') for x in flags))
            data = json.loads(inputs.read_text())
            for change in ({'modules': {'rules_cc': '0.0.1', 'platforms': '1.0.0'}},
                           {'lockfile': str(inputs)}, {'distdirs': [str(root / 'absent')]}):
                (root / 'bad.json').write_text(json.dumps(dict(data, **change)))
                with self.assertRaises((ValueError, OSError)):
                    t.load_bzlmod_inputs(root / 'bad.json')
            (root / 'bad.json').write_text(json.dumps({'distdirs': data['distdirs']}))
            with self.assertRaises(ValueError):
                t.load_bzlmod_inputs(root / 'bad.json')
            (entry / 'file').write_bytes(b'tampered\n')
            with self.assertRaises(ValueError):
                t.load_bzlmod_inputs(inputs)

    def test_stage_cache_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs, entry = offline_inputs(root)
            loaded = t.load_bzlmod_inputs(inputs)
            staged = t.stage_repository_cache(loaded, root / 'run/repository-cache')
            copied = staged / entry.relative_to(root / 'cache') / 'file'
            self.assertEqual(copied.read_bytes(), (entry / 'file').read_bytes())
            self.assertNotEqual(os.stat(copied).st_ino, os.stat(entry / 'file').st_ino)


if __name__ == '__main__':
    unittest.main()
