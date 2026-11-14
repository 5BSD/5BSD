#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise real certctl explicit construction against its directory-mode reference."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--selection', type=Path)
parser.add_argument('--certctl', type=Path)
parser.add_argument('--openssl', type=Path)
parser.add_argument('--trusted-directory', type=Path)
parser.add_argument('--untrusted-directory', type=Path)
options, remaining = parser.parse_known_args()
ENV = {'PATH': '/nonexistent', 'LC_ALL': 'C', 'LOCALBASE': '/nonexistent',
       'OPENSSL_CONF': '/dev/null'}
PRODUCED_TREE = PRODUCED_METADATA = ARCHIVE = ARCHIVE_METADATA = PREFIX = TREE_EXECPATH = None
if options.selection:
    import json
    def runfile(value):
        return (Path(os.environ['TEST_SRCDIR']) / value).resolve(strict=True)
    selection_path = options.selection
    if not selection_path.is_absolute():
        selection_path = runfile(str(selection_path))
    selection = json.loads(selection_path.read_text())
    if selection['format'] != 1:
        raise ValueError('format-1 selected certificate inputs required')
    CERTCTL, OPENSSL = [runfile(selection[k]) for k in ['certctl', 'openssl']]
    TRUSTED, UNTRUSTED = [[runfile(p) for p in selection[k]] for k in ['trusted', 'untrusted']]
    runtime = [runfile(p) for p in selection['runtime']]
    ENV['LD_LIBRARY_PATH'] = ':'.join(sorted({str(p.parent) for p in runtime}))
    PRODUCED_TREE, PRODUCED_METADATA = [runfile(selection[k]) for k in ['tree', 'metalog']]
    ARCHIVE, ARCHIVE_METADATA = [runfile(selection[k]) for k in ['archive', 'archive_metadata']]
    PREFIX = selection['prefix']
    TREE_EXECPATH = selection.get('tree_execpath')
else:
    if not all([options.certctl, options.openssl, options.trusted_directory, options.untrusted_directory]):
        parser.error('supply --selection or explicit tools and both corpus directories')
    CERTCTL = options.certctl.resolve(strict=True)
    OPENSSL = options.openssl.resolve(strict=True)
    TRUSTED = sorted(options.trusted_directory.resolve(strict=True).glob('*.pem'))
    UNTRUSTED = sorted(options.untrusted_directory.resolve(strict=True).glob('*.pem'))


def snapshot(root, *, runfiles_tree=None, modes=True):
    result = {}
    for path in sorted(root.rglob('*')):
        relative = str(path.relative_to(root))
        original = path
        if path.is_symlink() and runfiles_tree:
            # Bazel expands directory artifacts into runfiles directories whose
            # leaves alias the declared output files. Follow precisely that alias,
            # then inspect the producer object itself with lstat (not resolve).
            target = Path(os.readlink(path))
            if not target.is_absolute():
                target = path.parent / target
            target = Path(os.path.abspath(target))
            if not str(target).endswith('/' + runfiles_tree + '/' + relative):
                raise ValueError('runfile does not alias its declared tree output: ' + str(original))
            path = target
        info = path.lstat()
        if path.is_symlink():
            value = ('symlink', os.readlink(path))
        elif path.is_file():
            value = ('file', hashlib.sha256(path.read_bytes()).hexdigest())
        elif path.is_dir():
            value = ('dir',)
        else:
            raise ValueError('unexpected certificate-store object')
        result[relative] = (stat.S_IMODE(info.st_mode), *value) if modes else value
    return result


class Store(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def run_store(self, name, trusted=(), untrusted=(), *, explicit=True, env=None, success=True):
        root = self.root / name
        command = [str(CERTCTL), '-U', '-D', str(root), '-M', str(self.root / (name + '.METALOG'))]
        if explicit:
            command += ['-E', '-C', str(root / 'etc/ssl/certs'), '-R', str(root / 'etc/ssl/untrusted'),
                        '-b', str(root / 'etc/ssl/cert.pem')]
            for flag, files in [('-T', trusted), ('-X', untrusted)]:
                for file in files:
                    command += [flag, str(file)]
        result = subprocess.run(command + ['rehash'], env=env or ENV, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return root

    def certificate(self, name, subject):
        cert = self.root / (name + '.pem')
        result = subprocess.run([str(OPENSSL), 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
            'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=' + subject,
            '-keyout', str(self.root / (name + '.key')), '-out', str(cert)], env=ENV, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return cert

    def test_declared_producer_tree_and_metadata(self):
        if PRODUCED_TREE is None:
            self.skipTest('host control run has no Bazel-produced tree')
        import shlex
        expected = self.run_store('expected', TRUSTED, UNTRUSTED)
        # Artifact-cache permissions belong to Bazel. Check file types/bytes
        # here; the declared installation modes are checked in METALOG and tar.
        self.assertEqual(snapshot(PRODUCED_TREE, runfiles_tree=TREE_EXECPATH, modes=False),
                         snapshot(expected / 'etc/ssl', modes=False))
        claims = {}
        for line in PRODUCED_METADATA.read_text().splitlines():
            words = shlex.split(line)
            self.assertTrue(words and words[0].startswith('./'))
            path = words[0][2:]
            self.assertNotIn(path, claims)
            fields = dict(word.split('=', 1) for word in words[1:])
            self.assertEqual(fields['type'], 'file')
            self.assertEqual((fields['uname'], fields['gname']), ('root', 'wheel'))
            file = PRODUCED_TREE / path
            self.assertTrue(file.is_file())
            self.assertEqual(int(fields['size']), file.stat().st_size)
            self.assertEqual(int(fields['mode'], 8), 0o444)
            claims[path] = fields
        self.assertEqual(set(claims), {str(p.relative_to(PRODUCED_TREE)) for p in PRODUCED_TREE.rglob('*') if p.is_file()})

    def test_installation_archive_matches_generated_tree(self):
        if ARCHIVE is None:
            self.skipTest('host control run has no Bazel-produced archive')
        import json
        import tarfile
        from pathlib import PurePosixPath
        metadata = json.loads(ARCHIVE_METADATA.read_text())
        declarations = {row['destination']: row for row in metadata['records']}
        self.assertEqual(len(declarations), len(metadata['records']))
        files = {PREFIX + '/' + str(p.relative_to(PRODUCED_TREE)): p
                 for p in PRODUCED_TREE.rglob('*') if p.is_file()}
        self.assertEqual({p for p, row in declarations.items() if row['type'] == 'file'}, set(files))
        for row in declarations.values():
            self.assertEqual(row['tags'], [])
        seen = set()
        with tarfile.open(ARCHIVE, 'r:') as archive:
            for entry in archive:
                path = '/' + entry.name if entry.name != '.' else '/'
                self.assertNotIn(path, seen)
                seen.add(path)
                self.assertEqual((entry.uname, entry.gname, entry.uid, entry.gid), ('root', 'wheel', 0, 0))
                self.assertEqual(entry.mtime, 0)
                if entry.isfile():
                    self.assertIn(path, files)
                    self.assertEqual(entry.mode, 0o444)
                    self.assertEqual(archive.extractfile(entry).read(), files[path].read_bytes())
                else:
                    self.assertTrue(entry.isdir())
                    self.assertEqual(entry.mode, 0o755)
                    self.assertTrue(path in declarations or PurePosixPath(path) in PurePosixPath(PREFIX).parents)
        self.assertTrue(set(declarations) <= seen)
        self.assertEqual({p for p in seen if p in files}, set(files))

    def test_complete_package_corpus_matches_directory_mode(self):
        self.assertTrue(TRUSTED, 'nonempty selected package corpus required')
        root = self.root / 'reference'
        for category, files in [('trusted', TRUSTED), ('untrusted', UNTRUSTED)]:
            directory = root / 'usr/share/certs' / category
            directory.mkdir(parents=True)
            # Different manifests may provide equal source basenames. Preserve
            # every selected input in the directory-mode control as well.
            for index, file in enumerate(files):
                shutil.copyfile(file, directory / (str(index) + '-' + file.name))
        self.run_store('reference', explicit=False)
        explicit = self.run_store('explicit', TRUSTED, UNTRUSTED)
        self.assertEqual(snapshot(root / 'etc/ssl'), snapshot(explicit / 'etc/ssl'))
        self.assertEqual((self.root / 'reference.METALOG').read_bytes(),
                         (self.root / 'explicit.METALOG').read_bytes())

    def test_order_and_repeated_construction_are_deterministic(self):
        one = self.run_store('one', TRUSTED, UNTRUSTED)
        two = self.run_store('two', list(reversed(TRUSTED)), list(reversed(UNTRUSTED)))
        self.assertEqual(snapshot(one), snapshot(two))
        self.assertEqual((self.root / 'one.METALOG').read_bytes(), (self.root / 'two.METALOG').read_bytes())
        before = snapshot(one)
        self.run_store('one', TRUSTED, UNTRUSTED)
        self.assertEqual(before, snapshot(one))

    def test_untrusted_overrides_trusted(self):
        cert = self.certificate('root', 'Explicit trust precedence')
        root = self.run_store('store', [cert], [cert])
        self.assertEqual(list((root / 'etc/ssl/certs').iterdir()), [])
        self.assertEqual(len(list((root / 'etc/ssl/untrusted').iterdir())), 1)
        self.assertEqual((root / 'etc/ssl/cert.pem').read_bytes(), b'')

    def test_hash_collisions_additions_and_removal(self):
        a = self.certificate('a', 'Deliberate subject collision')
        b = self.certificate('b', 'Deliberate subject collision')
        hashes = [subprocess.check_output([str(OPENSSL), 'x509', '-in', str(p), '-hash', '-noout'], env=ENV) for p in [a, b]]
        self.assertEqual(*hashes)
        root = self.run_store('store', [a])
        self.assertEqual(len(list((root / 'etc/ssl/certs').iterdir())), 1)
        self.run_store('store', [a, b])
        self.assertEqual(len(list((root / 'etc/ssl/certs').iterdir())), 2)
        other = self.run_store('reverse', [b, a])
        self.assertEqual(snapshot(root), snapshot(other))
        self.run_store('store', [b])
        self.assertEqual(len(list((root / 'etc/ssl/certs').iterdir())), 1)

    def test_explicit_selection_ignores_ambient_trust_and_verifies(self):
        a = self.certificate('allowed', 'Allowed root')
        b = self.certificate('ambient', 'Ambient root')
        poisoned = dict(ENV, TRUSTPATH=str(b), UNTRUSTPATH=str(a), BUNDLE=str(self.root / 'forbidden'))
        root = self.run_store('store', [a], env=poisoned)
        bundle = root / 'etc/ssl/cert.pem'
        for cert, expected in [(a, True), (b, False)]:
            result = subprocess.run([str(OPENSSL), 'verify', '-no-CApath', '-no-CAstore', '-CAfile', str(bundle), str(cert)], env=ENV, capture_output=True)
            self.assertEqual(result.returncode == 0, expected, result.stderr)
        self.assertFalse((self.root / 'forbidden').exists())

    def test_empty_selection_does_not_import_host_trust(self):
        cert = self.certificate('ambient', 'Must not become implicitly trusted')
        poisoned = dict(ENV, TRUSTPATH=str(cert), UNTRUSTPATH=str(cert))
        root = self.run_store('empty', env=poisoned)
        self.assertEqual(list((root / 'etc/ssl/certs').iterdir()), [])
        self.assertEqual(list((root / 'etc/ssl/untrusted').iterdir()), [])
        self.assertEqual((root / 'etc/ssl/cert.pem').read_bytes(), b'')

    def test_nonregular_inputs_are_refused_before_mutation(self):
        cert = self.certificate('valid', 'Valid root')
        root = self.run_store('store', [cert])
        before = snapshot(root)
        metadata = (self.root / 'store.METALOG').read_bytes()
        directory = self.root / 'directory'
        directory.mkdir()
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        for bad in [directory, fifo]:
            with self.subTest(input=bad.name):
                self.run_store('store', [cert, bad], success=False)
                self.assertEqual(snapshot(root), before)
                self.assertEqual((self.root / 'store.METALOG').read_bytes(), metadata)

    def test_malformed_input_preserves_prior_outputs(self):
        cert = self.certificate('valid', 'Valid root')
        root = self.run_store('store', [cert])
        before = snapshot(root)
        metadata = (self.root / 'store.METALOG').read_bytes()
        bad = self.root / 'bad.pem'
        bad.write_text('not a certificate\n')
        self.run_store('store', [cert, bad], success=False)
        self.assertEqual(snapshot(root), before)
        self.assertEqual((self.root / 'store.METALOG').read_bytes(), metadata)


if __name__ == '__main__':
    unittest.main(argv=[__file__, *remaining])
