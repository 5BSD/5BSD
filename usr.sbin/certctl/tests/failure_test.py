# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the real certificate tool, crypto parser, filesystem and write errors."""
import os
from pathlib import Path
import resource
import signal
import subprocess
import tempfile
import unittest

TOOL = os.environ.get('CERTCTL_TEST_TOOL', '/usr/sbin/certctl')
OPENSSL = os.environ.get('CERTCTL_TEST_OPENSSL', '/usr/bin/openssl')


class CertificateFailures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto = tempfile.TemporaryDirectory(prefix='certctl-crypto-')
        cls.addClassCleanup(cls.crypto.cleanup)
        directory = Path(cls.crypto.name)
        environment = dict(os.environ, OPENSSL_CONF='/dev/null')
        for serial in (1, 2):
            command = [OPENSSL, 'req', '-x509', '-new', '-subj', '/CN=Certificate construction fixture',
                       '-set_serial', str(serial), '-days', '2', '-out', str(directory / f'{serial}.pem')]
            if serial == 1:
                command += ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-noenc',
                            '-keyout', str(directory / 'key.pem')]
            else:
                command += ['-key', str(directory / 'key.pem')]
            subprocess.run(command, env=environment, check=True, capture_output=True)
        cls.a = (directory / '1.pem').read_bytes()
        cls.b = (directory / '2.pem').read_bytes()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certctl-case-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.trusted = self.root / 'inputs/trusted'
        self.denied = self.root / 'inputs/denied'
        self.trusted.mkdir(parents=True); self.denied.mkdir()
        (self.trusted / 'a.pem').write_bytes(self.a)
        self.store = self.root / 'store'
        self.environment = dict(os.environ, DESTDIR=str(self.root), DISTBASE='', LOCALBASE='/usr/local',
            TRUSTPATH=str(self.trusted), UNTRUSTPATH=str(self.denied),
            TRUSTDESTDIR=str(self.store / 'certs'), UNTRUSTDESTDIR=str(self.store / 'untrusted'),
            BUNDLE=str(self.store / 'cert.pem'))

    def run_tool(self, *args, limit=None):
        def constrain():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        return subprocess.run([TOOL, *args], env=self.environment, cwd=self.root,
            capture_output=True, timeout=15, preexec_fn=constrain if limit is not None else None)

    def snapshot(self):
        return {str(p.relative_to(self.store)): (p.read_bytes(), p.stat().st_mode & 0o7777)
                for p in self.store.rglob('*') if p.is_file()}

    def baseline(self):
        result = self.run_tool('rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.snapshot()

    def input_failure(self, before, *args):
        result = self.run_tool(*(args or ('rehash',)))
        self.assertNotEqual(result.returncode, 0, 'invalid input reported success')
        self.assertEqual(self.snapshot(), before, 'input failure changed installed store')

    def test_collision_exclusion_and_bundle(self):
        (self.trusted / 'b.pem').write_bytes(self.b)
        self.baseline()
        certificates = sorted((self.store / 'certs').iterdir())
        self.assertEqual(len(certificates), 2)
        self.assertEqual({p.name.split('.')[1] for p in certificates}, {'0', '1'})
        self.assertEqual({p.read_bytes() for p in certificates}, {self.a, self.b})
        (self.denied / 'a.pem').write_bytes(self.a)
        result = self.run_tool('rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([p.read_bytes() for p in (self.store / 'certs').iterdir()], [self.b])
        self.assertEqual([p.read_bytes() for p in (self.store / 'untrusted').iterdir()], [self.a])
        self.assertEqual((self.store / 'cert.pem').read_bytes(), self.b)

    def test_missing_explicit_exclusions(self):
        before = self.baseline()
        self.environment['UNTRUSTPATH'] = str(self.root / 'missing-exclusions')
        self.input_failure(before)

    def test_invalid_exclusion(self):
        before = self.baseline()
        (self.denied / 'bad.pem').write_bytes(b'not a certificate\n')
        self.input_failure(before)

    def test_partial_malformed_bundle(self):
        before = self.baseline()
        (self.denied / 'partial.pem').write_bytes(self.a + b'-----BEGIN CERTIFICATE-----\ninvalid\n')
        self.input_failure(before)

    def test_unreadable_exclusion(self):
        self.assertNotEqual(os.geteuid(), 0, 'run permission tests as an unprivileged account')
        before = self.baseline()
        path = self.denied / 'unreadable.pem'; path.write_bytes(self.a); path.chmod(0)
        try:
            self.input_failure(before)
        finally:
            path.chmod(0o600)

    def test_unreadable_source_directory(self):
        self.assertNotEqual(os.geteuid(), 0, 'run permission tests as an unprivileged account')
        before = self.baseline()
        self.denied.chmod(0)
        try:
            self.input_failure(before)
        finally:
            self.denied.chmod(0o700)

    def test_source_cycle(self):
        before = self.baseline()
        (self.denied / 'cycle').symlink_to(self.denied)
        self.input_failure(before)

    def test_mixed_explicit_untrust_arguments(self):
        before = self.baseline()
        bad = self.root / 'bad.pem'; bad.write_text('invalid')
        self.input_failure(before, 'untrust', str(self.trusted / 'a.pem'), str(bad))

    def test_buffered_write_failure_preserves_existing_files(self):
        before = self.baseline()
        result = self.run_tool('rehash', limit=0)
        self.assertNotEqual(result.returncode, 0, 'buffered output failure reported success')
        self.assertEqual(self.snapshot(), before, 'failed write replaced a usable certificate')
        self.assertFalse(any(p.name.startswith('.') for p in self.store.rglob('*')))

    def test_bundle_write_failure_preserves_existing_bundle(self):
        (self.trusted / 'b.pem').write_bytes(self.b)
        before = self.baseline()
        result = self.run_tool('rehash', limit=max(len(self.a), len(self.b)))
        self.assertNotEqual(result.returncode, 0, 'bundle write failure reported success')
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(any(p.name.startswith('.') for p in self.store.rglob('*')))

    def test_stale_output_removal_failure_is_reported(self):
        self.assertNotEqual(os.geteuid(), 0, 'run permission tests as an unprivileged account')
        self.baseline()
        (self.trusted / 'a.pem').unlink()
        stale = self.store / 'certs/stale'; stale.write_text('stale')
        stale.parent.chmod(0o555)
        try:
            result = self.run_tool('rehash')
            self.assertNotEqual(result.returncode, 0, 'failed removal reported success')
        finally:
            stale.parent.chmod(0o755)

    def test_broken_source_symlink(self):
        before = self.baseline()
        (self.denied / 'broken').symlink_to(self.root / 'missing')
        self.input_failure(before)

    def test_special_source_file(self):
        before = self.baseline()
        os.mkfifo(self.denied / 'pipe')
        self.input_failure(before)

    def test_explicit_special_file(self):
        before = self.baseline()
        pipe = self.root / 'pipe'
        os.mkfifo(pipe)
        self.input_failure(before, 'untrust', str(pipe))

    def test_empty_path_component(self):
        before = self.baseline()
        self.environment['UNTRUSTPATH'] += ':'
        self.input_failure(before)

    def test_optional_default_directories_absent(self):
        del self.environment['TRUSTPATH']
        del self.environment['UNTRUSTPATH']
        result = self.run_tool('rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.store / 'cert.pem').read_bytes(), b'')

    def test_malformed_installed_store_listing(self):
        self.baseline()
        (self.store / 'certs/bad.pem').write_text('invalid')
        result = self.run_tool('list')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_metalog_flush_failure_is_reported(self):
        self.baseline()
        metalog = self.root / 'METALOG'; metalog.write_bytes(b'#' * 4096)
        result = self.run_tool('-U', '-M', str(metalog), 'rehash', limit=4096)
        self.assertNotEqual(result.returncode, 0, 'failed metadata receipt reported success')

    def test_dry_run_creates_no_store_directories(self):
        result = self.run_tool('-n', 'rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.store.exists(), 'dry run created output directories')

    def test_bundle_basename(self):
        self.environment['BUNDLE'] = 'bundle.pem'
        result = self.run_tool('rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'bundle.pem').read_bytes(), self.a)

    def test_explicit_empty_sources(self):
        self.environment['TRUSTPATH'] = ''
        self.environment['UNTRUSTPATH'] = ''
        result = self.run_tool('rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.store / 'cert.pem').read_bytes(), b'')

    def test_file_selection_ignores_ambient_directories(self):
        # Neither environment search lists nor the legacy directory may alter
        # a generation's explicit certificate selection.
        legacy = self.root / 'etc/ssl/blacklisted'
        legacy.mkdir(parents=True)
        (legacy / 'a.pem').write_bytes(self.a)
        (self.trusted / 'unexpected.pem').write_text('malformed ambient input')
        excluded = self.root / 'excluded.pem'
        excluded.write_bytes(self.b)
        self.environment['TRUSTPATH'] = str(self.root / 'absent-trusted')
        self.environment['UNTRUSTPATH'] = str(self.root / 'absent-untrusted')
        result = self.run_tool('-E', '-T', str(self.trusted / 'a.pem'),
                               '-X', str(excluded), 'rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.store / 'cert.pem').read_bytes(), self.a)
        self.assertEqual([p.read_bytes() for p in (self.store / 'untrusted').iterdir()], [self.b])

    def test_file_selection_can_be_empty(self):
        legacy = self.root / 'etc/ssl/blacklisted'
        legacy.mkdir(parents=True)
        (legacy / 'bad.pem').write_text('malformed ambient input')
        result = self.run_tool('-E', 'rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.store / 'cert.pem').read_bytes(), b'')
        self.assertEqual(list((self.store / 'certs').iterdir()), [])
        self.assertEqual(list((self.store / 'untrusted').iterdir()), [])

    def test_file_selection_exclusion_and_duplicates(self):
        path = str(self.trusted / 'a.pem')
        result = self.run_tool('-E', '-T', path, '-T', path, '-X', path, 'rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.store / 'cert.pem').read_bytes(), b'')
        self.assertEqual([p.read_bytes() for p in (self.store / 'untrusted').iterdir()], [self.a])

    def test_file_selection_requires_explicit_mode(self):
        before = self.baseline()
        self.input_failure(before, '-T', str(self.trusted / 'a.pem'), 'rehash')
        self.input_failure(before, '-X', str(self.trusted / 'a.pem'), 'rehash')
        self.input_failure(before, '-E', 'list')
        self.input_failure(before, '-E', '-T', '', 'rehash')

    def test_file_selection_rejects_directories(self):
        before = self.baseline()
        self.input_failure(before, '-E', '-T', str(self.trusted), 'rehash')

    def test_file_selection_rejects_missing_and_malformed_inputs(self):
        before = self.baseline()
        bad = self.root / 'bad.pem'
        for contents in (None, b'not a certificate', self.a + b'-----BEGIN CERTIFICATE-----\ninvalid\n'):
            with self.subTest(contents=contents):
                if contents is not None:
                    bad.write_bytes(contents)
                self.input_failure(before, '-E', '-T', str(self.trusted / 'a.pem'),
                                   '-X', str(bad), 'rehash')

    def test_explicit_output_paths_and_stdout_plan(self):
        trusted = self.root / 'chosen/trusted'
        denied = self.root / 'chosen/denied'
        bundle = self.root / 'chosen/bundle.pem'
        args = ['-E', '-T', str(self.trusted / 'a.pem'), '-C', str(trusted),
                '-R', str(denied), '-b', str(bundle)]
        planned = self.run_tool(*args, '-n', '-U', '-M', '-', 'rehash')
        self.assertEqual(planned.returncode, 0, planned.stderr)
        self.assertIn(b'./chosen/bundle.pem type=file', planned.stdout)
        self.assertFalse((self.root / 'chosen').exists())
        self.assertFalse((self.root / '-').exists())
        actual = self.run_tool(*args, '-U', '-M', '-', 'rehash')
        self.assertEqual(actual.returncode, 0, actual.stderr)
        self.assertEqual(actual.stdout, planned.stdout)
        self.assertEqual(bundle.read_bytes(), self.a)
        self.assertFalse(self.store.exists(), 'environment output settings overrode CLI')

    def test_explicit_output_options_require_mode_and_nonempty_paths(self):
        before = self.baseline()
        for option in ('-C', '-R', '-b'):
            with self.subTest(option=option):
                self.input_failure(before, option, str(self.root / 'output'), 'rehash')
                self.input_failure(before, '-E', option, '', 'rehash')

    def test_dry_run_metadata_matches_written_files(self):
        (self.trusted / 'b.pem').write_bytes(self.b)
        planned = self.root / 'planned.mtree'
        actual = self.root / 'actual.mtree'
        args = ['-E', '-T', str(self.trusted / 'a.pem'), '-T', str(self.trusted / 'b.pem')]
        result = self.run_tool(*args, '-n', '-U', '-M', str(planned), 'rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.store.exists(), 'planning changed the destination tree')
        result = self.run_tool(*args, '-U', '-M', str(actual), 'rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(planned.read_bytes(), actual.read_bytes())
        lines = planned.read_text().splitlines()
        self.assertEqual(len(lines), 3, 'expected two hash-colliding certificates and their bundle')
        for line in lines:
            path, *fields = line.split()
            attributes = dict(field.split('=', 1) for field in fields)
            output = self.root / path.removeprefix('./')
            self.assertEqual(int(attributes['size']), output.stat().st_size)
            self.assertEqual(int(attributes['mode'], 8), output.stat().st_mode & 0o7777)
        before = self.snapshot()
        result = self.run_tool(*args, '-n', 'rehash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before, 'planning changed an existing store')


if __name__ == '__main__':
    unittest.main()
