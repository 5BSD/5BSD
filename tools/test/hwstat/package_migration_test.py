#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the migration with real pkg transactions in disposable fixtures."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[3]
MIGRATOR = SOURCE / 'tools/build/migrate-hwstat-packages.sh'


class Migration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hwstat-migration-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('db', 'cache', 'conf', 'repo', 'old', 'files'):
            (self.root / name).mkdir()
        self.pkg = [shutil.which('pkg'), '-o', f'PKG_DBDIR={self.root}/db',
                    '-o', f'PKG_CACHEDIR={self.root}/cache', '-o',
                    f'REPOS_DIR={self.root}/conf', '-o', 'INSTALL_AS_USER=yes',
                    '-o', 'SYSLOG=no', '-o', 'PKG_ENABLE_PLUGINS=no']
        self.abi = self.run_pkg('config', 'ABI').stdout.strip()
        wrapper = self.root / 'pkg-wrapper'
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.join(self.pkg) + ' "$@"\n')
        wrapper.chmod(0o700)
        self.env = dict(os.environ, PKG=str(wrapper), PKG_REPOSITORY='fixture',
                        PKG_NAME_PREFIX='hwstat-review')
        (self.root / 'conf/fixture.conf').write_text(
            'fixture: {url:"file://' + str(self.root / 'repo') +
            '", signature_type:"none", enabled:yes}\n')

    def run_pkg(self, *args):
        result = subprocess.run(self.pkg + list(args), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 0, result.stdout)
        return result

    def create(self, name, version, folder, deps=None):
        payload = self.root / 'files' / name
        payload.write_text(name + '\n')
        manifest = dict(name='hwstat-review-' + name, version=str(version),
                        origin='base/hwstat-review-' + name,
                        comment='migration fixture', desc='migration fixture',
                        maintainer='test@example.invalid', www='https://example.invalid',
                        prefix=str(self.root / 'files'), abi=self.abi,
                        files={str(payload): '-'})
        if deps:
            manifest['deps'] = {d: {'origin': 'base/' + d, 'version': str(version)}
                                for d in deps}
        path = self.root / (name + '.json')
        path.write_text(json.dumps(manifest))
        self.run_pkg('create', '-M', str(path), '-o', str(self.root / folder))
        payload.unlink()
        return self.root / folder / (manifest['name'] + '-' + str(version) + '.pkg')

    def prepare(self, missing=None, target_versions=None):
        target_versions = target_versions or {}
        for suffix in ('', '-man', '-dbg', '-tests'):
            deps = ['hwstat-review-hwtlm'] if suffix == '-tests' else None
            old = self.create('hwtlm' + suffix, 1, 'old', deps)
            self.run_pkg('add', '-I', str(old))
            if suffix != missing:
                deps = ['hwstat-review-hwstat'] if suffix == '-tests' else None
                self.create('hwstat' + suffix, target_versions.get(suffix, 2), 'repo', deps)
        self.run_pkg('repo', str(self.root / 'repo'))
        self.run_pkg('update', '-f')

    def migrate(self, expected=0):
        result = subprocess.run(['sh', str(MIGRATOR)], env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, expected, result.stdout)
        return result.stdout

    def test_upgrade_and_repeat(self):
        self.prepare()
        self.migrate()
        self.migrate()  # can resume between rename and upgrade
        self.run_pkg('upgrade', '-y')
        installed = self.run_pkg('query', '%n %o %v').stdout
        self.assertNotIn('hwtlm', installed)
        for suffix in ('', '-man', '-dbg', '-tests'):
            name = 'hwstat-review-hwstat' + suffix
            self.assertIn(f'{name} base/{name} 2', installed)
            self.assertFalse((self.root / 'files' / ('hwtlm' + suffix)).exists())
            payload = self.root / 'files' / ('hwstat' + suffix)
            self.assertEqual(payload.read_text(), 'hwstat' + suffix + '\n')
            self.assertFalse(payload.is_symlink())
        deps = self.run_pkg('query', '%dn', 'hwstat-review-hwstat-tests').stdout
        self.assertEqual(deps.strip(), 'hwstat-review-hwstat')
        self.run_pkg('check', '-da')
        self.migrate()

    def assert_version_rejected_without_changes(self, versions):
        self.prepare(target_versions=versions)
        before = self.run_pkg('query', '%n %o %v').stdout
        files = {p.name: p.read_bytes() for p in (self.root / 'files').iterdir()}
        self.assertIn('newer', self.migrate(expected=1))
        self.assertEqual(before, self.run_pkg('query', '%n %o %v').stdout)
        self.assertEqual(files, {p.name: p.read_bytes()
                                for p in (self.root / 'files').iterdir()})

    def test_equal_version(self):
        self.assert_version_rejected_without_changes(
            {suffix: 1 for suffix in ('', '-man', '-dbg', '-tests')})

    def test_older_version(self):
        self.assert_version_rejected_without_changes(
            {suffix: 0 for suffix in ('', '-man', '-dbg', '-tests')})

    def test_one_equal_version_stops_entire_migration(self):
        self.assert_version_rejected_without_changes({'-tests': 1})

    def test_previously_renamed_equal_version_is_rejected(self):
        self.prepare(target_versions={'': 1})
        self.run_pkg('set', '-a', '-y', '-n',
                     'hwstat-review-hwtlm:hwstat-review-hwstat')
        before = self.run_pkg('query', '%n %o %v').stdout
        self.assertIn('newer', self.migrate(expected=1))
        self.assertEqual(before, self.run_pkg('query', '%n %o %v').stdout)

    def test_interrupted_rename_can_resume(self):
        self.prepare()
        marker = self.root / 'interrupted'
        wrapper = self.root / 'interrupt-pkg'
        wrapper.write_text(
            '#!/bin/sh\n'
            'if [ "$1" = set ] && [ "$5" = '
            'hwstat-review-hwtlm-man:hwstat-review-hwstat-man ] && '
            '[ ! -e ' + shlex.quote(str(marker)) + ' ]; then\n'
            '  touch ' + shlex.quote(str(marker)) + '\n  exit 75\nfi\n'
            'exec ' + shlex.join(self.pkg) + ' "$@"\n')
        wrapper.chmod(0o700)
        self.env['PKG'] = str(wrapper)
        self.migrate(expected=75)
        installed = self.run_pkg('query', '%n %o').stdout
        self.assertIn('hwstat-review-hwstat base/hwstat-review-hwtlm', installed)
        self.assertIn('hwstat-review-hwtlm-man', installed)
        self.assertTrue((self.root / 'files/hwtlm').is_file())
        self.migrate()
        self.run_pkg('upgrade', '-y')
        self.assertNotIn('hwtlm', self.run_pkg('query', '%n %o').stdout)
        self.assertFalse(list((self.root / 'files').glob('hwtlm*')))
        self.run_pkg('check', '-da')

    def test_both_names_are_rejected_without_changes(self):
        self.prepare()
        self.run_pkg('add', '-I', str(self.root / 'repo/hwstat-review-hwstat-2.pkg'))
        before = self.run_pkg('query', '%n %o %v').stdout
        self.assertIn('Both', self.migrate(expected=1))
        self.assertEqual(before, self.run_pkg('query', '%n %o %v').stdout)

    def test_runtime_only_installation(self):
        self.prepare()
        self.run_pkg('delete', '-y', 'hwstat-review-hwtlm-tests',
                     'hwstat-review-hwtlm-dbg', 'hwstat-review-hwtlm-man')
        self.migrate()
        self.run_pkg('upgrade', '-y')
        self.assertEqual(self.run_pkg('query', '%n').stdout.strip(),
                         'hwstat-review-hwstat')
        self.assertFalse((self.root / 'files/hwtlm').exists())
        self.assertTrue((self.root / 'files/hwstat').is_file())

    def test_missing_target_does_not_rename_any_package(self):
        self.prepare(missing='-tests')
        before = self.run_pkg('query', '%n %o %v').stdout
        self.assertIn('missing', self.migrate(expected=1))
        self.assertEqual(before, self.run_pkg('query', '%n %o %v').stdout)

    def test_locked_package_does_not_rename_any_package(self):
        self.prepare()
        self.run_pkg('lock', '-y', 'hwstat-review-hwtlm-tests')
        before = self.run_pkg('query', '%n %o %v').stdout
        self.assertIn('locked', self.migrate(expected=1))
        self.assertEqual(before, self.run_pkg('query', '%n %o %v').stdout)


if __name__ == '__main__':
    unittest.main()
