# SPDX-License-Identifier: BSD-2-Clause
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
helper = os.environ.get('BSD_BUILD_INSTALLER_HELPER', str(Path(__file__).resolve().parents[3] / 'tools/build/capimage/installer.py'))
spec = importlib.util.spec_from_file_location('installer', helper)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class Installer(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'custom-publication/generation'
        self.repo.mkdir(parents=True)
        (self.repo / 'publication.json').write_text('{}')
        self.runs = self.base / 'runs'
        self.runs.mkdir()
        self.key = self.base / 'public'
        self.key.write_text('public trust fixture')
        self.tool = self.base / 'tool'
        self.tool.write_text('#!/bin/sh\nexit 0\n')
        self.tool.chmod(0o755)
        self.scripts = self.base / 'scripts'
        self.scripts.mkdir()
        for name in ('auto', 'repository.subr', 'verify-image'):
            (self.scripts / name).write_text('BSDINSTALL_CODE_PUBLIC_KEY bsdinstall_repository')
        self.events = []
        self.fail_copy = False
        self.fail_install = False
        self.host_abi = 'FreeBSD:16:amd64'
        self.names = {'pkg': None, '5BSD-set-base': None, '5BSD-kernel-generic': None}
        self.hardware = SimpleNamespace(verify=lambda p: {'abi': 'FreeBSD:16:amd64', 'osversion': 1600018},
            copy_signed_repository=self.copy_repository, inventory=lambda p: self.names)

    def copy_repository(self, source, target, public, pkg, abi, version):
        self.events.append(('verify-copy', target))
        if self.fail_copy:
            raise ValueError('payload verification failed')
        shutil.copytree(source, target)
        return target

    def command(self, words, **kwargs):
        if 'key-id' in words:
            return SimpleNamespace(stdout='fixture key identity', stderr='')
        if words[-2:] == ['config', 'ABI']:
            return SimpleNamespace(stdout=self.host_abi, stderr='')
        self.events.append(('install', words, kwargs))
        if self.fail_install:
            raise subprocess.CalledProcessError(1, words)
        return SimpleNamespace(returncode=0)

    def invoke(self, plan=False, uid=0):
        argv = ['installer', '--repository', str(self.repo), '--pkg-public-key', str(self.key),
                '--public-key', str(self.key), '--capsign', str(self.tool), '--elfcache', str(self.tool)]
        if plan:
            argv.append('--plan')
        with patch.object(sys, 'argv', argv), \
             patch.object(installer, 'RUN_ROOT', self.runs), patch.object(installer, 'INSTALLER', self.tool), \
             patch.object(installer, 'INSTALLER_SCRIPTS', self.scripts), \
             patch.object(installer.os, 'geteuid', return_value=uid), patch.object(sys.stdin, 'isatty', return_value=True), \
             patch.object(installer, 'load_hardware', return_value=self.hardware), \
             patch.object(installer.subprocess, 'run', side_effect=self.command):
            installer.main()

    def test_plan_is_read_only(self):
        before = sorted(self.base.rglob('*'))
        self.invoke(plan=True, uid=1001)
        self.assertEqual(before, sorted(self.base.rglob('*')))
        self.assertEqual(self.events, [])

    def test_verification_precedes_launch_and_pins_trust(self):
        with patch.dict(os.environ, {'BSDINSTALL_SKIP_HOSTNAME': 'yes', 'BSDINSTALL_PKG_REPOS_DIR': '/wrong'}):
            self.invoke()
        self.assertEqual([e[0] for e in self.events], ['verify-copy', 'install'])
        environment = self.events[1][2]['env']
        self.assertNotIn('BSDINSTALL_SKIP_HOSTNAME', environment)
        self.assertNotEqual(environment['BSDINSTALL_PKG_REPOS_DIR'], '/wrong')
        self.assertEqual(Path(environment['BSDINSTALL_CODE_PUBLIC_KEY']).read_text(), self.key.read_text())
        self.assertEqual(self.events[1][1], [str(self.tool), 'auto'])

    def test_bad_payload_never_launches(self):
        self.fail_copy = True
        with self.assertRaisesRegex(ValueError, 'payload verification'):
            self.invoke()
        self.assertEqual([e[0] for e in self.events], ['verify-copy'])

    def test_foreign_architecture_rejected_before_copy(self):
        self.host_abi = 'FreeBSD:16:aarch64'
        with self.assertRaisesRegex(ValueError, 'native architecture'):
            self.invoke()
        self.assertEqual(self.events, [])
        self.assertEqual(list(self.runs.iterdir()), [])

    def test_missing_bootstrap_never_launches(self):
        del self.names['pkg']
        with self.assertRaisesRegex(ValueError, 'lacks: pkg'):
            self.invoke()
        self.assertEqual([e[0] for e in self.events], ['verify-copy'])

    def test_old_installer_rejected(self):
        (self.scripts / 'auto').write_text('old installer')
        with self.assertRaisesRegex(ValueError, 'lacks explicit'):
            self.invoke()
        self.assertEqual(self.events, [])

    def test_failure_retains_recovery_files(self):
        self.fail_install = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke()
        work, = self.runs.iterdir()
        self.assertTrue((work / 'repository/publication.json').is_file())
        self.assertIn('failed', (work / 'status').read_text())

    def test_root_required(self):
        with self.assertRaises(PermissionError):
            self.invoke(uid=1001)
        self.assertEqual(self.events, [])


if __name__ == '__main__':
    unittest.main()
