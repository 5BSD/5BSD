import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
helper = os.environ.get('BSD_BUILD_DEPLOY_HELPER', str(Path(__file__).resolve().parents[3] / 'tools/build/capimage/deploy.py'))
spec = importlib.util.spec_from_file_location('deploy', helper)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class Deployment(unittest.TestCase):
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
        self.key.write_text('mock public key')
        self.tool = self.base / 'tool'
        self.tool.write_text('#!/bin/sh\nexit 0\n')
        self.tool.chmod(0o755)
        self.calls = []
        self.fail_at = None
        self.names = ['5BSD-set-base', '5BSD-kernel-generic', '5BSD-hardware-abi-test-1']
        self.hardware = SimpleNamespace(
            verify=lambda path: {'abi': 'FreeBSD:16:amd64', 'osversion': 1600018},
            manifest=lambda path: {'name': '5BSD-set-base'})

    def run_command(self, *args, capture=False):
        words = list(map(str, args))
        self.calls.append(words)
        if words[0] == 'bectl' and words[1] == 'mount':
            Path(words[-1]).mkdir()
        if 'fetch' in words:
            target = Path(words[words.index('fetch') + 4]) / 'All'
            target.mkdir(parents=True)
            (target / 'base.pkg').write_text('mock verified archive')
        if self.fail_at and self.fail_at(words):
            raise subprocess.CalledProcessError(1, words)
        return SimpleNamespace(stdout=('FreeBSD:16:amd64\n' if words[-2:] == ['config', 'ABI'] else '\n'.join(self.names) + '\n' if 'rquery' in words else ''), stderr='')

    def invoke(self, *extra, plan=False):
        argv = ['deploy', '--repository', str(self.repo), '--pkg-public-key', str(self.key),
                '--public-key', str(self.key), '--capsign', str(self.tool), '--elfcache', str(self.tool), *extra]
        if plan:
            argv.append('--plan')
        with patch.object(sys, 'argv', argv), \
             patch.object(deploy, 'RUN_ROOT', self.runs), patch.object(deploy.os, 'geteuid', return_value=0), \
             patch.object(deploy, 'load_hardware', return_value=self.hardware), \
             patch.object(deploy, 'command', side_effect=self.run_command), \
             patch.object(deploy.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
            deploy.main()

    def test_plan_no_mutation(self):
        before = sorted(self.base.rglob('*'))
        self.invoke('--bootenv', 'review', plan=True)
        self.assertEqual(before, sorted(self.base.rglob('*')))
        self.assertEqual([], self.calls)

    def test_fetch_failure_before_be_creation(self):
        self.fail_at = lambda words: 'fetch' in words
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] == 'bectl' for words in self.calls))

    def test_success_unmounts_without_activation(self):
        self.invoke('--bootenv', 'review')
        be = [words[:2] for words in self.calls if words[0] == 'bectl']
        self.assertEqual(be, [['bectl', 'create'], ['bectl', 'mount'], ['bectl', 'unmount']])
        self.assertTrue(any(words[0] == 'umount' for words in self.calls))
        self.assertTrue(any('chroot' == words[0] and 'install' in words for words in self.calls))

    def test_unmount_failure_retains_mounted_root(self):
        self.fail_at = lambda words: words[0] == 'umount'
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[:2] == ['bectl', 'unmount'] for words in self.calls))
        roots = list(self.runs.glob('deploy-*/root'))
        self.assertEqual(len(roots), 1)
        self.assertTrue((roots[0] / 'dev').is_dir())

    def test_existing_root_unchanged(self):
        root = self.base / 'existing'
        root.mkdir()
        (root / 'sentinel').write_text('preserve')
        with self.assertRaisesRegex(ValueError, 'must not exist'):
            self.invoke('--root', str(root))
        self.assertEqual('preserve', (root / 'sentinel').read_text())
        self.assertEqual([], self.calls)


if __name__ == '__main__':
    unittest.main()
