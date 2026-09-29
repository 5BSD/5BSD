#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise real pkg archives/solver and the shared hardware installer."""
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

SRC = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('hardware_packages', SRC / 'release/scripts/hardware-packages.py')
hw = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
spec.loader.exec_module(hw)
PKG = '/usr/local/sbin/pkg-static'
ABI = subprocess.check_output([PKG, 'config', 'ABI'], text=True).strip()
OSVERSION = subprocess.check_output([PKG, 'config', 'OSVERSION'], text=True).strip()


class HardwarePackages(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.inputs = self.base / 'inputs'
        self.inputs.mkdir()
        self.counter = 0

    def package(self, name, files=None, deps=None, version='1', origin=None):
        self.counter += 1
        root = self.base / ('payload' + str(self.counter))
        root.mkdir()
        entries = {}
        for f, data in (files or {}).items():
            p = root / f.lstrip('/')
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data if isinstance(data, bytes) else data.encode())
            entries[f] = hw.sha256(p)
        meta = dict(name=name, version=version, origin=origin or 'test/' + name,
                    abi=ABI, arch='freebsd:16:x86:64', prefix='/',
                    comment='test package', desc='test package',
                    maintainer='test@example.org', www='https://example.org',
                    files=entries, deps=deps or {},
                    annotations={'FreeBSD_version': OSVERSION})
        manifest = self.base / 'input.json'
        manifest.write_text(json.dumps(meta))
        hw.run(PKG, 'create', '-r', root, '-M', manifest, '-o', self.inputs,
               stdout=subprocess.DEVNULL)
        return self.inputs / (name + '-' + version + '.pkg')

    def repository(self, label='old', epoch=100):
        kernel = self.package('5BSD-kernel-generic', {'/boot/kernel/kernel': label}, version=str(epoch))
        self.package('wifi-firmware-test', {'/boot/firmware/test.bin': 'firmware'})
        self.package('drm-test', {'/boot/modules/test.ko': 'module'}, {
            'wifi-firmware-test': {'origin': 'test/wifi-firmware-test', 'version': '1'}})
        out = self.base / label
        hw.seal(SimpleNamespace(output=out, kernel_package=kernel,
                                packages=self.inputs, seeds=['drm-test'], epoch=epoch, pkg=PKG))
        return kernel, out

    def test_firmware_and_module_classification(self):
        self.assertEqual(hw.package_kind({'name': 'firmware-test',
            'files': {'/boot/modules/fw.ko.zst': 'hash'}}), 'module')
        self.assertEqual(hw.package_kind({'name': 'iwmbt-firmware',
            'files': {'/usr/local/share/iwmbt-firmware/intel.sfi': 'hash'}}), 'firmware')
        self.assertEqual(hw.package_kind({'name': 'firmware-tool',
            'files': {'/usr/local/bin/loader': 'hash'}}), 'support')

    def test_repository_defaults_keep_upstream_kmods_disabled(self):
        # Ask pkg to parse each shipped template, including variable expansion.
        # No catalogue refresh or network access is needed.
        repos = self.base / 'repos'
        repos.mkdir()
        templates = [(SRC / 'usr.sbin/pkg' / ('FreeBSD.conf.' + branch),
                      'FreeBSD-ports', 'FreeBSD-ports-kmods')
                     for branch in ('latest', 'quarterly', 'quarterly-release')]
        templates.append((SRC / 'release/pkg_repos/release-dvd.conf',
                          'release', 'release-kmods'))
        for template, userland, modules in templates:
            with self.subTest(template=template.name):
                (repos / 'test.conf').write_text(template.read_text())
                output = hw.run(PKG, '-C', '/dev/null', '-o',
                                'REPOS_DIR=' + str(repos), '-vv',
                                capture_output=True).stdout
                output = output.split('Repositories:', 1)[1]
                enabled = dict(re.findall(
                    r'^  ([\w-]+): \{\s*.*?enabled\s*:\s*(yes|no)',
                    output, re.M | re.S))
                self.assertEqual(enabled[userland], 'yes')
                self.assertEqual(enabled[modules], 'no')

    def test_gpu_wrapper_becomes_exact_raw_data(self):
        obj = self.base / 'firmware.o'
        assembly = ('.section .rodata\n.globl _binary_gpu_fw_start\n'
                    '_binary_gpu_fw_start:\n.byte 1,0,255,42\n'
                    '.globl _binary_gpu_fw_end\n_binary_gpu_fw_end:\n')
        hw.run('cc', '-x', 'assembler', '-c', '-o', obj, '-', input=assembly)
        package = self.package('gpu-firmware-test', {
            '/boot/modules/gpu_fw.ko': obj.read_bytes(),
            '/usr/local/share/licenses/gpu/LICENSE': 'test license'},
            origin='graphics/gpu-firmware-test')
        output = self.base / 'raw'
        output.mkdir()
        archive, meta = hw.raw_gpu_firmware(PKG, output, package, hw.manifest(package))
        self.assertEqual(hw.package_kind(meta), 'firmware')
        self.assertNotIn('/boot/modules/gpu_fw.ko', meta['files'])
        self.assertIn('/usr/local/share/licenses/gpu/LICENSE', meta['files'])
        self.assertFalse(meta.get('scripts'))
        root = self.base / 'unpacked'
        root.mkdir()
        hw.run('tar', '-xf', archive, '-C', root, '--exclude', '+*')
        self.assertEqual((root / 'boot/firmware/gpu_fw').read_bytes(), bytes([1, 0, 255, 42]))
        bad = self.package('gpu-firmware-bad', {'/boot/modules/gpu_fw.ko': 'not ELF'},
                           origin='graphics/gpu-firmware-bad')
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            hw.raw_gpu_firmware(PKG, output, bad, hw.manifest(bad))

    def test_closure_missing_dependency(self):
        with self.assertRaisesRegex(ValueError, 'missing hardware dependency'):
            hw.closure({}, ['missing'])

    def test_archive_identity_dependencies_and_raw_firmware(self):
        kernel, repo = self.repository()
        info = hw.verify(repo, kernel)
        self.assertEqual(info['osversion'], int(OSVERSION))
        token = '5BSD-hardware-abi-' + info['kernel_sha256']
        listing = hw.run('tar', '-tvf', repo / (token + '-1.pkg'),
                         capture_output=True).stdout.splitlines()
        identity = next(line for line in listing
                        if line.endswith('/usr/share/5bsd/hardware-abi'))
        self.assertEqual(identity.split()[2:4], ['root', 'wheel'])
        driver = hw.manifest(repo / info['packages']['drm-test']['file'])
        self.assertIn(token, driver['deps'])
        self.assertIn('5BSD-hw-wifi-firmware-test', driver['deps'])
        self.assertEqual(driver['annotations']['5BSD_hardware_kind'], 'module')
        self.assertEqual(info['packages']['wifi-firmware-test']['kind'], 'firmware')
        self.assertIn(token, hw.manifest(repo / info['kernel_package'])['deps'])
        firmware = hw.manifest(repo / info['packages']['wifi-firmware-test']['file'])
        self.assertFalse(firmware.get('deps'))
        self.assertNotIn('5BSD_kernel_sha256', firmware['annotations'])
        self.assertEqual(firmware['version'], '1')
        other = self.package('5BSD-kernel-generic', {'/boot/kernel/kernel': 'different'}, version='different')
        with self.assertRaisesRegex(ValueError, 'different kernel'):
            hw.verify(repo, other)
        (repo / info['packages']['drm-test']['file']).write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            hw.verify(repo)

    def test_driver_selection_does_not_install_all_gpu_firmware(self):
        kernel = self.package('5BSD-kernel-generic', {'/boot/kernel/kernel': 'old'}, version='100')
        self.package('drm-612-kmod', {'/boot/modules/drm.ko': 'module'})
        self.package('gpu-firmware-test', {'/boot/firmware/unneeded.bin': 'firmware'})
        def deps(*names):
            return {n: {'origin': 'test/' + n, 'version': '1'} for n in names}
        self.package('gpu-firmware-kmod', deps=deps('gpu-firmware-test'))
        self.package('drm-kmod', deps=deps('drm-612-kmod', 'gpu-firmware-kmod'))
        repo = self.base / 'repo'
        hw.seal(SimpleNamespace(output=repo, kernel_package=kernel,
            packages=self.inputs, seeds=['drm-kmod', 'gpu-firmware-kmod'], epoch=100, pkg=PKG))
        self.assertIn('gpu-firmware-test', hw.verify(repo)['packages'])
        root = self.base / 'target'
        conf = root / 'etc/pkg'
        conf.mkdir(parents=True)
        (conf / 'test.conf').write_text('test: { url: "file://' + str(repo) + '", enabled: yes }')
        cmd = [PKG, '-r', str(root), '-o', 'INSTALL_AS_USER=yes',
            '-o', 'PKG_DBDIR=' + str(root / 'var/db/pkg'),
            '-o', 'PKG_CACHEDIR=' + str(root / 'var/cache/pkg'),
            '-o', 'REPOS_DIR=' + str(conf), '-o', 'ABI=' + ABI, '-o', 'OSVERSION=' + OSVERSION]
        hw.run(*cmd, 'install', '-y', '5BSD-hw-drm-kmod')
        self.assertTrue((root / 'boot/modules/drm.ko').exists())
        self.assertFalse((root / 'boot/firmware/unneeded.bin').exists())

    def test_live_media_module_index(self):
        module = Path('/boot/modules/i915kms.ko')
        if not module.is_file():
            self.skipTest('requires a real module to exercise kldxref')
        kernel, repo = self.repository()
        root = self.base / 'indexed-media'
        (root / 'boot/kernel').mkdir(parents=True)
        (root / 'boot/kernel/kernel').write_text('old')
        (root / 'boot/modules').mkdir()
        import shutil
        shutil.copy2(module, root / 'boot/modules/i915kms.ko')
        hw.stage(SimpleNamespace(repository=repo, kernel_package=None,
                                 base_repository=None, media=root, pkg=PKG))
        self.assertTrue((root / 'boot/modules/linker.hints').is_file())
        self.assertIn('./boot/modules/linker.hints', (root / 'METALOG').read_text())

    def test_live_media_and_base_repository_staging(self):
        kernel, repo = self.repository()
        root = self.base / 'media'
        (root / 'boot/kernel').mkdir(parents=True)
        (root / 'boot/kernel/kernel').write_text('old')
        base = self.base / 'base-repo'
        base.mkdir()
        import shutil
        shutil.copy2(kernel, base / kernel.name)
        latest = self.base / 'latest'
        latest.symlink_to(base, target_is_directory=True)
        hw.stage(SimpleNamespace(repository=repo, kernel_package=None,
                                 base_repository=latest, media=root, pkg=PKG))
        self.assertTrue((root / 'boot/firmware/test.bin').exists())
        self.assertTrue((root / 'usr/5bsd-packages/hardware/hardware.json').exists())
        self.assertEqual((root / 'boot/kernel/kernel').read_text(), 'old')
        self.assertIn('5BSD_kernel_sha256', hw.manifest(base / kernel.name)['annotations'])
        (root / 'boot/kernel/kernel').write_text('wrong')
        with self.assertRaisesRegex(ValueError, 'live media kernel'):
            hw.stage(SimpleNamespace(repository=repo, kernel_package=None,
                                     base_repository=None, media=root, pkg=PKG))

    def test_real_pkg_install_and_kernel_upgrade_requires_matching_hardware(self):
        kernel, repo = self.repository()
        root = self.base / 'target'
        conf = root / 'etc/pkg'
        conf.mkdir(parents=True)
        # INSTALL_AS_USER uses host paths; runtime/root behavior is separately
        # covered by the helper stubs and release stage test.
        (conf / 'test.conf').write_text('test: { url: "file://' + str(repo) + '", enabled: yes }')
        db = root / 'var/db/pkg'
        db.mkdir(parents=True)
        cmd = [PKG, '-r', str(root), '-o', 'INSTALL_AS_USER=yes', '-o', 'PKG_DBDIR=' + str(db),
               '-o', 'REPOS_DIR=' + str(conf), '-o', 'PKG_CACHEDIR=' + str(root / 'cache'),
               '-o', 'ABI=' + ABI, '-o', 'OSVERSION=' + OSVERSION]
        hw.run(*cmd, 'update', '-f')
        hw.run(*cmd, 'install', '-y', '5BSD-kernel-generic', '5BSD-hw-drm-test')
        # A newer kernel with a different ABI token must not leave the old
        # hardware installed. With the new driver available, pkg upgrades both.
        kernel.unlink()
        _, newer = self.repository('new', 101)
        (conf / 'test.conf').write_text('test: { url: "file://' + str(newer) + '", enabled: yes }')
        hw.run(*cmd, 'update', '-f')
        hw.run(*cmd, 'upgrade', '-y')
        names = hw.run(*cmd, 'query', '%n-%v', capture_output=True).stdout
        self.assertIn('5BSD-hw-drm-test-1,101', names)
        self.assertEqual(names.count('5BSD-hardware-abi-'), 1)
        self.assertIn('5BSD-kernel-generic-101', names)
        self.assertEqual((root / 'boot/kernel/kernel').read_text(), 'new')


if __name__ == '__main__':
    unittest.main()
