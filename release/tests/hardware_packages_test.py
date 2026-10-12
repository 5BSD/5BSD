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

_host_spec = importlib.util.spec_from_file_location('native_hardware', SRC / 'release/scripts/native-hardware.py')
host = importlib.util.module_from_spec(_host_spec)
_host_spec.loader.exec_module(host)


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

    def test_signed_catalogue_consumer_verification(self):
        self.package('5BSD-signature-test', {'/bin/test': 'payload'})
        key = self.base / 'key.pem'
        wrong = self.base / 'wrong.pem'
        for path in (key, wrong):
            hw.run('openssl', 'genpkey', '-algorithm', 'RSA',
                   '-pkeyopt', 'rsa_keygen_bits:2048', '-out', path,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        hw.run(PKG, 'repo', self.inputs, key)
        hw.verify_signed_catalogue(self.inputs, key, PKG, ABI)
        public = self.base / 'repository.pub'
        hw.run('openssl', 'pkey', '-in', key, '-pubout', '-out', public)
        # Consumer verification must work without access to a signing key.
        hidden = key.rename(self.base / 'private-key-unavailable.pem')
        hw.verify_catalogue_public_key(self.inputs, public, PKG, ABI, OSVERSION)
        hidden.rename(key)
        offline = self.base / 'offline'
        hw.run(sys.executable, SRC / 'release/scripts/hardware-packages.py',
               'copy-signed-repository', '--repository', self.inputs,
               '--output', offline, '--public-key', public, '--pkg', PKG,
               '--abi', ABI, '--osversion', OSVERSION)
        original = {p.name: hw.sha256(p) for p in self.inputs.iterdir() if p.is_file()}
        copied = {p.name: hw.sha256(p) for p in offline.iterdir() if p.is_file()}
        self.assertEqual(original, copied)
        with self.assertRaisesRegex(ValueError, 'already exists'):
            hw.copy_signed_repository(self.inputs, offline, public, PKG, ABI, OSVERSION)
        (self.inputs / 'unexpected-link').symlink_to(key)
        with self.assertRaisesRegex(ValueError, 'unsupported offline'):
            hw.copy_signed_repository(self.inputs, self.base / 'rejected-copy',
                                      public, PKG, ABI, OSVERSION)
        self.assertFalse((self.base / 'rejected-copy').exists())
        (self.inputs / 'unexpected-link').unlink()
        # A valid signed catalogue with a different, well-formed same-name
        # archive must fail before an offline destination becomes visible.
        archive = self.inputs / '5BSD-signature-test-1.pkg'
        original_archive = archive.read_bytes()
        archive.unlink()
        self.package('5BSD-signature-test', {'/bin/test': 'changed payload'})
        with self.assertRaises((subprocess.CalledProcessError, ValueError)):
            hw.copy_signed_repository(self.inputs, self.base / 'bad-payload',
                                      public, PKG, ABI, OSVERSION)
        self.assertFalse((self.base / 'bad-payload').exists())
        self.assertFalse(list(self.base.glob('.offline-*')))
        archive.write_bytes(original_archive)
        wrong_public = self.base / 'wrong.pub'
        hw.run('openssl', 'pkey', '-in', wrong, '-pubout', '-out', wrong_public)
        with self.assertRaises((subprocess.CalledProcessError, ValueError)):
            hw.verify_catalogue_public_key(self.inputs, wrong_public, PKG, ABI, OSVERSION)
        with self.assertRaises((subprocess.CalledProcessError, ValueError)):
            hw.verify_signed_catalogue(self.inputs, wrong, PKG, ABI)
        # Replacing signed catalogues with valid unsigned catalogues must fail.
        for name in ('data.pkg', 'packagesite.pkg', 'meta.pkg'):
            (self.inputs / name).unlink(missing_ok=True)
        hw.run(PKG, 'repo', self.inputs)
        with self.assertRaises((subprocess.CalledProcessError, ValueError)):
            hw.verify_signed_catalogue(self.inputs, key, PKG, ABI)
        self.assertFalse(list(self.base.glob('.verify-*')))

    def test_signature_verification_failure_preserves_latest(self):
        from unittest.mock import patch
        kernel, hardware = self.repository()
        self.publish_repository(kernel, hardware, 'prior')
        base = self.base / 'prior-base'
        key = self.base / 'key.pem'
        hw.run('openssl', 'genpkey', '-algorithm', 'RSA',
               '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with patch.object(hw, 'verify_signed_catalogue', side_effect=ValueError('signature rejected')):
            with self.assertRaisesRegex(ValueError, 'signature rejected'):
                hw.publish(SimpleNamespace(repository=hardware, base_repository=base,
                    output=self.base / 'rejected', signing_key=key, pkg=PKG))
        self.assertEqual((self.base / 'latest').readlink(), Path('prior'))
        self.assertFalse((self.base / 'rejected').exists())
        self.assertFalse(list(self.base.glob('.publish-*')))

    def test_failed_query_preserves_captured_diagnostics(self):
        import contextlib
        import io
        diagnostic = io.StringIO()
        with contextlib.redirect_stderr(diagnostic):
            with self.assertRaises(subprocess.CalledProcessError):
                hw.run('/bin/sh', '-c', 'echo database-diagnostic >&2; exit 1',
                       capture_output=True)
        self.assertIn('database-diagnostic', diagnostic.getvalue())

    def host_inputs(self):
        self.package('5BSD-kernel-generic', {'/boot/kernel/kernel': 'kernel'})
        self.package('5BSD-src', {'/usr/src/Makefile': 'source'})
        self.package('5BSD-src-sys', {'/usr/src/sys/sys/param.h': 'source'})
        bootstrap = self.package('pkg', {'/usr/local/sbin/pkg': 'bootstrap'})
        bootstrap = bootstrap.rename(self.base / bootstrap.name)
        obj = self.base / 'obj'; obj.mkdir(); (obj / 'kernel').write_text('kernel')
        ports = self.base / 'custom-ports'; (ports / 'Mk').mkdir(parents=True)
        (ports / 'Mk/bsd.port.mk').write_text('# custom tree')
        (ports / 'graphics/drm-kmod').mkdir(parents=True)
        (ports / 'graphics/drm-kmod/Makefile').write_text('# driver')
        profile = self.base / 'profile'; profile.write_text('graphics/drm-kmod\n')
        return SimpleNamespace(base=self.inputs, kernel_build=obj, ports=ports,
            bootstrap=bootstrap, profile=profile, pkg=PKG, check=True,
            output=self.base / 'hardware', distfiles=self.base / 'distfiles',
            work=self.base / 'native-work')

    def test_host_preflight_rejects_foreign_kernel_architecture(self):
        from unittest.mock import patch
        args = self.host_inputs()
        original = hw.run
        # Only substitute the host ABI query; all package/kernel checks use
        # actual fixture archives. A foreign builder must refuse before writes.
        def query(*command, **kwargs):
            if command == (PKG, 'config', 'ABI'):
                return SimpleNamespace(stdout='FreeBSD:16:foreign\n')
            return original(*command, **kwargs)
        before = sorted(str(p) for p in self.base.rglob('*'))
        with patch.object(host.hw, 'run', side_effect=query):
            with self.assertRaisesRegex(ValueError, 'target-native builder'):
                host.build(args)
        self.assertEqual(before, sorted(str(p) for p in self.base.rglob('*')))

    def test_host_preflight_accepts_custom_ports_without_writes(self):
        args = self.host_inputs()
        before = sorted(str(x) for x in self.base.rglob('*'))
        host.build(args)
        self.assertEqual(before, sorted(str(x) for x in self.base.rglob('*')))

    def test_host_preflight_rejects_mismatched_objects(self):
        args = self.host_inputs()
        (args.kernel_build / 'kernel').write_text('wrong')
        with self.assertRaisesRegex(ValueError, 'kernel objects'):
            host.build(args)

    def test_host_preflight_requires_packaged_source(self):
        args = self.host_inputs()
        (args.base / '5BSD-src-sys-1.pkg').unlink()
        with self.assertRaisesRegex(ValueError, 'missing source package'):
            host.build(args)

    def test_host_preflight_rejects_missing_custom_ports(self):
        args = self.host_inputs()
        args.ports = self.base / 'missing'
        with self.assertRaisesRegex(ValueError, 'PORTSDIR'):
            host.build(args)

    def test_host_preflight_rejects_missing_profile_port(self):
        args = self.host_inputs()
        args.profile.write_text('graphics/not-in-this-tree\n')
        with self.assertRaisesRegex(ValueError, 'port missing'):
            host.build(args)

    def test_native_preflight_rejects_empty_profile_without_staging(self):
        args = self.host_inputs()
        args.profile.write_text('# empty profile\n')
        with self.assertRaisesRegex(ValueError, 'empty hardware profile'):
            host.build(args)
        self.assertFalse(args.work.exists())

    def test_native_preflight_accepts_existing_output_without_mutation(self):
        args = self.host_inputs()
        args.output.mkdir()
        marker = args.output / 'marker'; marker.write_text('preserve')
        host.build(args)
        self.assertEqual(marker.read_text(), 'preserve')
        self.assertFalse(args.work.exists())

    def repository(self, label='old', epoch=100, kernel_name='5BSD-kernel-generic'):
        kernel = self.package(kernel_name, {'/boot/kernel/kernel': label}, version=str(epoch))
        self.package('wifi-firmware-test', {'/boot/firmware/test.bin': 'firmware'})
        self.package('drm-test', {'/boot/modules/test.ko': 'module'}, {
            'wifi-firmware-test': {'origin': 'test/wifi-firmware-test', 'version': '1'}})
        out = self.base / label
        hw.seal(SimpleNamespace(output=out, kernel_package=kernel,
                                packages=self.inputs, seeds=['drm-test'], epoch=epoch, pkg=PKG))
        return kernel, out

    def publish_repository(self, kernel, hardware, name, pkg=PKG):
        import shutil
        base = self.base / (name + '-base')
        base.mkdir()
        shutil.copy2(kernel, base / kernel.name)
        runtime = self.package('5BSD-runtime', {'/bin/example': name}, version=name)
        shutil.copy2(runtime, base / runtime.name)
        output = self.base / name
        hw.publish(SimpleNamespace(repository=hardware, base_repository=base,
                                   output=output, signing_key=None, pkg=pkg))
        return output

    def signed_media_fixture(self):
        import shutil
        kernel, hardware = self.repository()
        key = self.base / 'media-private.pem'
        public = self.base / 'media-public.pem'
        hw.run('openssl', 'genpkey', '-algorithm', 'RSA',
               '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        hw.run('openssl', 'pkey', '-in', key, '-pubout', '-out', public)
        base = self.base / 'media-base'
        base.mkdir()
        for archive in (kernel, self.package('pkg', {'/usr/local/sbin/pkg': 'fixture'}),
                        self.package('5BSD-set-base')):
            shutil.copy2(archive, base / archive.name)
        repository = self.base / 'media-publication'
        hw.publish(SimpleNamespace(repository=hardware, base_repository=base,
            output=repository, signing_key=key, pkg=PKG))
        media = self.base / 'media'
        (media / 'boot/kernel').mkdir(parents=True)
        (media / 'usr').mkdir()
        (media / 'boot/kernel/kernel').write_text('old')
        codekey = self.base / 'code-private.pem'
        codepublic = self.base / 'code-public.pem'
        hw.run('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', codekey)
        hw.run('openssl', 'pkey', '-in', codekey, '-pubout', '-out', codepublic)
        return SimpleNamespace(repository=repository, media=media,
            public_key=public, code_public_key=codepublic, pkg=PKG)

    def test_signed_media_preserves_catalogue_and_installs_firmware(self):
        args = self.signed_media_fixture()
        before = {p.name: hw.sha256(p) for p in args.repository.iterdir() if p.is_file()}
        hw.stage_signed_media(args)
        destination = args.media / 'usr/5bsd-packages'
        after = {p.name: hw.sha256(p) for p in (destination / 'offline').iterdir() if p.is_file()}
        self.assertEqual(before, after)
        config = json.loads((destination / 'repos/5BSD-base-offline.conf').read_text())['5BSD-base']
        self.assertEqual(config['signature_type'], 'pubkey')
        self.assertEqual(config['url'], 'file:///usr/5bsd-packages/offline')
        self.assertEqual((destination / 'keys/repository.pub').read_bytes(), args.public_key.read_bytes())
        self.assertEqual((args.media / 'boot/firmware/test.bin').read_text(), 'firmware')
        self.assertIn('./usr/5bsd-packages/keys/code.pub type=file', (args.media / 'METALOG').read_text())
        with self.assertRaisesRegex(ValueError, 'already exists'):
            hw.stage_signed_media(args)

    def test_signed_media_rejects_kernel_and_symlink_before_copy(self):
        args = self.signed_media_fixture()
        kernel = args.media / 'boot/kernel/kernel'
        kernel.write_text('wrong')
        with self.assertRaisesRegex(ValueError, 'kernel does not match'):
            hw.stage_signed_media(args)
        self.assertFalse((args.media / 'usr/5bsd-packages').exists())
        kernel.write_text('old')
        (args.media / 'usr').rmdir()
        (args.media / 'usr').symlink_to(self.base)
        with self.assertRaisesRegex(ValueError, 'invalid media directory'):
            hw.stage_signed_media(args)
        self.assertFalse((self.base / '5bsd-packages').exists())

    def test_complete_publication_is_one_repository_and_inputs_unchanged(self):
        kernel, hardware = self.repository()
        original = hw.sha256(kernel)
        repo = self.publish_repository(kernel, hardware, 'complete')
        self.assertEqual((self.base / 'latest').readlink(), Path('complete'))
        packages = hw.inventory(repo)
        self.assertIn('5BSD-runtime', packages)
        self.assertIn('5BSD-hw-drm-test', packages)
        self.assertIn('5BSD-kernel-generic', packages)
        self.assertEqual(hw.sha256(kernel), original)
        self.assertEqual(hw.verify(repo)['kernel_sha256'], hw.kernel_hash(kernel))
        with self.assertRaisesRegex(ValueError, 'new generation'):
            hw.publish(SimpleNamespace(repository=hardware,
                base_repository=self.base / 'complete-base', output=repo,
                signing_key=None, pkg=PKG))

    def test_missing_base_dependency_never_advances_latest(self):
        import shutil
        kernel, hardware = self.repository()
        base = self.base / 'incomplete-base'; base.mkdir()
        shutil.copy2(kernel, base / kernel.name)
        broken = self.package('5BSD-unrelated', {'/bin/unrelated': 'payload'},
            {'5BSD-missing': {'origin': 'test/missing', 'version': '1'}})
        shutil.copy2(broken, base / broken.name)
        (self.base / 'latest').symlink_to('previous')
        output = self.base / 'rejected'
        with self.assertRaisesRegex(ValueError, '5BSD-missing'):
            hw.publish(SimpleNamespace(repository=hardware, base_repository=base,
                output=output, signing_key=None, pkg=PKG))
        self.assertEqual((self.base / 'latest').readlink(), Path('previous'))
        self.assertFalse(output.exists())
        self.assertFalse(list(self.base.glob('.publish-*')))
        self.assertTrue(broken.exists())

    def test_failed_catalogue_never_advances_latest(self):
        kernel, hardware = self.repository()
        previous = self.base / 'previous'; previous.mkdir()
        (self.base / 'latest').symlink_to('previous')
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish_repository(kernel, hardware, 'failed', '/usr/bin/false')
        self.assertEqual((self.base / 'latest').resolve(), previous)
        self.assertFalse((self.base / 'failed').exists())
        self.assertFalse(list(self.base.glob('.publish-*')))

    def test_wrong_kernel_never_advances_latest(self):
        kernel, hardware = self.repository()
        wrong = self.package('5BSD-kernel-generic',
                             {'/boot/kernel/kernel': 'wrong'}, version='100')
        (self.base / 'latest').symlink_to('previous')
        with self.assertRaisesRegex(ValueError, 'different kernel'):
            self.publish_repository(wrong, hardware, 'wrong')
        self.assertEqual((self.base / 'latest').readlink(), Path('previous'))
        self.assertFalse((self.base / 'wrong').exists())

    def test_real_upgrade_from_hardware_repo_to_combined_repo(self):
        kernel, old = self.repository()
        root = self.base / 'target'; conf = root / 'etc/pkg'; conf.mkdir(parents=True)
        db = root / 'var/db/pkg'; db.mkdir(parents=True)
        config = conf / 'test.conf'
        config.write_text('5BSD-hardware: { url: "file://' + str(old) + '", enabled: yes }')
        cmd = [PKG, '-r', str(root), '-o', 'INSTALL_AS_USER=yes',
               '-o', 'PKG_DBDIR=' + str(db), '-o', 'REPOS_DIR=' + str(conf),
               '-o', 'PKG_CACHEDIR=' + str(root / 'cache'),
               '-o', 'ABI=' + ABI, '-o', 'OSVERSION=' + OSVERSION]
        hw.run(*cmd, 'install', '-y', '-r', '5BSD-hardware',
               '5BSD-kernel-generic', '5BSD-hw-drm-test')
        kernel.unlink()
        kernel, hardware = self.repository('new', 101, '5BSD-kernel-generic-nodebug')
        repo = self.publish_repository(kernel, hardware, 'combined')
        config.write_text('5BSD-base: { url: "file://' + str(repo) + '", enabled: no }')
        hw.run(*cmd, 'set', '-y', '-n', '5BSD-kernel-generic:5BSD-kernel-generic-nodebug')
        hw.run(*cmd, 'update', '-f', '-r', '5BSD-base')
        hw.run(*cmd, 'upgrade', '-y', '-r', '5BSD-base')
        names = hw.run(*cmd, 'query', '%n-%v', capture_output=True).stdout
        self.assertIn('5BSD-kernel-generic-nodebug-101', names)
        self.assertIn('5BSD-hw-drm-test-1,101', names)
        self.assertEqual(names.count('5BSD-hardware-abi-'), 1)
        self.assertEqual((root / 'boot/kernel/kernel').read_text(), 'new')

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
                self.assertEqual(enabled[userland],
                                 'yes' if userland == 'release' else 'no')
                self.assertEqual(enabled[modules], 'no')

    def test_5bsd_ports_default_is_local_native_catalogue(self):
        repos = self.base / 'repos'
        repos.mkdir()
        (repos / '5BSD-ports.conf').write_text(
            (SRC / 'usr.sbin/pkg/5BSD-ports.conf').read_text())
        output = hw.run(PKG, '-C', '/dev/null', '-o',
                        'REPOS_DIR=' + str(repos), '-vv',
                        capture_output=True).stdout.split('Repositories:', 1)[1]
        self.assertIn('5BSD-ports:', output)
        self.assertIn('file:///usr/5bsd-packages/ports', output)
        self.assertRegex(output, r'enabled\s*:\s*yes')

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
        module = Path(os.environ.get('HARDWARE_TEST_MODULE', '/boot/modules/i915kms.ko'))
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
        latest = self.base / 'latest-built'
        latest.symlink_to(base, target_is_directory=True)
        hw.stage(SimpleNamespace(repository=repo, kernel_package=None,
                                 base_repository=latest, media=root, pkg=PKG))
        self.assertTrue((root / 'boot/firmware/test.bin').exists())
        self.assertTrue((root / ('usr/obj/usr/src/repo/' + ABI + '/latest/hardware.json')).exists())
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

    def test_real_pkg_generic_to_nodebug_preserves_matching_hardware(self):
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
        _, newer = self.repository('new', 101, '5BSD-kernel-generic-nodebug')
        (conf / 'test.conf').write_text('test: { url: "file://' + str(newer) + '", enabled: yes }')
        hw.run(*cmd, 'update', '-f')
        hw.run(*cmd, 'set', '-y', '-n', '5BSD-kernel-generic:5BSD-kernel-generic-nodebug')
        hw.run(*cmd, 'upgrade', '-y')
        names = hw.run(*cmd, 'query', '%n-%v', capture_output=True).stdout
        self.assertIn('5BSD-hw-drm-test-1,101', names)
        self.assertEqual(names.count('5BSD-hardware-abi-'), 1)
        self.assertIn('5BSD-kernel-generic-nodebug-101', names)
        self.assertEqual((root / 'boot/kernel/kernel').read_text(), 'new')


if __name__ == '__main__':
    unittest.main()
