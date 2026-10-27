# SPDX-License-Identifier: BSD-2-Clause
"""Transport validation with real tar/media bytes; not boot acceptance."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

backend = Path(os.environ.get('BSD_BUILD_HELPERS', Path(__file__).resolve().parents[3] / 'tools/build/capimage'))
modules = {}
for name in ('generation_image', 'generation_boot'):
    spec = importlib.util.spec_from_file_location(name, backend / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); modules[name] = module
image, boot = modules['generation_image'], modules['generation_boot']


class RegularBootInput(unittest.TestCase):
    def test_fifo_rejected_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / 'input'
            os.mkfifo(fifo)
            # A subprocess timeout bounds a regression in open(), which otherwise
            # blocks before fstat can reject the nonregular input.
            code = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location('boot_input', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    with module.opened(sys.argv[2]):
        raise SystemExit('accepted FIFO')
except ValueError as error:
    if str(error) != 'input must be a regular file':
        raise
"""
            result = subprocess.run([sys.executable, '-B', '-c', code,
                str(backend / 'generation_boot.py'), str(fifo)],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_regular_file_and_nonregular_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / 'input'
            regular.write_bytes(b'boot input')
            with boot.opened(regular) as stream:
                self.assertEqual(stream.read(), b'boot input')
            with self.assertRaisesRegex(ValueError, 'regular file'):
                boot.opened(root)
            alias = root / 'alias'
            alias.symlink_to(regular)
            with self.assertRaises(OSError):
                boot.opened(alias)


class BootCheck(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.root = self.base / 'root'; self.root.mkdir()
        directory = self.root / 'boot'; directory.mkdir()
        (directory / 'kernel').write_bytes(b'kernel fixture')
        os.link(directory / 'kernel', self.root / 'alias')
        (directory / 'link').symlink_to('/boot/kernel')
        observed = image.construction.generation.scan(self.root)
        self.archive = self.base / 'boot.tar'
        archived = image.boot_archive(self.root, observed, self.archive)
        self.image = self.base / 'image.ufs'; self.image.write_bytes(b'image transport fixture, not a UFS')
        self.receipt = dict(scope='trusted-builder-filesystem-image', result='PASS',
            generation_authenticated=False, activation_authorized=False,
            source_observation_sha256=image.construction.digest(observed),
            readback_observation_sha256=image.construction.digest(observed),
            image_bytes=self.image.stat().st_size, image_sha256=image.file_hash(self.image), boot_archive=archived)
        self.receipt_path = self.base / 'receipt.json'

    def verify(self):
        self.receipt_path.write_text(json.dumps(self.receipt))
        return boot.verify(self.image, self.archive, self.receipt_path)

    def verified_artifacts(self):
        self.image = self.base / 'system.ufs'
        self.image.write_bytes(bytes(range(256)) * 32)
        self.receipt.update(scope='trusted-builder-partition-image',
            partition_content='immutable', partition_boundary=None,
            expected_observation_sha256=self.receipt['source_observation_sha256'],
            image_bytes=self.image.stat().st_size, image_sha256=image.file_hash(self.image))
        self.receipt['verity'] = image.verity.build(self.base,
            {'format': 1, 'block_size': 4096, 'salt_hex': 'aabb'},
            self.receipt['image_sha256'], self.receipt['image_bytes'])
        self.receipt_path.write_text(json.dumps(self.receipt))
        # Arbitrary input names demonstrate that the checker does not discover
        # artifacts by assuming names adjacent to the input filesystem image.
        combined, descriptor = self.base/'selected.bytes', self.base/'selected.root'
        (self.base/'system.verity').rename(combined)
        (self.base/'root.descriptor').rename(descriptor)
        return combined, descriptor

    def test_explicit_verity_inputs_are_bound_to_complete_boot_receipt(self):
        combined, descriptor = self.verified_artifacts()
        report = boot.verify(self.image, self.archive, self.receipt_path,
            verity_image=combined, verity_descriptor=descriptor)
        self.assertTrue(report['verity']['internal_consistency_verified'])
        self.assertEqual(report['verity']['image_sha256'], self.receipt['verity']['image_sha256'])
        self.assertEqual(report['verity']['descriptor_sha256'], image.file_hash(descriptor))
        for field in ('generation_authenticated', 'boot_verified', 'activation_authorized'):
            self.assertFalse(report[field])
        self.assertFalse(report['verity']['signer_authenticated'])
        out = self.base/'missing-artifacts-stage'
        with self.assertRaisesRegex(ValueError, 'explicit image and descriptor'):
            boot.stage(self.image, self.archive, self.receipt_path, out)
        self.assertFalse(out.exists())

    def test_root_transition_artifact_and_rejections(self):
        import struct
        signing = self.signing_inputs()
        efi = None
        required = ('BSD_BUILD_EFI_FIXTURE', 'BSD_BUILD_LOADER_RECEIPT',
                    'BSD_BUILD_MANIFEST_VERIFIER', 'BSD_BUILD_AUTHENTICODE_VERIFIER',
                    'BSD_BUILD_GENERATION_KEY', 'BSD_BUILD_GENERATION_CERTIFICATE',
                    'BSD_BUILD_UEFISIGN')
        if all(os.environ.get(name) for name in required):
            loader = Path(os.environ['BSD_BUILD_EFI_FIXTURE'])
            (self.root/'boot/loader.efi').write_bytes(loader.read_bytes())
            self.archive.unlink()
            observed = image.construction.generation.scan(self.root)
            self.receipt['boot_archive'] = image.boot_archive(self.root, observed, self.archive)
            self.receipt['source_observation_sha256'] = image.construction.digest(observed)
            self.receipt['readback_observation_sha256'] = image.construction.digest(observed)
            self.verify()
            signing = dict(key=Path(os.environ['BSD_BUILD_GENERATION_KEY']),
                certificate=Path(os.environ['BSD_BUILD_GENERATION_CERTIFICATE']),
                openssl=Path('/usr/bin/openssl'))
            efi = dict(path='/boot/loader.efi', signer=Path(os.environ['BSD_BUILD_UEFISIGN']),
                manifest_verifier=Path(os.environ['BSD_BUILD_MANIFEST_VERIFIER']),
                signature_verifier=Path(os.environ['BSD_BUILD_AUTHENTICODE_VERIFIER']),
                **self.loader_record(loader))
        combined, descriptor = self.verified_artifacts()
        checked = boot.verify(self.image, self.archive, self.receipt_path,
            verity_image=combined, verity_descriptor=descriptor)
        transition = dict(version=1, transport_fs='ufs',
            transport_device='/dev/gpt/site-boot', provider='site-root',
            workers=2, cache_blocks=64, window_bytes=131072, buffer_bytes=1048576)
        policy = dict(version=1, mode='verity', image='/boot/site-base.verity',
            descriptor='/boot/site-base.root', cache_blocks=8, heap_bytes=65536,
            transition=transition)
        wire = boot.render_boot_transition(policy, checked)
        self.assertEqual(len(wire), 2192)
        values = struct.unpack('>8sII32sIIQQQ', wire[:80])
        self.assertEqual(values, (b'5BSDBOOT', 1, 2192,
            bytes.fromhex(image.file_hash(descriptor)), 2, 1, 64, 131072, 1048576))
        for start, end, expected in ((80,1104,transition['transport_device']),
                (1104,2128,policy['image']), (2128,2192,transition['provider'])):
            field = wire[start:end]
            self.assertEqual(field, expected.encode() + bytes(len(field)-len(expected)))
        for change in ({'version': True}, {'extra': 1}, {'workers': 0},
                {'workers': 2**32}, {'workers': True}, {'cache_blocks': -1},
                {'window_bytes': 0}, {'buffer_bytes': 2**63},
                {'provider': '../root'}, {'provider': 'x'*64},
                {'provider': 'root\n.ask'}, {'transport_fs': 'nfs'},
                {'transport_fs': []}, {'transport_device': '/dev/../disk'},
                {'transport_device': '/dev//disk'}, {'transport_device': '/dev/a b'},
                {'transport_device': '/dev/'+'x'*1024}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                boot.render_boot_policy(dict(policy, transition=dict(transition, **change)), checked)
        with self.assertRaisesRegex(ValueError, 'checked descriptor'):
            boot.render_boot_transition(policy, dict(checked, verity={}))
        zfs = boot.render_boot_transition(dict(policy, transition=dict(transition,
            transport_fs='zfs', transport_device='pool/boot/generation')), checked)
        self.assertEqual(struct.unpack_from('>I', zfs, 52)[0], 2)
        out = self.base / 'transition-stage'
        report = boot.stage(self.image, self.archive, self.receipt_path, out,
            boot_policy=policy, signing=signing, efi=efi,
            verity_image=combined, verity_descriptor=descriptor)
        artifact = report['root_transition']
        self.assertEqual(Path(report['file_payloads'][artifact['path']]['path']).read_bytes(), wire)
        self.assertIn('root-transition.bin sha256='+artifact['sha256'],
                      (out/'payloads/manifest').read_text())
        self.assertTrue(artifact['manifest_signed'])
        self.assertFalse(artifact['loader_consumed'])
        self.assertFalse(artifact['kernel_admission_enabled'])
        self.assertFalse(artifact['target_resource_limits_verified'])
        self.assertEqual(json.loads((out/'stage.json').read_text())['root_transition'], artifact)
        if efi is not None:
            self.assertEqual(report['efi_loader']['build_binding']['root_transition_version'], 1)
            self.assertTrue(report['efi_loader']['signature_verified'])
            old_record = json.loads(efi['build_receipt'].read_bytes())
            old_record.pop('root_transition_version')
            old_path = self.base/'undeclared-loader.json'
            old_path.write_text(json.dumps(old_record))
            with patch.object(boot, 'sign_loader_manifest') as manifest_signer, \
                    patch.object(boot, 'sign_efi_loader') as efi_signer:
                with self.assertRaisesRegex(ValueError, 'does not declare required'):
                    boot.stage(self.image, self.archive, self.receipt_path,
                        self.base/'unsupported-transition', boot_policy=policy,
                        signing=signing, verity_image=combined, verity_descriptor=descriptor,
                        efi=dict(efi, build_receipt=old_path, build_sha256=image.file_hash(old_path)))
                manifest_signer.assert_not_called()
                efi_signer.assert_not_called()
            self.assertFalse((self.base/'unsupported-transition/stage.json').exists())


    def test_disk_policy_derives_descriptor_identity_from_checked_artifacts(self):
        combined, descriptor = self.verified_artifacts()
        report = boot.verify(self.image, self.archive, self.receipt_path,
            verity_image=combined, verity_descriptor=descriptor)
        policy = dict(version=1, mode='verity', image='/boot/selected.img',
            descriptor='/boot/selected.desc', cache_blocks=8, heap_bytes=65536)
        payload = boot.render_boot_policy(policy, report).decode('ascii')
        policy_file = self.base/'disk-policy.json'
        policy_file.write_text(json.dumps(policy))
        checked = subprocess.run([sys.executable, '-B', str(backend/'generation_boot.py'),
            '--image', str(self.image), '--boot-archive', str(self.archive),
            '--image-receipt', str(self.receipt_path), '--verity-image', str(combined),
            '--verity-descriptor', str(descriptor), '--boot-policy', str(policy_file)],
            check=True, text=True, capture_output=True, timeout=10)
        contract = json.loads(checked.stdout)['startup_contract']
        self.assertEqual(contract['payload'], payload)
        self.assertFalse(contract['signed'])
        self.assertFalse(contract['transport_paths_bound'])
        self.assertFalse(contract['startup_integration_verified'])
        self.assertIn('descriptor_sha256="'+image.file_hash(descriptor)+'"', payload)
        self.assertIn('cache_blocks="8", heap_bytes="65536"', payload)
        with self.assertRaisesRegex(ValueError, 'checked generation artifacts'):
            boot.render_boot_policy(policy)
        for change in ({'image':'/boot/bad path'}, {'descriptor':'/boot/../root'},
                       {'descriptor':'/boot/selected.img'}, {'cache_blocks':True},
                       {'heap_bytes':0}, {'heap_bytes':2**63}, {'descriptor_sha256':'0'*64}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                boot.render_boot_policy(dict(policy, **change), report)
        out = self.base/'disk-policy-missing-artifacts'
        with self.assertRaises(ValueError):
            boot.stage(self.image, self.archive, self.receipt_path, out, boot_policy=policy)
        self.assertFalse(out.exists())

    def test_disk_stage_binds_checked_artifacts_policy_and_signed_manifest(self):
        combined, descriptor = self.verified_artifacts()
        policy = dict(version=1, mode='verity', image='/boot/base.verity',
            descriptor='/boot/base.root', cache_blocks=8, heap_bytes=65536)
        out = self.base/'disk-stage'
        signing = self.signing_inputs()
        with patch.object(boot, 'verify', wraps=boot.verify) as verifier:
            report = boot.stage(self.image, self.archive, self.receipt_path, out,
                generated={}, signing=signing, boot_policy=policy,
                verity_image=combined, verity_descriptor=descriptor)
        self.assertEqual(verifier.call_count, 2)  # Initial validation + final input recheck.
        manifest = (out/'payloads/manifest').read_text()
        for logical, original in ((policy['image'], combined), (policy['descriptor'], descriptor)):
            binding = report['file_payloads'][logical]
            self.assertEqual(Path(binding['path']).read_bytes(), original.read_bytes())
            self.assertIn(logical.removeprefix('/boot/')+' sha256='+binding['sha256'], manifest)
        self.assertEqual(json.loads((out/'stage.json').read_text()), report)
        contract = report['startup_contract']
        self.assertTrue(contract['staged_paths_bound'])
        self.assertFalse(contract['transport_paths_bound'])
        self.assertFalse(contract['startup_integration_verified'])
        self.assertEqual(contract['descriptor_sha256'], image.file_hash(descriptor))
        self.assertIn('boot-policy.lua sha256='+contract['sha256'], manifest)
        self.assertEqual(report['root_image_binding']['path'], policy['image'])
        self.assertEqual(report['root_image_binding']['sha256'], image.file_hash(combined))
        self.assertEqual(report['root_image_binding']['size'], combined.stat().st_size)
        self.assertTrue(report['manifest_signing']['signature_verified'])
        for field in ('generation_authenticated', 'boot_verified', 'activation_authorized'):
            self.assertFalse(report[field])

        policy_file, generated_file = self.base/'stage-policy.json', self.base/'generated.json'
        policy_file.write_text(json.dumps(policy)); generated_file.write_text('{}')
        cli = subprocess.run([sys.executable, '-B', str(backend/'generation_boot.py'),
            '--image', str(self.image), '--boot-archive', str(self.archive),
            '--image-receipt', str(self.receipt_path), '--verity-image', str(combined),
            '--verity-descriptor', str(descriptor), '--boot-policy', str(policy_file),
            '--generated', str(generated_file), '--output', str(self.base/'disk-cli-stage'),
            '--signing-key', str(signing['key']), '--signing-certificate', str(signing['certificate']),
            '--openssl', str(signing['openssl'])], check=True, text=True, capture_output=True, timeout=10)
        cli_report = json.loads(cli.stdout)
        self.assertEqual(json.loads((self.base/'disk-cli-stage/stage.json').read_text()), cli_report)
        self.assertTrue(cli_report['startup_contract']['staged_paths_bound'])
        self.assertTrue(cli_report['manifest_signing']['signature_verified'])
        self.assertEqual(cli_report['root_image_binding'], report['root_image_binding'])

    def test_disk_stage_rejects_conflicting_paths_and_changed_descriptor(self):
        combined, descriptor = self.verified_artifacts()
        policy = dict(version=1, mode='verity', image='/boot/base.verity',
            descriptor='/boot/base.root', cache_blocks=8, heap_bytes=65536)
        for index, change in enumerate(({'image': '/boot/kernel'},
                {'descriptor': boot.BOOT_POLICY_PATH}, {'image': '/boot/manifest'})):
            out = self.base/('conflict-'+str(index))
            with self.subTest(change=change), self.assertRaises(ValueError):
                boot.stage(self.image, self.archive, self.receipt_path, out,
                    boot_policy=dict(policy, **change), verity_image=combined, verity_descriptor=descriptor)
            self.assertFalse(out.exists())
        out = self.base/'different-root-path'
        with self.assertRaisesRegex(ValueError, 'root path differs'):
            boot.stage(self.image, self.archive, self.receipt_path, out,
                boot_policy=policy, root_path='/boot/other',
                verity_image=combined, verity_descriptor=descriptor)
        self.assertFalse(out.exists())
        render = boot.render_boot_policy
        def change_after_verification(*args):
            payload = render(*args)
            wire = descriptor.read_bytes()
            descriptor.write_bytes(wire[:-1]+bytes([wire[-1]^1]))
            return payload
        out = self.base/'changed-after-check'
        with patch.object(boot, 'render_boot_policy', side_effect=change_after_verification):
            with self.assertRaisesRegex(ValueError, 'differs from binding'):
                boot.stage(self.image, self.archive, self.receipt_path, out,
                    boot_policy=policy, signing=self.signing_inputs(),
                    verity_image=combined, verity_descriptor=descriptor)
        self.assertFalse((out/'payloads/manifest.sig').exists())

    def test_verity_inputs_reject_partial_mismatched_or_mutable_selection(self):
        combined, descriptor = self.verified_artifacts()
        with self.assertRaisesRegex(ValueError, 'both image and descriptor'):
            boot.verify(self.image, self.archive, self.receipt_path, verity_image=combined)
        original = descriptor.read_bytes()
        descriptor.write_bytes(original[:-1]+bytes([original[-1]^1]))
        with self.assertRaises(ValueError):
            boot.verify(self.image, self.archive, self.receipt_path,
                verity_image=combined, verity_descriptor=descriptor)
        descriptor.write_bytes(original)
        self.receipt['partition_content']='ordinary'
        self.receipt_path.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(ValueError, 'immutable base'):
            boot.verify(self.image, self.archive, self.receipt_path,
                verity_image=combined, verity_descriptor=descriptor)

    def test_verity_inputs_without_receipt_are_rejected(self):
        self.verify()
        with self.assertRaisesRegex(ValueError, 'without a matching image receipt'):
            boot.verify(self.image, self.archive, self.receipt_path,
                verity_image=self.image, verity_descriptor=self.image)

    def test_receipt_replaced_between_verification_and_staging(self):
        self.verify()
        original = self.receipt_path.read_bytes()
        replacement = copy.deepcopy(self.receipt)
        replacement['boot_archive']['entries']['/boot']['mode'] = 0o777
        real_verify = boot.verify
        calls = 0

        def replace_after_verification(*args):
            nonlocal calls
            calls += 1
            if calls > 1:
                self.receipt_path.write_bytes(original)
            report = real_verify(*args)
            if calls == 1:
                self.receipt_path.write_text(json.dumps(replacement))
            return report

        output = self.base / 'replaced-receipt'
        with patch.object(boot, 'verify', side_effect=replace_after_verification):
            with self.assertRaisesRegex(ValueError, 'receipt changed before staging'):
                boot.stage(self.image, self.archive, self.receipt_path, output)
        self.assertFalse(output.exists())

    def test_archive_namespace_replaced_during_staging(self):
        self.verify()
        original = self.archive.read_bytes()
        with tarfile.open(self.archive) as archive:
            members = [(m, archive.extractfile(m).read() if m.isfile() else None)
                       for m in archive]
        variants = {
            'missing-directory': members[1:],
            'missing-last-object': members[:-1],
            'duplicate-directory': [members[0]] + members,
            'reordered': list(reversed(members)),
        }
        real_verify = boot.verify
        for label, selected in variants.items():
            with self.subTest(label=label):
                self.archive.write_bytes(original)
                replacement = io.BytesIO()
                with tarfile.open(fileobj=replacement, mode='w', format=tarfile.PAX_FORMAT) as archive:
                    for member, data in selected:
                        archive.addfile(member, None if data is None else io.BytesIO(data))
                calls = 0

                def replace_after_verification(*args):
                    nonlocal calls
                    calls += 1
                    if calls > 1:
                        self.archive.write_bytes(original)
                    report = real_verify(*args)
                    if calls == 1:
                        self.archive.write_bytes(replacement.getvalue())
                    return report

                output = self.base / label
                with patch.object(boot, 'verify', side_effect=replace_after_verification):
                    with self.assertRaisesRegex(ValueError, 'boot archive namespace changed during staging'):
                        boot.stage(self.image, self.archive, self.receipt_path, output)
                self.assertFalse((output / 'stage.json').exists())
                self.assertFalse((output / 'filesystem.mtree').exists())

    def test_partition_base_binding(self):
        self.receipt.update(scope='trusted-builder-partition-image', partition_content='immutable',
            partition_boundary=None, expected_observation_sha256='b' * 64,
            readback_observation_sha256='b' * 64)
        self.verify()
        for key, value in (('partition_content', 'ordinary'), ('partition_boundary', '/state'),
                           ('expected_observation_sha256', 'c' * 64)):
            original = self.receipt[key]; self.receipt[key] = value
            with self.assertRaises(ValueError):
                self.verify()
            self.receipt[key] = original

    def rewrite(self, change):
        with tarfile.open(self.archive) as archive:
            members = [(m, archive.extractfile(m).read() if m.isfile() else None) for m in archive]
        change(members)
        with tarfile.open(self.archive, 'w', format=tarfile.PAX_FORMAT) as archive:
            for m, data in members: archive.addfile(m, None if data is None else io.BytesIO(data))
        self.receipt['boot_archive'].update(archive_bytes=self.archive.stat().st_size,
                                          archive_sha256=image.file_hash(self.archive))

    def test_stage_preserves_internal_links_and_escapes_paths(self):
        os.link(self.root / 'boot/kernel', self.root / 'boot/kernel alias')
        self.archive.unlink()
        observed = image.construction.generation.scan(self.root)
        self.receipt['boot_archive'] = image.boot_archive(self.root, observed, self.archive)
        self.receipt['source_observation_sha256'] = image.construction.digest(observed)
        self.receipt['readback_observation_sha256'] = image.construction.digest(observed)
        self.verify()
        output = self.base / 'stage with spaces'
        result = boot.stage(self.image, self.archive, self.receipt_path, output)
        expected = result['expected_observations']
        self.assertEqual(expected['/boot/kernel']['hardlinks'], ['/boot/kernel', '/boot/kernel alias'])
        self.assertNotIn('/alias', expected)
        files = list((output / 'payloads').iterdir())
        self.assertEqual(len(files), 2)
        payloads = result['file_payloads']
        self.assertEqual(set(payloads), {'/boot/kernel', '/boot/kernel alias'})
        for name, binding in payloads.items():
            path = Path(binding['path'])
            self.assertEqual(path.parent, output / 'payloads')
            self.assertEqual(path.read_bytes(), (self.root / name.lstrip('/')).read_bytes())
            self.assertEqual(binding['size'], path.stat().st_size)
            self.assertEqual(binding['sha256'], image.file_hash(path))
            self.assertEqual(result['payloads_sha256'][str(path)], binding['sha256'])
        self.assertEqual(json.loads((output / 'stage.json').read_text())['file_payloads'], payloads)
        self.assertEqual(files[0].stat().st_ino, files[1].stat().st_ino)
        self.assertIn(r'./boot/kernel\040alias', (output / 'filesystem.mtree').read_text())
        self.assertFalse((output / 'boot').exists())
        self.assertFalse(result['filesystem_readback_verified'])
        with self.assertRaisesRegex(ValueError, 'must be new'):
            boot.stage(self.image, self.archive, self.receipt_path, output)

    def generated_input(self):
        source = self.base / 'config'
        source.write_bytes(b'console="comconsole"\n')
        item = dict(type='file', uid=0, gid=0, mode=0o444, flags_set=0,
                    mtime=0, mtime_nsec=0, size=source.stat().st_size,
                    sha256=image.file_hash(source))
        return {'/boot/loader.conf': {'source': str(source), 'observation': item}}

    def generated_root(self, name='/boot/selected-volume.ufs'):
        generated = self.generated_input()
        item = dict(type='file', uid=0, gid=0, mode=0o444, flags_set=0,
                    mtime=0, mtime_nsec=0, size=self.image.stat().st_size,
                    sha256=image.file_hash(self.image))
        generated[name] = dict(source=str(self.image), observation=item)
        return generated

    def test_root_image_selection_is_bound_to_receipt(self):
        self.verify()
        name = '/boot/custom-root.image'
        generated = self.generated_root(name)
        report = boot.stage(self.image, self.archive, self.receipt_path,
                            self.base / 'root-bound', generated=generated, root_path=name)
        self.assertEqual(report['root_image_binding']['path'], name)
        self.assertEqual(report['root_image_binding']['sha256'], self.receipt['image_sha256'])
        for i, selection in enumerate(('/boot/absent', '/boot/link', '/boot/kernel', '/boot/loader.conf')):
            out = self.base / ('invalid-root-' + str(i))
            with self.assertRaises(ValueError):
                boot.stage(self.image, self.archive, self.receipt_path, out,
                           generated=generated, root_path=selection)
            self.assertFalse(out.exists())
        # A self-consistent binding for a different image must still reject.
        other = self.base / 'other.ufs'
        data = self.image.read_bytes()
        other.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        wrong = copy.deepcopy(generated)
        wrong[name]['source'] = str(other)
        wrong[name]['observation']['sha256'] = image.file_hash(other)
        with self.assertRaisesRegex(ValueError, 'differs from the verified image'):
            boot.stage(self.image, self.archive, self.receipt_path,
                       self.base / 'different-image', generated=wrong, root_path=name)
        self.assertFalse((self.base / 'different-image').exists())
        with self.assertRaisesRegex(ValueError, 'explicit root image'):
            boot.stage(self.image, self.archive, self.receipt_path,
                       self.base / 'missing-root', generated=generated, media={})
        self.assertFalse((self.base / 'missing-root').exists())

    def test_signing_rejects_reserved_directory_or_directory_alias(self):
        empty = self.root / 'boot/empty'
        empty.mkdir()
        for name in ('manifest', 'manifest.sig', 'manifest.certs'):
            for alias in (False, True):
                with self.subTest(name=name, alias=alias):
                    target = self.root / 'boot' / name
                    if alias:
                        target.symlink_to('/boot/empty')
                    else:
                        target.mkdir()
                    try:
                        self.archive.unlink()
                        observed = image.construction.generation.scan(self.root)
                        self.receipt['boot_archive'] = image.boot_archive(
                            self.root, observed, self.archive)
                        self.receipt['source_observation_sha256'] = image.construction.digest(observed)
                        self.receipt['readback_observation_sha256'] = image.construction.digest(observed)
                        self.verify()
                        out = self.base / (name + '-' + str(alias))
                        artifacts = {key: b'synthetic signature artifact' for key in
                                     ('manifest', 'manifest.sig', 'manifest.certs')}
                        with patch.object(boot, 'sign_loader_manifest',
                                          return_value=(artifacts, {})) as signer:
                            with self.assertRaisesRegex(ValueError, 'reserved signing artifact'):
                                boot.stage(self.image, self.archive, self.receipt_path,
                                           out, generated={}, signing={}, boot_policy={'version': 1, 'mode': 'preloaded'})
                            signer.assert_not_called()
                        self.assertFalse(out.exists())
                    finally:
                        target.unlink() if alias else target.rmdir()

    def signing_inputs(self, name='sign'):
        key, cert = self.base / (name + '.key'), self.base / (name + '.pem')
        subprocess.run(['/usr/bin/openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048',
            '-noenc', '-keyout', str(key), '-out', str(cert), '-days', '1',
            '-subj', '/CN=boot manifest test'], check=True, capture_output=True)
        key.chmod(0o600)
        return dict(key=key, certificate=cert, openssl=Path('/usr/bin/openssl'))

    def test_signed_stage_requires_explicit_startup_policy(self):
        out = self.base / 'missing-policy'
        with self.assertRaisesRegex(ValueError, 'explicit boot policy'):
            boot.stage(self.image, self.archive, self.receipt_path, out, generated={}, signing={})
        self.assertFalse(out.exists())

    def test_explicit_startup_contract_is_signed_and_retained(self):
        self.verify()
        out = self.base / 'contract-stage'
        policy = {'version': 1, 'mode': 'preloaded'}
        report = boot.stage(self.image, self.archive, self.receipt_path, out,
                            generated={}, signing=self.signing_inputs(), boot_policy=policy)
        self.assertEqual(json.loads((out/'stage.json').read_text()), report)
        contract = report['startup_contract']
        binding = report['file_payloads'][contract['path']]
        self.assertEqual(Path(binding['path']).read_bytes(), boot.render_boot_policy(policy))
        self.assertEqual(binding['sha256'], contract['sha256'])
        self.assertEqual(image.file_hash(Path(binding['path'])), contract['sha256'])
        self.assertIn('boot-policy.lua sha256=' + contract['sha256'],
                      (out / 'payloads/manifest').read_text())
        self.assertTrue(report['manifest_signing']['signature_verified'])
        self.assertFalse(contract['startup_integration_verified'])
        self.assertEqual(report['generated_inputs'][contract['path']]['source'], binding['path'])

    def test_startup_contract_rejects_implicit_or_unsupported_policy(self):
        invalid = [None, {}, {'version': True, 'mode': 'preloaded'},
                   {'version': 2, 'mode': 'preloaded'},
                   {'version': 1, 'mode': 'verity'},
                   {'version': 1, 'mode': 'preloaded', 'image': '/boot/image'}]
        for policy in invalid:
            with self.subTest(policy=policy), self.assertRaisesRegex(ValueError, 'unsupported boot policy'):
                boot.render_boot_policy(policy)
        self.verify()
        out = self.base / 'contract-collision'
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            boot.stage(self.image, self.archive, self.receipt_path, out,
                       generated={boot.BOOT_POLICY_PATH: {}},
                       boot_policy={'version': 1, 'mode': 'preloaded'})
        self.assertFalse(out.exists())

    def test_signed_stage_includes_verified_manifest_artifacts(self):
        self.verify()
        out = self.base / 'signed-stage'
        report = boot.stage(self.image, self.archive, self.receipt_path, out,
                            generated=self.generated_input(), signing=self.signing_inputs(),
                            boot_policy={'version': 1, 'mode': 'preloaded'})
        self.assertTrue(report['loader_manifest_signed'])
        self.assertTrue(report['manifest_signing']['signature_verified'])
        self.assertFalse(report['manifest_signing']['release_authorization_verified'])
        self.assertFalse(report['generation_authenticated'])
        for name in ('manifest', 'manifest.sig', 'manifest.certs'):
            binding = report['file_payloads']['/boot/' + name]
            self.assertEqual(image.file_hash(Path(binding['path'])), binding['sha256'])
            self.assertIn('./boot/' + name + ' type=file', (out / 'filesystem.mtree').read_text())
        self.assertEqual((out / 'payloads/manifest').read_bytes(),
                         (out / 'loader.manifest.unsigned').read_bytes())
        self.assertEqual(list(out.glob('manifest-sign-*')), [])
        # Verify the serialized artifacts, then prove altered manifest bytes fail.
        import base64
        armor = (out / 'payloads/manifest.sig').read_bytes().splitlines()
        self.assertEqual(armor[0], b'-----BEGIN SIGNATURE-----')
        self.assertEqual(armor[-1], b'-----END SIGNATURE-----')
        signature = self.base / 'serialized.sig'
        signature.write_bytes(base64.b64decode(b''.join(armor[1:-1]), validate=True))
        public = self.base / 'public.pem'
        public.write_bytes(subprocess.check_output(['/usr/bin/openssl', 'x509', '-in',
            str(out / 'payloads/manifest.certs'), '-pubkey', '-noout']))
        command = ['/usr/bin/openssl', 'dgst', '-sha256', '-verify', str(public),
                   '-signature', str(signature)]
        subprocess.run(command + [str(out / 'payloads/manifest')], check=True, capture_output=True)
        changed = self.base / 'tampered.manifest'
        changed.write_bytes((out / 'payloads/manifest').read_bytes() + b'altered\n')
        result = subprocess.run(command + [str(changed)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_efi_signing_artifact_and_inventory_refusal(self):
        loader = Path(os.environ.get('BSD_BUILD_EFI_FIXTURE', '/boot/loader.efi'))
        signer = Path(os.environ.get('BSD_BUILD_UEFISIGN', '/usr/sbin/uefisign'))
        if not loader.is_file() or not signer.is_file():
            self.skipTest('explicit or installed EFI signing fixtures unavailable')
        signing = self.signing_inputs()
        binding = dict(path=str(loader), size=loader.stat().st_size, sha256=image.file_hash(loader))
        out = self.base / 'efi'
        report = boot.sign_efi_loader(binding, signing, signer, signing['certificate'], out)
        self.assertEqual(image.file_hash(out / 'unsigned.efi'), binding['sha256'])
        self.assertEqual(image.file_hash(out / 'loader.efi'), report['signed_sha256'])
        self.assertFalse(report['signature_verified'])
        self.assertFalse(report['firmware_verified'])
        with self.assertRaisesRegex(ValueError, 'differs from boot inventory'):
            boot.sign_efi_loader(dict(binding, sha256='0' * 64), signing, signer,
                                 signing['certificate'], self.base / 'wrong-efi')
        self.assertFalse((self.base / 'wrong-efi/loader.efi').exists())

    def test_efi_signer_orders_sections_by_file_offset(self):
        import hashlib
        import re
        import struct
        loader = Path(os.environ.get('BSD_BUILD_EFI_FIXTURE', '/boot/loader.efi'))
        signer = Path(os.environ.get('BSD_BUILD_UEFISIGN', '/usr/sbin/uefisign'))
        if not loader.is_file() or not signer.is_file():
            self.skipTest('explicit or installed EFI signing fixtures unavailable')
        data = bytearray(loader.read_bytes())
        pe = struct.unpack_from('<I', data, 60)[0]
        self.assertEqual(data[pe:pe+4], b'PE\0\0')
        count = struct.unpack_from('<H', data, pe+6)[0]
        optional = pe+24
        optional_size = struct.unpack_from('<H', data, pe+20)[0]
        magic = struct.unpack_from('<H', data, optional)[0]
        self.assertIn(magic, (0x10b, 0x20b))
        headers = struct.unpack_from('<I', data, optional+60)[0]
        checksum = optional+64
        security = optional+(112 if magic==0x20b else 96)+4*8
        self.assertEqual(struct.unpack_from('<II', data, security), (0, 0))
        table = optional+optional_size
        rows = [bytes(data[table+40*i:table+40*(i+1)]) for i in range(count)]
        self.assertGreater(sum(struct.unpack_from('<I', r, 16)[0]>0 for r in rows), 1)
        # Reorder the section table, preserving section bytes. Header bytes
        # participate in the expected digest in their newly written order.
        rows.reverse()
        data[table:table+40*count] = b''.join(rows)
        sections = sorted((struct.unpack_from('<I', r, 20)[0],
                           struct.unpack_from('<I', r, 16)[0]) for r in rows
                          if struct.unpack_from('<I', r, 16)[0])
        digest = hashlib.sha256(data[:checksum]+data[checksum+4:security]+data[security+8:headers])
        total = headers
        for offset, size in sections:
            self.assertLessEqual(offset+size, len(data))
            digest.update(data[offset:offset+size]); total += size
        self.assertLessEqual(total, len(data))
        digest.update(data[total:])
        source = self.base/'reordered.efi'; source.write_bytes(data)
        signing = self.signing_inputs()
        result = subprocess.run([str(signer), '-v', '-k', signing['key'],
            '-c', signing['certificate'], '-o', str(self.base/'reordered-signed.efi'),
            str(source)], capture_output=True, text=True, check=True, timeout=60)
        hashes = re.findall(r'computed SHA256 digest ([0-9a-f]{64});', result.stdout)
        self.assertEqual(hashes, [digest.hexdigest()])

    def loader_record(self, loader):
        selected = os.environ.get('BSD_BUILD_LOADER_RECEIPT')
        if selected:
            path = Path(selected)
        else:
            # A synthetic record tests consistency only, never build provenance.
            path = self.base / 'loader-build-fixture.json'
            path.write_text(json.dumps(dict(schema='org.5bsd.loader-build.v1', result='PASS',
                scope='trusted-builder-loader-compilation', firmware_db_manifest_fallback=False,
                loader=dict(size=loader.stat().st_size, sha256=image.file_hash(loader)),
                anchors=dict(sha256='a'*64), inputs_sha256='b'*64,
                generated_trust_header_sha256='c'*64,
                manifest_verifier=dict(sha256='d'*64, trust_header_sha256='c'*64))))
        return dict(build_receipt=path, build_sha256=image.file_hash(path))

    def test_loader_build_record_binding(self):
        loader = self.base / 'loader-fixture'; loader.write_bytes(b'fixture loader bytes')
        # This test uses deliberately synthetic records; external real records
        # are exercised by the staging test below with a real EFI executable.
        with patch.dict(os.environ, {}, clear=True):
            selected = self.loader_record(loader)
        binding = dict(size=loader.stat().st_size, sha256=image.file_hash(loader))
        raw, result = boot.bind_loader_build(binding, selected['build_receipt'], selected['build_sha256'])
        self.assertTrue(result['staged_artifact_bound'])
        self.assertFalse(result['source_attestation_verified'])
        self.assertFalse(result['release_authorization_verified'])
        with self.assertRaisesRegex(ValueError, 'differs from selected SHA256'):
            boot.bind_loader_build(binding, selected['build_receipt'], '0'*64)
        with self.assertRaisesRegex(ValueError, 'differs from selected build record'):
            boot.bind_loader_build(dict(binding, sha256='0'*64), selected['build_receipt'], selected['build_sha256'])
        with self.assertRaisesRegex(ValueError, 'differs from selected build record'):
            boot.bind_loader_build(dict(binding, size=binding['size']+1), selected['build_receipt'], selected['build_sha256'])
        record = json.loads(raw)
        # A missing declaration remains usable for old contracts, not new ones.
        self.assertEqual(result['root_transition_version'], 0)
        with self.assertRaisesRegex(ValueError, 'does not declare required'):
            boot.bind_loader_build(binding, selected['build_receipt'], selected['build_sha256'],
                                   required_transition_version=1)
        capable = dict(record, root_transition_version=1)
        selected['build_receipt'].write_text(json.dumps(capable))
        _, accepted = boot.bind_loader_build(binding, selected['build_receipt'],
            image.file_hash(selected['build_receipt']), required_transition_version=1)
        self.assertEqual(accepted['root_transition_version'], 1)
        for unsupported in (True, -1, 2, '1', None):
            selected['build_receipt'].write_text(json.dumps(dict(record, root_transition_version=unsupported)))
            with self.assertRaisesRegex(ValueError, 'unsupported loader root-transition'):
                boot.bind_loader_build(binding, selected['build_receipt'],
                    image.file_hash(selected['build_receipt']), required_transition_version=1)
        for mutate in (lambda r: r.update(firmware_db_manifest_fallback=True),
                       lambda r: r.update(result='FAIL'),
                       lambda r: r.update(schema='unknown'),
                       lambda r: r['loader'].update(size=True),
                       lambda r: r.update(anchors={}),
                       lambda r: r.update(inputs_sha256='bad')):
            changed = copy.deepcopy(record); mutate(changed)
            selected['build_receipt'].write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                boot.bind_loader_build(binding, selected['build_receipt'], image.file_hash(selected['build_receipt']))
        selected['build_receipt'].write_bytes(raw+b' ')
        with self.assertRaisesRegex(ValueError, 'differs from selected SHA256'):
            boot.bind_loader_build(binding, selected['build_receipt'], selected['build_sha256'])

    def test_separate_efi_credentials_and_public_input(self):
        required = ('BSD_BUILD_LOADER_RECEIPT', 'BSD_BUILD_MANIFEST_VERIFIER',
                    'BSD_BUILD_GENERATION_KEY', 'BSD_BUILD_GENERATION_CERTIFICATE',
                    'BSD_BUILD_AUTHENTICODE_VERIFIER')
        if any(not os.environ.get(name) for name in required):
            self.skipTest('real paired loader/verifier and matching generation credentials required')
        verifier = Path(os.environ['BSD_BUILD_MANIFEST_VERIFIER'])
        loader = Path(os.environ.get('BSD_BUILD_EFI_FIXTURE', '/boot/loader.efi'))
        signer = Path(os.environ.get('BSD_BUILD_UEFISIGN', '/usr/sbin/uefisign'))
        if not loader.is_file() or not signer.is_file():
            self.skipTest('explicit or installed EFI signing fixtures unavailable')
        (self.root / 'boot/loader.efi').write_bytes(loader.read_bytes())
        self.archive.unlink()
        observed = image.construction.generation.scan(self.root)
        self.receipt['boot_archive'] = image.boot_archive(self.root, observed, self.archive)
        self.receipt['source_observation_sha256'] = image.construction.digest(observed)
        self.receipt['readback_observation_sha256'] = image.construction.digest(observed)
        self.verify()
        manifest = dict(key=Path(os.environ['BSD_BUILD_GENERATION_KEY']),
                        certificate=Path(os.environ['BSD_BUILD_GENERATION_CERTIFICATE']),
                        openssl=Path('/usr/bin/openssl'))
        firmware = self.signing_inputs('firmware')
        out = self.base / 'separate-stage'
        report = boot.stage(self.image, self.archive, self.receipt_path, out,
            generated=self.generated_input(), signing=manifest,
            boot_policy={'version': 1, 'mode': 'preloaded'},
            efi=dict(path='/boot/loader.efi', signer=signer,
                     signature_verifier=Path(os.environ['BSD_BUILD_AUTHENTICODE_VERIFIER']),
                     key=firmware['key'], certificate=firmware['certificate'],
                     manifest_verifier=verifier, **self.loader_record(loader)))
        self.assertEqual(report['efi_loader']['credential_selection'], 'explicit-efi')
        self.assertTrue(report['efi_loader']['build_binding']['staged_artifact_bound'])
        self.assertTrue(report['manifest_signing']['compiled_generation_trust']['compiled_generation_trust_verified'])
        self.assertFalse(report['manifest_signing']['compiled_generation_trust']['firmware_revocations_checked'])
        self.assertEqual(image.file_hash(out / 'efi/loader-build.json'),
                         report['efi_loader']['build_binding']['receipt_sha256'])
        self.assertEqual(report['efi_loader']['certificate_sha256'], image.file_hash(firmware['certificate']))
        self.assertNotEqual(report['efi_loader']['certificate_sha256'],
                            report['manifest_signing']['certificate_sha256'])
        self.assertEqual((out / 'efi/certificate.pem').read_bytes(), firmware['certificate'].read_bytes())
        self.assertEqual((out / 'payloads/manifest.certs').read_bytes(), manifest['certificate'].read_bytes())
        self.assertFalse(report['efi_loader']['firmware_verified'])
        self.assertTrue(report['efi_loader']['signature_verified'])
        self.assertFalse(report['efi_loader']['authenticode_verification']['revocations_checked'])
        real_sign = boot.sign_efi_loader
        def corrupt_signature(*args, **kwargs):
            result = real_sign(*args, **kwargs)
            signed_path = Path(args[-1]) / 'loader.efi'
            data = bytearray(signed_path.read_bytes())
            data[-16] ^= 1
            signed_path.write_bytes(data)
            # Update the consistency digest so rejection must be cryptographic.
            result['signed_sha256'] = image.file_hash(signed_path)
            return result
        with patch.object(boot, 'sign_efi_loader', side_effect=corrupt_signature), \
                patch.object(boot, 'assemble_media') as media_builder:
            with self.assertRaisesRegex(ValueError, 'Authenticode verification rejected'):
                boot.stage(self.image, self.archive, self.receipt_path,
                    self.base / 'invalid-signature', generated=self.generated_root(),
                    root_path='/boot/selected-volume.ufs',
                    signing=manifest, boot_policy={'version': 1, 'mode': 'preloaded'},
                    efi=dict(path='/boot/loader.efi', signer=signer,
                        signature_verifier=Path(os.environ['BSD_BUILD_AUTHENTICODE_VERIFIER']),
                        key=firmware['key'], certificate=firmware['certificate'],
                        manifest_verifier=verifier, **self.loader_record(loader)),
                    media={'deliberately': 'must not be reached'})
            media_builder.assert_not_called()
        self.assertFalse((self.base / 'invalid-signature/stage.json').exists())

        for case, extra in (('missing-build', {}),
                            ('wrong-build-pin', dict(self.loader_record(loader), build_sha256='0'*64))):
            with patch.object(boot, 'sign_loader_manifest') as manifest_signer, \
                    patch.object(boot, 'sign_efi_loader') as efi_signer:
                with self.assertRaises(ValueError):
                    boot.stage(self.image, self.archive, self.receipt_path, self.base / case,
                        generated=self.generated_input(), signing=manifest,
                        boot_policy={'version': 1, 'mode': 'preloaded'},
                        efi=dict(path='/boot/loader.efi', signer=signer,
                     signature_verifier=Path(os.environ['BSD_BUILD_AUTHENTICODE_VERIFIER']), manifest_verifier=verifier, **extra))
                manifest_signer.assert_not_called()
                efi_signer.assert_not_called()
            self.assertFalse((self.base / case / 'stage.json').exists())
        for case, signing_input, selected_verifier, message in (
                ('untrusted-generation', firmware, verifier, 'compiled generation trust rejected'),
                ('wrong-verifier', manifest, Path('/usr/bin/true'), 'differs from selected loader build')):
            with patch.object(boot, 'sign_efi_loader') as efi_signer:
                with self.assertRaisesRegex(ValueError, message):
                    boot.stage(self.image, self.archive, self.receipt_path, self.base / case,
                        generated=self.generated_input(), signing=signing_input,
                        boot_policy={'version': 1, 'mode': 'preloaded'},
                        efi=dict(path='/boot/loader.efi', signer=signer,
                     signature_verifier=Path(os.environ['BSD_BUILD_AUTHENTICODE_VERIFIER']),
                            manifest_verifier=selected_verifier, **self.loader_record(loader)))
                efi_signer.assert_not_called()
            self.assertFalse((self.base / case / 'stage.json').exists())
        mixed = self.base / 'mixed.pem'
        mixed.write_bytes(firmware['certificate'].read_bytes() + firmware['key'].read_bytes())
        binding = report['file_payloads']['/boot/loader.efi']
        with self.assertRaisesRegex(ValueError, 'certificate-only PEM'):
            boot.sign_efi_loader(binding, firmware, signer, mixed, self.base / 'rejected-efi')
        self.assertFalse((self.base / 'rejected-efi').exists())
        with self.assertRaises(subprocess.CalledProcessError):
            boot.sign_efi_loader(binding, manifest, signer, firmware['certificate'], self.base / 'mismatched-efi')

    def test_efi_signing_preserves_payload(self):
        import struct
        unsigned, signed = self.base / 'unsigned-pe', self.base / 'signed-pe'
        for machine, magic, directories in ((0x14c, 0x10b, 96),
                                            (0x8664, 0x20b, 112)):
            data = bytearray(512)
            data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 64)
            data[64:68] = b'PE\0\0'
            struct.pack_into('<H', data, 68, machine)
            struct.pack_into('<H', data, 84, directories + 40)
            struct.pack_into('<H', data, 88, magic)
            struct.pack_into('<H', data, 156, 10)
            struct.pack_into('<I', data, 88 + directories - 4, 5)
            unsigned.write_bytes(data)
            certificate = 88 + directories + 32
            result = data + bytes(16)
            struct.pack_into('<I', result, 152, 1234)
            struct.pack_into('<II', result, certificate, 512, 16)
            signed.write_bytes(result)
            # Synthetic envelope tests transformation only, never cryptography.
            self.assertTrue(boot.check_efi_signing_payload(unsigned, signed))
            for offset in (2, 68, 160, 300, 511):
                changed = bytearray(result); changed[offset] ^= 1
                signed.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, 'changed executable payload'):
                    boot.check_efi_signing_payload(unsigned, signed)
            for offset, length in ((504, 24), (512, 8), (512, 17)):
                changed = bytearray(result)
                struct.pack_into('<II', changed, certificate, offset, length)
                signed.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, 'must be appended'):
                    boot.check_efi_signing_payload(unsigned, signed)
            signed.write_bytes(result[:100])
            with self.assertRaisesRegex(ValueError, 'truncated signed EFI'):
                boot.check_efi_signing_payload(unsigned, signed)

    def test_efi_fallback_header_validation(self):
        import struct
        path = self.base / 'pe-fixture'
        def fixture(machine=0x8664, magic=0x20b, subsystem=10):
            data = bytearray(256)
            data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 64)
            data[64:68] = b'PE\0\0'
            struct.pack_into('<H', data, 68, machine)
            struct.pack_into('<H', data, 84, 112)
            struct.pack_into('<H', data, 88, magic)
            struct.pack_into('<H', data, 156, subsystem)
            return data
        for machine, magic, name in ((0x14c, 0x10b, 'BOOTIA32.EFI'),
                (0x8664, 0x20b, 'BOOTX64.EFI'), (0xaa64, 0x20b, 'BOOTAA64.EFI'),
                (0x5064, 0x20b, 'BOOTRISCV64.EFI')):
            path.write_bytes(fixture(machine, magic))
            self.assertEqual(boot.efi_fallback_name(path), name)
        bad = [b'MZ', fixture(0xffff), fixture(magic=0x10b), fixture(subsystem=11)]
        data = fixture(); struct.pack_into('<I', data, 60, 0xffffffff); bad.append(data)
        data = fixture(); struct.pack_into('<H', data, 84, 0xffff); bad.append(data)
        data = fixture(); data[64] = 0; bad.append(data)
        for data in bad:
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                boot.efi_fallback_name(path)

    def test_media_partitions_contain_exact_staged_images(self):
        self.check_media_partitions('preloaded')

    def test_disk_media_partitions_contain_exact_staged_images(self):
        self.check_media_partitions('verity')

    def test_loader_reads_preloaded_transport_files(self):
        self.check_media_partitions('preloaded', loader_readback=True)

    def test_loader_reads_disk_transport_files(self):
        self.check_media_partitions('verity', loader_readback=True)

    def check_media_partitions(self, mode, loader_readback=False):
        import struct
        makefs = os.environ.get('BSD_BUILD_MAKEFS')
        if not makefs:
            self.skipTest('media test requires explicit qualified BSD_BUILD_MAKEFS')
        construction_tests = backend.parents[1] / 'test/construction'
        if loader_readback and not (construction_tests / 'loader_ufs_readback.py').is_file():
            self.skipTest('native loader readback requires the matching source checkout')
        loader = Path(os.environ.get('BSD_BUILD_EFI_FIXTURE', '/boot/loader.efi'))
        signer = Path(os.environ.get('BSD_BUILD_UEFISIGN', '/usr/sbin/uefisign'))
        signing = self.signing_inputs()
        output = self.base / 'media-stage'
        root_path = '/boot/selected-volume.ufs'
        if mode == 'verity':
            combined, descriptor = self.verified_artifacts()
            # Synthetic root bytes exercise transport construction only. They
            # deliberately do not stand in for a bootable filesystem or OS.
            policy = dict(version=1, mode=mode, image=root_path,
                          descriptor='/boot/selected.root', cache_blocks=8,
                          heap_bytes=65536)
            inputs = dict(verity_image=combined, verity_descriptor=descriptor)
        else:
            self.verify()
            policy = dict(version=1, mode=mode)
            inputs = dict(generated=self.generated_root())
        report = boot.stage(self.image, self.archive, self.receipt_path, output,
                            signing=signing, boot_policy=policy,
                            root_path=root_path, **inputs)
        binding = dict(path=str(loader), size=loader.stat().st_size, sha256=image.file_hash(loader))
        report['efi_loader'] = boot.sign_efi_loader(binding, signing, signer,
            output / 'payloads/manifest.certs', output / 'efi')
        authenticode = os.environ.get('BSD_BUILD_AUTHENTICODE_VERIFIER')
        if not authenticode:
            self.skipTest('explicit independent Authenticode verifier required')
        report['efi_loader'].update(boot.verify_efi_signature(report['efi_loader'],
            Path(authenticode), signing['openssl'], output / 'efi'))
        fallback = boot.efi_fallback_name(loader)
        other_fallback = 'BOOTAA64.EFI' if fallback != 'BOOTAA64.EFI' else 'BOOTX64.EFI'
        options = dict(makefs=makefs, mkimg=os.environ.get('BSD_BUILD_MKIMG', '/usr/bin/mkimg'),
                       fallback_name=fallback, esp_mib=32, free_percent=5)
        with self.assertRaisesRegex(ValueError, 'does not match loader architecture'):
            boot.assemble_media(output, report, dict(options, fallback_name=other_fallback))
        self.assertFalse((output / 'media').exists())
        unbound = dict(report); unbound.pop('root_image_binding')
        with self.assertRaisesRegex(ValueError, 'receipt-bound root image'):
            boot.assemble_media(output, unbound, options)
        self.assertFalse((output / 'media').exists())
        if mode == 'verity':
            wrong = copy.deepcopy(report)
            wrong['root_image_binding']['sha256'] = report['image_sha256']
            with self.assertRaisesRegex(ValueError, 'receipt-bound root image'):
                boot.assemble_media(output, wrong, options)
            self.assertFalse((output / 'media').exists())
        result = boot.assemble_media(output, report, options)
        self.assertFalse(result['firmware_verified'])
        # Inspect GPT partition extents and compare payload bytes, independently
        # of the builder's recorded output digests and success status.
        with (output / 'media/disk.img').open('rb') as disk:
            disk.seek(512); header = disk.read(92)
            self.assertEqual(header[:8], b'EFI PART')
            table_lba = struct.unpack_from('<Q', header, 72)[0]
            entry_size = struct.unpack_from('<I', header, 84)[0]
            for index, name in enumerate(('esp.fat', 'boot.ufs')):
                disk.seek(table_lba * 512 + index * entry_size)
                entry = disk.read(entry_size)
                start, end = struct.unpack_from('<QQ', entry, 32)
                artifact = output / 'media' / name
                self.assertGreaterEqual((end - start + 1) * 512, artifact.stat().st_size)
                disk.seek(start * 512)
                with artifact.open('rb') as source:
                    while chunk := source.read(1048576):
                        self.assertEqual(disk.read(len(chunk)), chunk)
        if loader_readback:
            sys.path.insert(0, str(construction_tests))
            try:
                import loader_ufs_readback
                loader_ufs_readback.check_payloads(self.base / 'loader-readback',
                    output / 'media/disk.img', report['file_payloads'])
            finally:
                sys.path.pop(0)
        with self.assertRaisesRegex(ValueError, 'invalid EFI media'):
            boot.assemble_media(output, report, dict(options, fallback_name='../escape'))
        payload = Path(report['file_payloads'][boot.BOOT_POLICY_PATH]['path'])
        payload.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'media input changed'):
            boot.assemble_media(output, report, options)

    def test_signing_rejects_combined_certificate_and_private_key(self):
        signing = self.signing_inputs()
        certificate = signing['certificate'].read_bytes()
        private = signing['key'].read_bytes()
        work = self.base / 'mixed-pem-work'; work.mkdir()
        for data in (certificate + private, private + certificate,
                     certificate + private + certificate):
            signing['certificate'].write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'certificate-only PEM'):
                boot.sign_loader_manifest(b'fixture', signing, work)
            self.assertEqual(list(work.iterdir()), [])

    def test_signing_preserves_public_certificate_chain(self):
        signing = self.signing_inputs()
        certificate = signing['certificate'].read_bytes()
        # Chain construction/trust is a separate gate; exercise full transport
        # with two parseable certificates, rather than silently keeping one.
        signing['certificate'].write_bytes(certificate + b'\n' + certificate)
        artifacts, receipt = boot.sign_loader_manifest(b'fixture', signing, self.base)
        self.assertEqual(artifacts['manifest.certs'].count(b'-----BEGIN CERTIFICATE-----'), 2)
        self.assertNotIn(b'PRIVATE KEY', artifacts['manifest.certs'])
        self.assertFalse(receipt['release_authorization_verified'])

    def test_signing_parses_every_certificate_before_staging(self):
        signing = self.signing_inputs()
        valid = signing['certificate'].read_bytes()
        signing['certificate'].write_bytes(valid +
            b'-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n')
        work = self.base / 'invalid-chain-work'; work.mkdir()
        with self.assertRaises(subprocess.CalledProcessError):
            boot.sign_loader_manifest(b'fixture', signing, work)
        self.assertEqual(list(work.iterdir()), [])

    def test_signing_never_stages_private_key(self):
        from unittest import mock
        signing = self.signing_inputs()
        work = self.base / 'signing-work'; work.mkdir()
        real_run = subprocess.run
        calls = []
        def inspect(argv, **kwargs):
            for path in work.rglob('*'):
                if path.is_file():
                    self.assertNotIn(b'PRIVATE KEY', path.read_bytes())
            if '-sign' in argv:
                descriptor = argv[argv.index('-sign') + 1]
                self.assertEqual(descriptor, '/dev/stdin')
                self.assertTrue(hasattr(kwargs['stdin'], 'fileno'))
            elif 'input' in kwargs:
                self.assertNotIn(b'PRIVATE KEY', kwargs['input'])
                self.assertNotIn('stdin', kwargs)
            else:
                self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            calls.append(argv[1])
            return real_run(argv, **kwargs)
        with mock.patch('subprocess.run', side_effect=inspect):
            boot.sign_loader_manifest(b'fixture', signing, work)
        self.assertEqual(calls, ['x509', 'x509', 'dgst', 'dgst'])
        self.assertEqual(list(work.iterdir()), [])

    def test_signing_refuses_key_mismatch_and_public_private_key(self):
        signing = self.signing_inputs()
        other = self.base / 'other.key'
        subprocess.run(['/usr/bin/openssl', 'genpkey', '-algorithm', 'RSA',
            '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(other)], check=True, capture_output=True)
        other.chmod(0o600)
        with self.assertRaises(subprocess.CalledProcessError):
            boot.sign_loader_manifest(b'kernel sha256=' + b'a' * 64 + b'\n',
                dict(signing, key=other), self.base)
        signing['key'].chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'nonprivate key'):
            boot.sign_loader_manifest(b'fixture', signing, self.base)
        self.assertEqual(list(self.base.glob('manifest-sign-*')), [])

    def test_generated_boot_file_is_copied_bound_and_manifested(self):
        self.verify()
        generated = self.generated_input()
        out = self.base / 'generated-stage'
        report = boot.stage(self.image, self.archive, self.receipt_path, out, generated=generated)
        binding = report['file_payloads']['/boot/loader.conf']
        self.assertEqual(Path(binding['path']).read_bytes(), (self.base / 'config').read_bytes())
        self.assertIn('loader.conf sha256=' + binding['sha256'],
                      (out / 'loader.manifest.unsigned').read_text())
        self.assertIn('./boot/loader.conf type=file', (out / 'filesystem.mtree').read_text())
        self.assertFalse(report['loader_manifest_signed'])
        self.assertFalse(report['generation_authenticated'])

    def test_generated_boot_refuses_replacement_and_wrong_bytes(self):
        self.verify()
        generated = self.generated_input()
        replacement = {'/boot/kernel': generated['/boot/loader.conf']}
        with self.assertRaisesRegex(ValueError, 'replace packaged'):
            boot.stage(self.image, self.archive, self.receipt_path, self.base / 'replace', generated=replacement)
        self.assertFalse((self.base / 'replace').exists())
        (self.base / 'config').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'differs from binding'):
            boot.stage(self.image, self.archive, self.receipt_path, self.base / 'changed', generated=generated)
        self.assertFalse((self.base / 'changed/stage.json').exists())

    def test_manifest_binds_file_and_directory_aliases(self):
        (self.root / 'boot/modules').mkdir()
        (self.root / 'boot/modules/driver.ko').write_bytes(b'driver')
        (self.root / 'boot/alias').symlink_to('modules')
        (self.root / 'boot/modules/kernel-link').symlink_to('../kernel')
        entries = image.construction.generation.scan(self.root)
        entries = {n: v for n, v in entries.items() if n == '/boot' or n.startswith('/boot/')}
        bindings = boot.manifest_bindings(entries)
        self.assertEqual(set(bindings), {'kernel', 'link', 'modules/driver.ko',
            'modules/kernel-link', 'alias/driver.ko', 'alias/kernel-link'})
        self.assertEqual(bindings['kernel'], bindings['link'])
        self.assertEqual(bindings['kernel'], bindings['alias/kernel-link'])
        self.assertEqual(bindings['modules/driver.ko'], bindings['alias/driver.ko'])

    def test_manifest_symlink_chain_limit(self):
        entries = copy.deepcopy(self.receipt['boot_archive']['entries'])
        for i in range(32):
            entry = dict(entries['/boot/link'])
            entry['target'] = 'kernel' if i == 31 else 'chain' + str(i + 1)
            entries['/boot/chain' + str(i)] = entry
        self.assertEqual(boot.manifest_bindings(entries)['chain0'], entries['/boot/kernel']['sha256'])
        entries['/boot/link']['target'] = 'chain0'
        with self.assertRaisesRegex(ValueError, 'excessive chain'):
            boot.manifest_bindings(entries)

    def test_manifest_counts_directory_aliases_across_complete_path(self):
        entries = copy.deepcopy(self.receipt['boot_archive']['entries'])
        for i in range(34):
            entries['/boot/d' + str(i)] = dict(entries['/boot'])
        for i in range(32):
            entries['/boot/d' + str(i) + '/a'] = dict(
                entries['/boot/link'], target='../d' + str(i + 1))
        payload = {k: v for k, v in entries['/boot/kernel'].items() if k != 'hardlinks'}
        entries['/boot/d32/file'] = dict(payload)
        path = 'd0/' + 'a/' * 32 + 'file'
        self.assertEqual(boot.manifest_bindings(entries)[path],
                         entries['/boot/kernel']['sha256'])
        entries['/boot/d32/a'] = dict(entries['/boot/link'], target='../d33')
        entries['/boot/d33/file'] = dict(payload)
        # Each individual directory alias is only one link, but the loader
        # must traverse 33 links to open this complete logical pathname.
        with self.assertRaisesRegex(ValueError, 'excessive chain'):
            boot.manifest_bindings(entries)

    def test_manifest_rejects_unresolvable_aliases(self):
        entries = self.receipt['boot_archive']['entries']
        for target in ('/', '/etc/passwd', '../../etc/passwd', 'missing', 'link', '.', 'kernel/child'):
            changed = copy.deepcopy(entries)
            changed['/boot/link']['target'] = target
            with self.subTest(target=target), self.assertRaises(ValueError):
                boot.manifest_bindings(changed)

    def test_loader_manifest_exact_and_deterministic(self):
        bindings = {'system.ufs': 'b' * 64, 'kernel/kernel': 'a' * 64,
                    'loader.conf': 'c' * 64}
        expected = ('kernel/kernel sha256=' + 'a' * 64 + '\nloader.conf sha256=' +
                    'c' * 64 + '\nsystem.ufs sha256=' + 'b' * 64 + '\n').encode()
        self.assertEqual(boot.loader_manifest(bindings), expected)
        self.assertEqual(boot.loader_manifest(dict(reversed(list(bindings.items())))), expected)

    def test_loader_manifest_rejects_path_and_record_injection(self):
        for name in ('', '/kernel', '../kernel', 'a/../kernel', 'a//b', 'a/./b',
                     'a b', 'a\nb sha256=', 'a\tb', 'a\0b', 'manifest',
                     'manifest.sig', 'manifest.certs', 'x' * 1018, 'caf\u00e9'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                boot.loader_manifest({name: 'a' * 64})
        for digest in ('', 'a' * 63, 'A' * 64, 'a' * 64 + '\n', None):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                boot.loader_manifest({'kernel/kernel': digest})
        with self.assertRaises(ValueError):
            boot.loader_manifest({})

    def test_exact_transport(self):
        report = self.verify()
        self.assertEqual(report['objects'], 3)
        self.assertFalse(report['boot_verified'])
        self.assertFalse(report['generation_authenticated'])
        self.assertTrue(report['metadata_reconstruction_required'])

    def test_inner_payload_changed_even_with_new_archive_digest(self):
        def change(members):
            m, data = members[1]; members[1] = (m, b'x' * len(data))
        self.rewrite(change)
        with self.assertRaisesRegex(ValueError, 'file digest'): self.verify()

    def test_metadata_changed_even_with_new_archive_digest(self):
        self.rewrite(lambda members: setattr(members[1][0], 'uid', members[1][0].uid + 1))
        with self.assertRaisesRegex(ValueError, 'metadata'): self.verify()

    def test_symlink_parent_observation_refused(self):
        self.receipt['boot_archive']['entries']['/boot/link/escape'] = copy.deepcopy(
            self.receipt['boot_archive']['entries']['/boot/kernel'])
        del self.receipt['boot_archive']['entries']['/boot/link/escape']['hardlinks']
        with self.assertRaisesRegex(ValueError, 'parent'): self.verify()

    def test_hardlink_set_must_include_current_name(self):
        self.receipt['boot_archive']['entries']['/boot/kernel']['hardlinks'] = ['/a', '/b']
        with self.assertRaisesRegex(ValueError, 'hardlink'): self.verify()

    def test_trailing_data_refused_even_with_new_archive_digest(self):
        with self.archive.open('ab') as stream: stream.write(b'unexpected'.ljust(512,b'\0'))
        self.receipt['boot_archive'].update(archive_bytes=self.archive.stat().st_size,
                                          archive_sha256=image.file_hash(self.archive))
        with self.assertRaisesRegex(ValueError, 'trailing'): self.verify()

    def test_binding_and_schema_fail_closed(self):
        original = copy.deepcopy(self.receipt)
        for change in (lambda r: r.update(readback_observation_sha256='b'*64),
                       lambda r: r['boot_archive']['entries']['/boot'].update(uid=True),
                       lambda r: r['boot_archive']['entries'].update({'/boot': []})):
            self.receipt = copy.deepcopy(original); change(self.receipt)
            with self.assertRaises(ValueError): self.verify()


if __name__ == '__main__': unittest.main()
