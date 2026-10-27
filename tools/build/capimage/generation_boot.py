#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check collected boot transport against its image receipt, without extraction.

This is unsigned consistency verification, not release approval or boot proof.
"""
import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile


SIGNING_ARTIFACT_NAMES = frozenset({'manifest', 'manifest.sig', 'manifest.certs'})


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate receipt key')
        result[key] = value
    return result


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def canonical(name):
    return (isinstance(name, str) and name.startswith('/') and '\0' not in name and
            all(part not in ('', '.', '..') for part in name.split('/')[1:]))


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def observations(entries):
    if (not isinstance(entries, dict) or not isinstance(entries.get('/boot'), dict) or
            entries['/boot'].get('type') != 'directory'):
        raise ValueError('complete boot observation required')
    common = {'type', 'uid', 'gid', 'mode', 'flags_set', 'mtime', 'mtime_nsec'}
    for name, item in entries.items():
        if not canonical(name) or (name != '/boot' and not name.startswith('/boot/')) or not isinstance(item, dict):
            raise ValueError('invalid boot observation path or object')
        kind = item.get('type')
        fields = common | ({'size', 'sha256'} if kind == 'file' else {'target'} if kind == 'symlink' else set())
        if 'hardlinks' in item and kind in ('file', 'symlink'):
            fields = fields | {'hardlinks'}
        if kind not in ('file', 'directory', 'symlink') or set(item) != fields:
            raise ValueError('unsupported boot observation fields')
        for field, low, high in (('uid', 0, 2**32-2), ('gid', 0, 2**32-2), ('mode', 0, 0o7777),
                ('flags_set', 0, 2**32-1), ('mtime', -(2**63), 2**63-1), ('mtime_nsec', 0, 999999999)):
            if not integer(item[field], low, high):
                raise ValueError('invalid boot observation metadata: ' + field)
        if name != '/boot' and entries.get(name.rsplit('/', 1)[0], {}).get('type') != 'directory':
            raise ValueError('boot observation parent is not a directory')
        if kind == 'file' and (not integer(item['size'], 0, 2**63-1) or not sha(item['sha256'])):
            raise ValueError('invalid boot file binding')
        if kind == 'symlink' and (not isinstance(item['target'], str) or not item['target'] or '\0' in item['target']):
            raise ValueError('invalid boot symlink target')
        if 'hardlinks' in item:
            links = item['hardlinks']
            if (not isinstance(links, list) or not all(canonical(n) for n in links) or
                    len(links) < 2 or links != sorted(set(links)) or name not in links):
                raise ValueError('invalid boot hardlink set')
            for alias in links:
                if alias == '/boot' or alias.startswith('/boot/'):
                    if entries.get(alias) != item:
                        raise ValueError('inconsistent boot hardlink observations')
    return entries


def opened(path):
    # Reject FIFOs without waiting for a writer before the type check.
    # O_NONBLOCK does not change regular-file reads.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError('input must be a regular file')
    return os.fdopen(fd, 'rb')


def verify(image, archive_path, receipt_path, *, verity_image=None, verity_descriptor=None):
    with opened(receipt_path) as stream:
        if os.fstat(stream.fileno()).st_size > 64 * 1048576:
            raise ValueError('image receipt too large')
        raw = stream.read()
    receipt = json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError('invalid JSON constant')))
    if not isinstance(receipt, dict):
        raise ValueError('invalid image receipt')
    if (verity_image is None) != (verity_descriptor is None):
        raise ValueError('offline verity checking requires both image and descriptor')
    if 'verity' in receipt and verity_image is None:
        raise ValueError('verity image checking requires explicit image and descriptor artifacts')
    if 'verity' not in receipt and verity_image is not None:
        raise ValueError('unexpected verity artifacts without a matching image receipt')
    boot = receipt.get('boot_archive')
    source = receipt.get('source_observation_sha256')
    scope = receipt.get('scope')
    expected = source
    if scope == 'trusted-builder-partition-image':
        if (receipt.get('partition_content') != 'immutable' or
                'partition_boundary' not in receipt or receipt['partition_boundary'] is not None):
            raise ValueError('boot transport requires the immutable base partition')
        expected = receipt.get('expected_observation_sha256')
    if (scope not in ('trusted-builder-filesystem-image', 'trusted-builder-partition-image') or receipt.get('result') != 'PASS' or
            receipt.get('generation_authenticated') is not False or receipt.get('activation_authorized') is not False or
            not sha(source) or not sha(expected) or receipt.get('readback_observation_sha256') != expected or
            not isinstance(boot, dict) or boot.get('scope') != 'generation-boot-transport' or
            boot.get('result') != 'PASS' or boot.get('source_observation_sha256') != source or
            boot.get('generation_authenticated') is not False or boot.get('activation_authorized') is not False or
            boot.get('metadata_reconstruction_required') is not True):
        raise ValueError('image and boot observations lack a completed common binding')
    entries = observations(boot.get('entries'))
    for path, size, digest in ((image, receipt.get('image_bytes'), receipt.get('image_sha256')),
                               (archive_path, boot.get('archive_bytes'), boot.get('archive_sha256'))):
        if not integer(size, 1, 2**63-1) or not sha(digest):
            raise ValueError('invalid artifact binding')
        with opened(path) as stream:
            if os.fstat(stream.fileno()).st_size != size or hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                raise ValueError('artifact differs from image receipt')
    expected = sorted(entries)
    count, end = 0, 0
    with opened(archive_path) as stream, tarfile.open(fileobj=stream, mode='r:') as archive:
        for member in archive:
            if count >= len(expected) or member.name != expected[count].lstrip('/'):
                raise ValueError('boot archive namespace differs from observation')
            item = entries[expected[count]]; count += 1
            if member.sparse is not None or set(member.pax_headers) - {'path', 'linkpath', 'mtime', 'uid', 'gid', 'size'}:
                raise ValueError('unsupported boot archive extensions')
            if (member.uid, member.gid, member.mode) != (item['uid'], item['gid'], item['mode']):
                raise ValueError('boot archive metadata differs from observation')
            try:
                timestamp = Decimal(member.pax_headers['mtime']) * 1000000000
            except (KeyError, InvalidOperation):
                raise ValueError('invalid boot archive timestamp') from None
            if not timestamp.is_finite() or timestamp != item['mtime'] * 1000000000 + item['mtime_nsec']:
                raise ValueError('boot archive timestamp differs from observation')
            kind = item['type']
            if kind == 'file':
                if member.type != tarfile.REGTYPE or member.size != item['size']:
                    raise ValueError('boot archive file type/size differs')
                with archive.extractfile(member) as payload:
                    if hashlib.file_digest(payload, 'sha256').hexdigest() != item['sha256']:
                        raise ValueError('boot archive file digest differs')
            elif kind == 'symlink':
                if member.type != tarfile.SYMTYPE or member.linkname != item['target'] or member.size:
                    raise ValueError('boot archive symlink differs')
            elif member.type != tarfile.DIRTYPE or member.size:
                raise ValueError('boot archive directory differs')
            end = member.offset_data + ((member.size + 511) // 512) * 512
        if count != len(expected):
            raise ValueError('boot archive is incomplete')
        stream.seek(end)
        padding = 0
        while chunk := stream.read(1048576):
            if any(chunk):
                raise ValueError('unexpected trailing boot archive data')
            padding += len(chunk)
        if padding < 1024 or (end + padding) % 512:
            raise ValueError('invalid boot archive end records')
        stream.seek(0)
        if hashlib.file_digest(stream, 'sha256').hexdigest() != boot['archive_sha256']:
            raise ValueError('boot archive changed during verification')
    verity_report = None
    if verity_image is not None:
        if scope != 'trusted-builder-partition-image' or receipt.get('partition_content') != 'immutable':
            raise ValueError('verity checking requires an immutable base partition receipt')
        import importlib.util
        spec = importlib.util.spec_from_file_location('verity_artifacts', Path(__file__).with_name('verity_artifacts.py'))
        artifacts = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(artifacts)
        selected = receipt['verity']
        if not isinstance(selected, dict):
            raise ValueError('invalid verity artifact receipt')
        artifacts.verify_paths(verity_image, verity_descriptor, selected, selected.get('policy'),
                               receipt['image_sha256'], receipt['image_bytes'])
        verity_report = dict(image_sha256=selected['image_sha256'],
            descriptor_sha256=selected['descriptor_sha256'], root_sha256=selected['root_sha256'],
            data_bytes=selected['data_bytes'], image_bytes=selected['image_bytes'],
            internal_consistency_verified=True, signer_authenticated=False)
    result = {'result': 'PASS', 'scope': 'collected-boot-transport-consistency',
            'image_sha256': receipt['image_sha256'], 'boot_archive_sha256': boot['archive_sha256'],
            'image_receipt_sha256': hashlib.sha256(raw).hexdigest(), 'objects': len(entries),
            'source_observation_sha256': source, 'metadata_reconstruction_required': True,
            'generation_authenticated': False, 'boot_verified': False, 'activation_authorized': False}
    if verity_report is not None:
        result['verity'] = verity_report
    return result




def manifest_bindings(entries):
    """Enumerate every readable file path in a completed observed /boot tree.

    Resolve links against observations only, never the builder's filesystem.
    Directory aliases expand to file aliases; cycles and escaping links fail.
    """
    from collections import deque
    entries = observations(entries)
    children = {}
    for name in entries:
        if name != '/boot':
            children.setdefault(name.rsplit('/', 1)[0], []).append(name)

    def resolve(name):
        pending = deque(name.split('/')[1:])
        parts, links = [], 0
        while pending:
            part = pending.popleft()
            if part in ('', '.'):
                continue
            if part == '..':
                if len(parts) <= 1:
                    raise ValueError('boot symlink escapes boot tree')
                parts.pop()
                continue
            parts.append(part)
            current = '/' + '/'.join(parts)
            if parts[0] != 'boot' or current not in entries:
                raise ValueError('dangling or escaping boot symlink')
            item = entries[current]
            if item['type'] == 'symlink':
                links += 1
                # Match MAXSYMLINKS in sys/sys/param.h.
                if links > 32:
                    raise ValueError('boot symlink cycle or excessive chain')
                target = item['target']
                parts.pop()
                if target.startswith('/'):
                    parts = []
                pending.extendleft(reversed(target.split('/')))
            elif pending and item['type'] != 'directory':
                raise ValueError('boot symlink traverses non-directory')
        resolved = '/' + '/'.join(parts)
        if resolved not in entries:
            raise ValueError('boot symlink escapes boot tree')
        return resolved

    result = {}
    def visit(logical, ancestors):
        # The loader resolves the full pathname, so directory aliases count
        # toward the same symlink limit as the final file alias.
        physical = resolve(logical)
        item = entries[physical]
        if item['type'] == 'file':
            result[logical.removeprefix('/boot/')] = item['sha256']
        elif item['type'] == 'directory':
            if physical in ancestors:
                raise ValueError('boot directory alias cycle')
            for child in sorted(children.get(physical, [])):
                visit(logical + '/' + child.rsplit('/', 1)[1],
                      ancestors | {physical})
        else:
            raise ValueError('unresolved boot symlink')
    visit('/boot', set())
    # Validate the complete namespace against the actual loader line format.
    loader_manifest(result)
    return result


def loader_manifest(files):
    """Render the loader's line format from explicit path-to-digest bindings.

    Callers must bind the completed boot filesystem, including generated inputs.
    This renderer neither authorizes signing nor follows filesystem paths.
    """
    if not isinstance(files, dict) or not files:
        raise ValueError('nonempty boot file bindings required')
    for name, digest in files.items():
        # The loader matches a literal pathname followed by a space. Whitespace
        # permits ambiguous prefix matches; no quoting/escaping exists here.
        if (not isinstance(name, str) or not name or name.startswith('/') or
                any(part in ('', '.', '..') for part in name.split('/')) or
                any(ord(c) < 33 or ord(c) > 126 for c in name) or
                len(('/boot/' + name).encode('ascii')) >= 1024 or name in SIGNING_ARTIFACT_NAMES):
            raise ValueError('unrepresentable or reserved loader manifest path')
        if not sha(digest):
            raise ValueError('invalid loader manifest digest')
    return ''.join(name + ' sha256=' + files[name] + '\n' for name in sorted(files)).encode('ascii')



def certificate_pem_blocks(data):
    """Reject private or mixed PEM before copying certificate input to output."""
    blocks, end = [], 0
    for match in re.finditer(br'-----BEGIN CERTIFICATE-----[\r\n]+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----', data):
        if data[end:match.start()].strip():
            raise ValueError('signing certificate requires certificate-only PEM')
        blocks.append(match[0])
        end = match.end()
    if not blocks or data[end:].strip():
        raise ValueError('signing certificate requires certificate-only PEM')
    return blocks


def sign_loader_manifest(manifest, signing, work):
    """Sign in a trusted builder; signature correctness is not release authority."""
    import base64
    import subprocess
    import tempfile
    if set(signing) != {'key', 'certificate', 'openssl'}:
        raise ValueError('explicit key, certificate and openssl required')
    tool = Path(signing['openssl'])
    if not tool.is_absolute() or not os.access(tool, os.X_OK):
        raise ValueError('openssl must be an absolute executable')
    with opened(tool) as stream:
        tool_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    # Keep key material in its original file. Only the signing subprocess
    # inherits this descriptor; even an interrupted builder leaves no key copy.
    with opened(signing['key']) as key, tempfile.TemporaryDirectory(prefix='manifest-sign-', dir=work) as temporary:
        key_stat = os.fstat(key.fileno())
        if key_stat.st_size > 1048576 or key_stat.st_mode & 0o077:
            raise ValueError('oversized signing input or nonprivate key')
        directory = Path(temporary)
        with opened(signing['certificate']) as stream:
            if os.fstat(stream.fileno()).st_size > 4 * 1048576:
                raise ValueError('oversized signing certificate')
            data = stream.read(4 * 1048576 + 1)
        if len(data) > 4 * 1048576:
            raise ValueError('signing certificate grew')
        # The certificate input is public output, not an arbitrary PEM file.
        # Reject keys and other material before any input bytes reach staging.
        blocks = certificate_pem_blocks(data)
        environment = dict(PATH='/sbin:/bin:/usr/sbin:/usr/bin', LC_ALL='C', OPENSSL_CONF='/dev/null')
        def run(*args, with_key=False, input_data=None):
            transport = ({'stdin': key if with_key else subprocess.DEVNULL}
                         if input_data is None else {'input': input_data})
            return subprocess.run([str(tool), *map(str, args)], env=environment,
                **transport, capture_output=True, check=True, timeout=60).stdout
        # Parse every certificate and emit canonical public PEM. Never write
        # the original combined input, even to a temporary staging file.
        certificate = b''.join(run('x509', '-inform', 'PEM', '-outform', 'PEM',
                                  input_data=block) for block in blocks)
        with (directory / 'certificate').open('xb') as target:
            os.fchmod(target.fileno(), 0o600)
            target.write(certificate)
        (directory / 'manifest').write_bytes(manifest)
        public = run('x509', '-in', directory / 'certificate', '-pubkey', '-noout')
        (directory / 'public.pem').write_bytes(public)
        signature = run('dgst', '-sha256', '-sign', '/dev/stdin',
                        directory / 'manifest', with_key=True)
        (directory / 'signature').write_bytes(signature)
        run('dgst', '-sha256', '-verify', directory / 'public.pem', '-signature',
            directory / 'signature', directory / 'manifest')
        certificate = (directory / 'certificate').read_bytes()
    with opened(tool) as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != tool_hash:
            raise ValueError('openssl changed during signing')
    armored = (b'-----BEGIN SIGNATURE-----\n' + base64.encodebytes(signature) +
               b'-----END SIGNATURE-----\n')
    return {'manifest': manifest, 'manifest.sig': armored, 'manifest.certs': certificate}, {
        'openssl_sha256': tool_hash, 'certificate_sha256': hashlib.sha256(certificate).hexdigest(),
        'certificate_input_sha256': hashlib.sha256(data).hexdigest(),
        'signature_verified': True, 'release_authorization_verified': False}



def bind_loader_build(binding, receipt, expected_sha256, *, required_transition_version=0):
    """Bind bytes to a pinned trusted-builder record, never confer signer authority."""
    if not sha(expected_sha256):
        raise ValueError('loader build requires an explicit SHA256 pin')
    with opened(receipt) as stream:
        if os.fstat(stream.fileno()).st_size > 1048576:
            raise ValueError('loader build record too large')
        raw = stream.read(1048577)
    if len(raw) > 1048576 or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('loader build record differs from selected SHA256')
    record = json.loads(raw, object_pairs_hook=unique)
    if (not isinstance(record, dict) or
            record.get('schema') != 'org.5bsd.loader-build.v1' or
            record.get('result') != 'PASS' or
            record.get('scope') != 'trusted-builder-loader-compilation' or
            record.get('firmware_db_manifest_fallback') is not False or
            not isinstance(record.get('loader'), dict) or
            not isinstance(record.get('anchors'), dict) or
            not sha(record['anchors'].get('sha256')) or
            not sha(record.get('inputs_sha256')) or
            not sha(record.get('generated_trust_header_sha256')) or
            not isinstance(record.get('manifest_verifier'), dict) or
            not sha(record['manifest_verifier'].get('sha256')) or
            not sha(record['manifest_verifier'].get('trust_header_sha256'))):
        raise ValueError('unsupported loader build record or trust profile')
    transition_version = record.get('root_transition_version', 0)
    if (not integer(transition_version, 0, 1) or
            not integer(required_transition_version, 0, 1)):
        raise ValueError('unsupported loader root-transition version')
    if required_transition_version and transition_version != required_transition_version:
        raise ValueError('selected loader build does not declare required root-transition support')
    loader = record['loader']
    if (not sha(loader.get('sha256')) or
            not integer(loader.get('size'), 1, 2**63-1) or
            loader['size'] != binding['size'] or loader['sha256'] != binding['sha256']):
        raise ValueError('staged EFI loader differs from selected build record')
    # Do not open paths from the record or inherit its claims of verification.
    return raw, dict(receipt_sha256=expected_sha256,
        root_transition_version=transition_version,
        inputs_sha256=record['inputs_sha256'],
        anchors_sha256=record['anchors']['sha256'],
        generated_trust_header_sha256=record['generated_trust_header_sha256'],
        manifest_verifier_sha256=record['manifest_verifier']['sha256'],
        manifest_verifier_trust_header_sha256=record['manifest_verifier']['trust_header_sha256'],
        staged_artifact_bound=True, source_attestation_verified=False,
        release_authorization_verified=False, firmware_verified=False)


def verify_generation_manifest(build_binding, verifier, artifacts, payloads, output):
    """Verify staged signatures with the explicitly selected, build-bound native tool."""
    import subprocess
    import tempfile
    verifier = Path(verifier)
    if not verifier.is_absolute() or not os.access(verifier, os.X_OK):
        raise ValueError('manifest verifier must be an absolute executable')
    expected = {name: hashlib.sha256(artifacts[name]).hexdigest()
                for name in ('manifest', 'manifest.sig', 'manifest.certs')}

    def check_inputs():
        for name, digest in expected.items():
            with opened(payloads / name) as stream:
                if (os.fstat(stream.fileno()).st_size != len(artifacts[name]) or
                        hashlib.file_digest(stream, 'sha256').hexdigest() != digest):
                    raise ValueError('manifest verification input changed')

    # Execute the exact checked snapshot, not a path read from the build record.
    with tempfile.TemporaryDirectory(prefix='manifest-verify-', dir=output) as work:
        executable = Path(work) / 'verify'
        count, digest = 0, hashlib.sha256()
        with opened(verifier) as source, executable.open('xb') as target:
            while chunk := source.read(1048576):
                count += len(chunk)
                if count > 64 * 1048576:
                    raise ValueError('manifest verifier exceeds size limit')
                digest.update(chunk); target.write(chunk)
            if digest.hexdigest() != build_binding['manifest_verifier_sha256']:
                raise ValueError('manifest verifier differs from selected loader build')
            os.fchmod(target.fileno(), 0o500)
        check_inputs()
        result = subprocess.run([str(executable), str(payloads / 'manifest.sig')],
            env=dict(PATH='/sbin:/bin:/usr/sbin:/usr/bin', LC_ALL='C'),
            stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        if result.returncode != 0 or result.stdout != b'accepted\n' or result.stderr:
            raise ValueError('compiled generation trust rejected manifest: ' +
                (result.stdout + result.stderr)[:2048].decode('utf-8', errors='replace'))
        with opened(executable) as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != digest.hexdigest():
                raise ValueError('manifest verifier changed during execution')
        check_inputs()
    return dict(compiled_generation_trust_verified=True,
        verifier_sha256=digest.hexdigest(), artifact_sha256=expected,
        firmware_revocations_checked=False, certificate_expiry_enforced=False,
        firmware_verified=False)


def verify_efi_signature(report, verifier, openssl, output):
    """Check Authenticode under the selected certificate, without firmware claims."""
    import subprocess
    verifier, openssl, output = Path(verifier), Path(openssl), Path(output)
    for tool in (verifier, openssl):
        if not tool.is_absolute() or not os.access(tool, os.X_OK):
            raise ValueError('EFI verification tools must be absolute executables')
    signed, certificate = output / 'loader.efi', output / 'certificate.pem'

    def digest(path):
        with opened(path) as stream:
            return hashlib.file_digest(stream, 'sha256').hexdigest()

    expected = {signed: report['signed_sha256'],
                certificate: report['certificate_sha256'],
                verifier: digest(verifier), openssl: digest(openssl)}

    def check_inputs():
        for path, value in expected.items():
            if digest(path) != value:
                raise ValueError('EFI verification input changed: ' + str(path))

    env = dict(PATH='/sbin:/bin:/usr/sbin:/usr/bin', LC_ALL='C',
               OPENSSL_CONF='/dev/null')
    check_inputs()
    # uefisign selects the first certificate as its signer. The remaining PEM
    # certificates can supply its chain, but cannot substitute another leaf.
    der = subprocess.run([str(openssl), 'x509', '-in', str(certificate),
        '-outform', 'DER'], env=env, stdin=subprocess.DEVNULL,
        capture_output=True, check=True, timeout=60).stdout
    pin = hashlib.sha256(der).hexdigest()
    argv = [str(verifier), 'verify', '-in', str(signed), '-CAfile',
            str(certificate), '-require-leaf-hash', 'sha256:' + pin,
            '-ignore-timestamp', '-ignore-crl']
    result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=60)
    check_inputs()
    (output / 'signature-verification.log').write_bytes(result.stdout + result.stderr)
    if result.returncode != 0:
        raise ValueError('EFI Authenticode verification rejected signed loader: ' +
            (result.stdout + result.stderr)[:2048].decode('utf-8', errors='replace'))
    return dict(signature_verified=True, firmware_verified=False,
        authenticode_verification=dict(verifier_sha256=expected[verifier],
            openssl_sha256=expected[openssl], leaf_certificate_sha256=pin,
            signed_sha256=expected[signed], certificate_sha256=expected[certificate],
            revocations_checked=False, timestamp_trust_used=False,
            firmware_trust_checked=False, argv=argv))


def check_efi_signing_payload(unsigned, signed):
    """Require uefisign output to retain the selected executable byte for byte.

    Only the PE checksum and certificate directory may change. This is a
    transformation check, not Authenticode signature validation.
    """
    import struct
    efi_fallback_name(unsigned)
    with opened(unsigned) as source, opened(signed) as target:
        size = os.fstat(source.fileno()).st_size
        signed_size = os.fstat(target.fileno()).st_size
        source.seek(60)
        pe = struct.unpack('<I', source.read(4))[0]
        source.seek(pe + 20)
        optional_size = struct.unpack('<H', source.read(2))[0]
        optional = pe + 24
        source.seek(optional)
        magic = struct.unpack('<H', source.read(2))[0]
        directories = 112 if magic == 0x20b else 96
        if optional_size < directories + 40:
            raise ValueError('EFI certificate directory missing')
        source.seek(optional + directories - 4)
        if struct.unpack('<I', source.read(4))[0] < 5:
            raise ValueError('EFI certificate directory missing')
        checksum, certificate = optional + 64, optional + directories + 32
        source.seek(certificate)
        if source.read(8) != bytes(8):
            raise ValueError('EFI signing requires an unsigned loader')
        target.seek(certificate)
        entry = target.read(8)
        if len(entry) != 8:
            raise ValueError('truncated signed EFI header')
        offset, length = struct.unpack('<II', entry)
        if (offset != size or offset % 8 or length < 8 or length % 8 or
                offset + length != signed_size):
            raise ValueError('EFI certificate table must be appended to loader')
        # Bound memory independently of loader size. Compare every original
        # byte except the two explicitly permitted PE signing fields.
        start = 0
        for end, following in ((checksum, checksum + 4),
                               (certificate, certificate + 8), (size, size)):
            source.seek(start); target.seek(start)
            remaining = end - start
            while remaining:
                count = min(remaining, 1048576)
                original, result = source.read(count), target.read(count)
                if len(original) != count or original != result:
                    raise ValueError('EFI signer changed executable payload')
                remaining -= count
            start = following
    return True


def sign_efi_loader(binding, signing, signer, certificate, output):
    """Produce an EFI signing artifact; firmware verification is still required."""
    import subprocess
    signer = Path(signer)
    if not signer.is_absolute() or not os.access(signer, os.X_OK):
        raise ValueError('EFI signer must be an absolute executable')
    with opened(signer) as stream:
        signer_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    key = Path(signing['key'])
    if not key.is_absolute():
        raise ValueError('EFI key path must be absolute')
    with opened(key) as stream:
        before = os.fstat(stream.fileno())
        if before.st_mode & 0o077:
            raise ValueError('EFI signing key must be private')
    with opened(certificate) as stream:
        if os.fstat(stream.fileno()).st_size > 4 * 1048576:
            raise ValueError('oversized EFI signing certificate')
        certificate_data = stream.read(4 * 1048576 + 1)
    if len(certificate_data) > 4 * 1048576:
        raise ValueError('EFI signing certificate grew')
    certificate_pem_blocks(certificate_data)
    output = Path(output)
    output.mkdir(mode=0o700)
    certificate = output / 'certificate.pem'
    with certificate.open('xb') as target:
        os.fchmod(target.fileno(), 0o600)
        target.write(certificate_data)
    unsigned, signed = output / 'unsigned.efi', output / 'loader.efi'
    with opened(binding['path']) as source, unsigned.open('xb') as target:
        os.fchmod(target.fileno(), 0o600)
        size, digest = 0, hashlib.sha256()
        while chunk := source.read(1048576):
            size += len(chunk)
            if size > binding['size']:
                raise ValueError('EFI input exceeds binding')
            digest.update(chunk); target.write(chunk)
    if size != binding['size'] or digest.hexdigest() != binding['sha256']:
        raise ValueError('EFI input differs from boot inventory binding')
    # uefisign opens the key in its parent AFTER forking its sandboxed parser.
    # Do not pass a key descriptor or key bytes to that parser via stdin.
    subprocess.run([str(signer), '-k', str(key), '-c', str(certificate), '-o', str(signed), str(unsigned)],
        env=dict(PATH='/sbin:/bin:/usr/sbin:/usr/bin', LC_ALL='C', OPENSSL_CONF='/dev/null'),
        stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=60)
    with opened(key) as stream:
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode')
    if any(getattr(before, f) != getattr(after, f) for f in fields):
        raise ValueError('EFI signing key changed during signing')
    with opened(signer) as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != signer_hash:
            raise ValueError('EFI signer changed during signing')
    with opened(unsigned) as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != binding['sha256']:
            raise ValueError('EFI signer changed unsigned input')
    with opened(certificate) as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != hashlib.sha256(certificate_data).hexdigest():
            raise ValueError('EFI signing certificate changed during signing')
    with opened(signed) as stream:
        signed_size = os.fstat(stream.fileno()).st_size
        signed_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    if signed_size == 0 or signed_hash == binding['sha256']:
        raise ValueError('EFI signer produced no signed artifact')
    check_efi_signing_payload(unsigned, signed)
    return dict(input_sha256=binding['sha256'], signed_sha256=signed_hash,
        signed_bytes=signed_size, signer_sha256=signer_hash,
        executable_payload_preserved=True,
        certificate_sha256=hashlib.sha256(certificate_data).hexdigest(),
        firmware_verified=False, signature_verified=False)




def efi_fallback_name(path):
    """Read bounded PE headers to select the architecture's UEFI fallback name.

    This checks format/architecture, not the signature or firmware trust.
    """
    import struct
    machines = {0x14c: ('BOOTIA32.EFI', 0x10b),
                0x8664: ('BOOTX64.EFI', 0x20b),
                0xaa64: ('BOOTAA64.EFI', 0x20b),
                0x5064: ('BOOTRISCV64.EFI', 0x20b)}
    with opened(path) as stream:
        size = os.fstat(stream.fileno()).st_size
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b'MZ':
            raise ValueError('invalid EFI DOS header')
        offset = struct.unpack_from('<I', dos, 60)[0]
        if offset < 64 or offset > size - 24:
            raise ValueError('EFI PE header outside file')
        stream.seek(offset); pe = stream.read(24)
        if len(pe) != 24 or pe[:4] != b'PE\0\0':
            raise ValueError('invalid EFI PE header')
        machine = struct.unpack_from('<H', pe, 4)[0]
        optional_size = struct.unpack_from('<H', pe, 20)[0]
        if optional_size < 70 or offset + 24 + optional_size > size:
            raise ValueError('EFI optional header outside file')
        optional = stream.read(70)
        if len(optional) != 70:
            raise ValueError('truncated EFI optional header')
        magic = struct.unpack_from('<H', optional)[0]
        subsystem = struct.unpack_from('<H', optional, 68)[0]
        if machine not in machines:
            raise ValueError('unsupported EFI machine')
        name, expected_magic = machines[machine]
        if magic != expected_magic or subsystem != 10:
            raise ValueError('EFI loader must be an application with matching PE format')
        return name


def assemble_media(stage_path, report, options):
    """Assemble transport media from bound stage artifacts, without boot claims."""
    import subprocess
    required = {'makefs', 'mkimg', 'fallback_name', 'esp_mib', 'free_percent'}
    if not isinstance(options, dict) or set(options) != required:
        raise ValueError('explicit media tools, fallback name and capacities required')
    if (not isinstance(options['fallback_name'], str) or
            not re.fullmatch(r'BOOT[A-Z0-9]+\.EFI', options['fallback_name']) or
            not integer(options['esp_mib'], 16, 1024) or
            not integer(options['free_percent'], 0, 50)):
        raise ValueError('invalid EFI media layout inputs')
    if not report.get('loader_manifest_signed') or 'efi_loader' not in report:
        raise ValueError('media requires signed manifest and EFI artifact')
    if report['efi_loader'].get('signature_verified') is not True:
        raise ValueError('media requires verified EFI signature')
    root = report.get('root_image_binding')
    root_digest = report['verity']['image_sha256'] if 'verity' in report else report['image_sha256']
    if (not isinstance(root, dict) or set(root) != {'path', 'size', 'sha256'} or
            root['path'] not in report['file_payloads'] or
            root['sha256'] != root_digest or
            any(root[key] != report['file_payloads'][root['path']][key]
                for key in ('size', 'sha256'))):
        raise ValueError('media requires a receipt-bound root image boot path')
    stage_path = Path(stage_path)
    def digest(path):
        with opened(path) as stream:
            return hashlib.file_digest(stream, 'sha256').hexdigest()
    inputs = dict(report['payloads_sha256'])
    inputs[str(stage_path / 'filesystem.mtree')] = report['filesystem_mtree_sha256']
    inputs[str(stage_path / 'efi/loader.efi')] = report['efi_loader']['signed_sha256']
    tools = {}
    for name in ('makefs', 'mkimg'):
        path = Path(options[name])
        if not path.is_absolute() or not os.access(path, os.X_OK):
            raise ValueError('media tools must be absolute executables')
        tools[name] = path
        inputs[str(path)] = digest(path)
    def check_inputs():
        for path, expected in inputs.items():
            if digest(path) != expected:
                raise ValueError('media input changed: ' + path)
    check_inputs()
    if efi_fallback_name(stage_path / 'efi/loader.efi') != options['fallback_name']:
        raise ValueError('EFI fallback name does not match loader architecture')
    output = stage_path / 'media'; output.mkdir(mode=0o700)
    esp_root = output / 'esp'; fallback = esp_root / 'EFI/BOOT' / options['fallback_name']
    fallback.parent.mkdir(parents=True, mode=0o700)
    with opened(stage_path / 'efi/loader.efi') as source, fallback.open('xb') as target:
        os.fchmod(target.fileno(), 0o600)
        while chunk := source.read(1048576):
            target.write(chunk)
    if digest(fallback) != report['efi_loader']['signed_sha256']:
        raise ValueError('EFI media copy differs from signed artifact')
    command_log = []
    def run(name, *args):
        argv = [str(tools[name]), *map(str, args)]
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
            env=dict(PATH='/sbin:/bin:/usr/sbin:/usr/bin', LC_ALL='C'), timeout=600)
        command_log.append(dict(argv=argv, exit_code=result.returncode))
        with (output / 'commands.log').open('ab') as log:
            log.write(result.stdout + result.stderr)
        result.check_returncode()
    boot_image, esp_image, disk = output / 'boot.ufs', output / 'esp.fat', output / 'disk.img'
    run('makefs', '-t', 'ffs', '-o', 'version=2', '-b', str(options['free_percent']) + '%',
        boot_image, stage_path / 'filesystem.mtree')
    run('makefs', '-t', 'msdos', '-s', str(options['esp_mib']) + 'm', '-o', 'fat_type=16', esp_image, esp_root)
    run('mkimg', '-s', 'gpt', '-f', 'raw', '-p', 'efi:=' + str(esp_image),
        '-p', 'freebsd-ufs:=' + str(boot_image), '-o', disk)
    check_inputs()
    artifacts = {p.name: dict(sha256=digest(p), size=p.stat().st_size)
                 for p in (boot_image, esp_image, disk)}
    return dict(scope='signed-boot-media-construction', result='PASS', artifacts=artifacts,
        fallback_name=options['fallback_name'], esp_mib=options['esp_mib'],
        free_percent=options['free_percent'], commands=command_log,
        tools_sha256={name: inputs[str(path)] for name, path in tools.items()},
        filesystem_readback_verified=False, firmware_verified=False,
        normal_boot_verified=False, activation_authorized=False)


BOOT_POLICY_PATH = '/boot/boot-policy.lua'


BOOT_TRANSITION_PATH = '/boot/root-transition.bin'
BOOT_TRANSITION_BYTES = 2192


def render_boot_transition(policy, verified):
    """Encode construction inputs; loader/kernel consumption is a separate gate.

    Version 1: big-endian header, descriptor digest, resource fields, then
    NUL-terminated zero-padded transport (1024), image (1024), provider (64).
    See sys/geom/verity/g_verity_transition.h for the shared wire contract.
    """
    import struct
    transition = policy.get('transition')
    fields = {'version', 'transport_fs', 'transport_device', 'provider',
              'workers', 'cache_blocks', 'window_bytes', 'buffer_bytes'}
    if (policy.get('mode') != 'verity' or not isinstance(transition, dict) or
            set(transition) != fields or type(transition['version']) is not int or
            transition['version'] != 1):
        raise ValueError('invalid root transition fields or version')
    filesystem = {'ufs': 1, 'zfs': 2}.get(transition['transport_fs']) if isinstance(transition['transport_fs'], str) else None
    device, provider = transition['transport_device'], transition['provider']
    if (filesystem is None or not isinstance(device, str) or
            re.fullmatch(r'[A-Za-z0-9_./+:-]+', device) is None or
            any(part in ('', '.', '..') for part in device.lstrip('/').split('/')) or
            (filesystem == 1 and not device.startswith('/dev/')) or
            (filesystem == 2 and (device.startswith('/') or ':' in device))):
        raise ValueError('invalid transition transport selection')
    if (not isinstance(provider, str) or
            re.fullmatch(r'[A-Za-z0-9_.+-]+', provider) is None or provider in ('.', '..')):
        raise ValueError('invalid transition provider name')
    if not integer(transition['workers'], 1, 2**32-1):
        raise ValueError('invalid transition worker count')
    for field in ('cache_blocks', 'window_bytes', 'buffer_bytes'):
        if not integer(transition[field], 0 if field == 'cache_blocks' else 1, 2**63-1):
            raise ValueError('invalid transition resource bound')
    if (not isinstance(verified, dict) or verified.get('result') != 'PASS' or
            verified.get('scope') != 'collected-boot-transport-consistency' or
            not isinstance(verified.get('verity'), dict) or
            verified['verity'].get('internal_consistency_verified') is not True or
            not sha(verified['verity'].get('descriptor_sha256'))):
        raise ValueError('root transition requires checked descriptor')

    def field(value, capacity):
        data = value.encode('ascii')
        if len(data) >= capacity:
            raise ValueError('transition path or name exceeds wire capacity')
        return data + bytes(capacity - len(data))

    return (struct.pack('>8sII32sIIQQQ', b'5BSDBOOT', 1, BOOT_TRANSITION_BYTES,
                bytes.fromhex(verified['verity']['descriptor_sha256']),
                transition['workers'], filesystem, transition['cache_blocks'],
                transition['window_bytes'], transition['buffer_bytes']) +
            field(device, 1024) + field(policy['image'], 1024) + field(provider, 64))


def render_boot_policy(policy, verified=None):
    """Render explicit data, deriving disk descriptor identity from checked artifacts."""
    if (not isinstance(policy, dict) or type(policy.get('version')) is not int or
            policy['version'] != 1):
        raise ValueError('unsupported boot policy version')
    if policy.get('mode') == 'preloaded' and set(policy) == {'version', 'mode'}:
        return b'return {version=1, mode="preloaded"}\n'
    fields = {'version', 'mode', 'image', 'descriptor', 'cache_blocks', 'heap_bytes'}
    if policy.get('mode') != 'verity' or set(policy) not in (fields, fields | {'transition'}):
        raise ValueError('unsupported boot policy fields or mode')
    for key in ('image', 'descriptor'):
        path = policy[key]
        if (not canonical(path) or not path.startswith('/boot/') or
                re.fullmatch(r'/[A-Za-z0-9_./+\-]+', path) is None):
            raise ValueError('invalid boot policy artifact path')
    if policy['image'] == policy['descriptor']:
        raise ValueError('boot image and descriptor paths must differ')
    if (not integer(policy['cache_blocks'], 0, 2**63-1) or
            not integer(policy['heap_bytes'], 1, 2**63-1)):
        raise ValueError('invalid boot policy memory bounds')
    if (not isinstance(verified, dict) or verified.get('result') != 'PASS' or
            verified.get('scope') != 'collected-boot-transport-consistency' or
            not isinstance(verified.get('verity'), dict) or
            verified['verity'].get('internal_consistency_verified') is not True or
            not sha(verified['verity'].get('descriptor_sha256'))):
        raise ValueError('disk boot policy requires checked generation artifacts')
    transition_fields = ''
    if 'transition' in policy:
        transition_digest = hashlib.sha256(render_boot_transition(policy, verified)).hexdigest()
        transition_fields = f', transition="{BOOT_TRANSITION_PATH}", transition_sha256="{transition_digest}"'
    digest = verified['verity']['descriptor_sha256']
    return (f'return {{version=1, mode="verity", image="{policy["image"]}", '
            f'descriptor="{policy["descriptor"]}", descriptor_sha256="{digest}", '
            f'cache_blocks="{policy["cache_blocks"]}", heap_bytes="{policy["heap_bytes"]}"{transition_fields}}}\n').encode('ascii')


def stage(image, archive_path, receipt_path, output, *, generated=None, signing=None,
          efi=None, media=None, root_path=None, boot_policy=None,
          verity_image=None, verity_descriptor=None):
    if boot_policy is None:
        if signing is not None:
            raise ValueError('signed boot staging requires an explicit boot policy')
        if verity_image is not None or verity_descriptor is not None:
            raise ValueError('disk staging requires an explicit boot policy')
        report = _stage(image, archive_path, receipt_path, output, generated=generated,
                        signing=signing, efi=efi, media=media, root_path=root_path)
        return _publish_stage(output, report)
    import copy
    import tempfile
    boot_policy = copy.deepcopy(boot_policy)
    checked = None
    options = {}
    if isinstance(boot_policy, dict) and boot_policy.get('mode') == 'verity':
        if verity_image is None or verity_descriptor is None:
            raise ValueError('disk staging requires both explicit verity artifacts')
        options = dict(verity_image=verity_image, verity_descriptor=verity_descriptor)
        checked = verify(image, archive_path, receipt_path, **options)
    elif verity_image is not None or verity_descriptor is not None:
        raise ValueError('verity artifacts require a disk-mode boot policy')
    payload = render_boot_policy(boot_policy, checked)
    additions = {} if generated is None else copy.deepcopy(generated)
    if (not isinstance(additions, dict) or BOOT_POLICY_PATH in additions or
            ('transition' in boot_policy and BOOT_TRANSITION_PATH in additions)):
        raise ValueError('boot policy conflicts with generated inputs')

    def binding(source, size, digest):
        return dict(source=str(Path(source).absolute()), observation=dict(
            type='file', uid=0, gid=0, mode=0o444, flags_set=0, mtime=0,
            mtime_nsec=0, size=size, sha256=digest))

    if checked is not None:
        selected = checked['verity']
        paths = (boot_policy['image'], boot_policy['descriptor'])
        if (BOOT_POLICY_PATH in paths or BOOT_TRANSITION_PATH in paths or any(path in additions for path in paths) or
                any(path in {'/boot/'+name for name in SIGNING_ARTIFACT_NAMES} for path in paths)):
            raise ValueError('disk artifact path conflicts with generated or signing inputs')
        if root_path is not None and root_path != boot_policy['image']:
            raise ValueError('root path differs from disk startup policy')
        root_path = boot_policy['image']
        additions[paths[0]] = binding(verity_image, selected['image_bytes'], selected['image_sha256'])
        additions[paths[1]] = binding(verity_descriptor, 384, selected['descriptor_sha256'])
    # All inputs use the same bounded copy/hash/inventory/signing implementation.
    with tempfile.TemporaryDirectory(prefix='bsd-boot-policy-') as temporary:
        source = Path(temporary) / 'policy.lua'
        source.write_bytes(payload)
        additions[BOOT_POLICY_PATH] = binding(source, len(payload), hashlib.sha256(payload).hexdigest())
        transition_bytes = None
        if 'transition' in boot_policy:
            transition_bytes = render_boot_transition(boot_policy, checked)
            transition_source = Path(temporary) / 'transition.bin'
            transition_source.write_bytes(transition_bytes)
            additions[BOOT_TRANSITION_PATH] = binding(transition_source,
                len(transition_bytes), hashlib.sha256(transition_bytes).hexdigest())
        report = _stage(image, archive_path, receipt_path, output, generated=additions,
                        signing=signing, efi=efi, media=media, root_path=root_path,
                        verification_report=checked, verification_options=options)
        report['generated_inputs'][BOOT_POLICY_PATH]['source'] = report['file_payloads'][BOOT_POLICY_PATH]['path']
        report['startup_contract'] = dict(version=1, mode=boot_policy['mode'],
            path=BOOT_POLICY_PATH, sha256=hashlib.sha256(payload).hexdigest(),
            staged_paths_bound=True, transport_paths_bound=False,
            startup_integration_verified=False)
        if checked is not None:
            report['startup_contract'].update(image=boot_policy['image'],
                descriptor=boot_policy['descriptor'],
                descriptor_sha256=checked['verity']['descriptor_sha256'])
        if transition_bytes is not None:
            report['generated_inputs'][BOOT_TRANSITION_PATH]['source'] = report['file_payloads'][BOOT_TRANSITION_PATH]['path']
            report['root_transition'] = dict(version=1, path=BOOT_TRANSITION_PATH,
                bytes=len(transition_bytes), sha256=hashlib.sha256(transition_bytes).hexdigest(),
                descriptor_sha256=checked['verity']['descriptor_sha256'],
                manifest_signed=signing is not None, loader_consumed=False,
                kernel_admission_enabled=False, target_resource_limits_verified=False)
        return _publish_stage(output, report)


def _publish_stage(output, report):
    # Publish only the final report, including the startup contract and stable
    # generated-input paths. An interrupted write must not expose partial JSON.
    output = Path(output)
    pending = output / 'stage.json.tmp'
    with pending.open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    os.replace(pending, output / 'stage.json')
    return report


def _stage(image, archive_path, receipt_path, output, *, generated=None, signing=None, efi=None, media=None, root_path=None, verification_report=None, verification_options=None):
    """Prepare makefs input without changing host ownership or extracting links."""
    import ctypes as C
    import copy
    verification_options = {} if verification_options is None else verification_options
    report = (verify(image, archive_path, receipt_path, **verification_options)
              if verification_report is None else verification_report)
    with opened(receipt_path) as stream:
        if os.fstat(stream.fileno()).st_size > 64 * 1048576:
            raise ValueError('image receipt too large')
        raw = stream.read()
    # Stage exactly the receipt verified above. A later verification cannot
    # detect a replacement restored after this read but before that check.
    if hashlib.sha256(raw).hexdigest() != report['image_receipt_sha256']:
        raise ValueError('image receipt changed before staging')
    receipt = json.loads(raw, object_pairs_hook=unique)
    entries = copy.deepcopy(observations(receipt['boot_archive']['entries']))
    if signing is not None and generated is None:
        raise ValueError('signing requires explicit generated boot inputs, including an empty object')
    additions = {} if generated is None else copy.deepcopy(generated)
    if not isinstance(additions, dict):
        raise ValueError('generated boot inputs must be an object')
    combined = copy.deepcopy(entries)
    for name, binding in additions.items():
        if (not isinstance(binding, dict) or set(binding) != {'source', 'observation'} or
                not isinstance(binding['source'], str) or not binding['source'].startswith('/') or
                not isinstance(binding['observation'], dict) or
                binding['observation'].get('type') != 'file' or
                'hardlinks' in binding['observation']):
            raise ValueError('invalid generated boot file binding')
        if name in entries:
            raise ValueError('generated boot input would replace packaged object')
        combined[name] = binding['observation']
    observations(combined)
    if signing is not None:
        # The file-only loader manifest cannot reveal empty directory aliases.
        # Reject every object occupying a signing output path before staging.
        collisions = sorted('/boot/' + name for name in SIGNING_ARTIFACT_NAMES
                            if '/boot/' + name in combined)
        if collisions:
            raise ValueError('boot input occupies reserved signing artifact: ' +
                             ', '.join(collisions))
    root_binding = None
    if media is not None and root_path is None:
        raise ValueError('media requires an explicit root image boot path')
    if root_path is not None:
        if not isinstance(root_path, str) or root_path not in combined:
            raise ValueError('root image boot path is absent from the boot inventory')
        selected = combined[root_path]
        root_size = report['verity']['image_bytes'] if 'verity' in report else receipt['image_bytes']
        root_digest = report['verity']['image_sha256'] if 'verity' in report else report['image_sha256']
        if (selected['type'] != 'file' or
                selected.get('size') != root_size or selected.get('sha256') != root_digest):
            raise ValueError('selected root image differs from the verified image receipt')
        root_binding = dict(path=root_path, size=selected['size'], sha256=selected['sha256'])
    if generated is not None:
        # Reject unrepresentable namespace before creating output.
        manifest_bindings(combined)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('boot stage output must be new')
    output = output.resolve()
    output.mkdir(mode=0o700)
    payloads = output / 'payloads'; payloads.mkdir(mode=0o700)
    lib = C.CDLL(None)
    lib.fflagstostr.argtypes, lib.fflagstostr.restype = [C.c_ulong], C.c_void_p
    lib.strtofflags.argtypes = [C.POINTER(C.c_char_p), C.POINTER(C.c_ulong), C.POINTER(C.c_ulong)]
    lib.strtofflags.restype = C.c_int
    lib.free.argtypes = [C.c_void_p]

    def flags_text(flags):
        if flags == 0:
            return 'none'
        ptr = lib.fflagstostr(flags)
        if not ptr:
            raise ValueError('cannot encode boot flags')
        try:
            text = C.string_at(ptr)
        finally:
            lib.free(ptr)
        buffer = C.create_string_buffer(text); cursor = C.cast(buffer, C.c_char_p)
        setflags, clearflags = C.c_ulong(), C.c_ulong()
        if lib.strtofflags(C.byref(cursor), C.byref(setflags), C.byref(clearflags)) or setflags.value != flags or clearflags.value:
            raise ValueError('unsupported boot flags')
        return text.decode('ascii')

    def escape(text):
        safe = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_.-'
        return ''.join(chr(b) if b in safe else '\\%03o' % b for b in text.encode('utf-8'))

    # The outer transport root is a format directory, not the installed root.
    root = dict(type='directory', uid=0, gid=0, mode=0o755, flags_set=0, mtime=0, mtime_nsec=0)
    expected = {'/': root}
    lines = ['#mtree 2.0', '. type=dir uid=0 gid=0 mode=0755 flags=none time=0.000000000']
    groups, sources, file_payloads = {}, {}, {}
    archive_names = sorted(entries)
    copied = 0
    with opened(archive_path) as stream, tarfile.open(fileobj=stream, mode='r:') as archive:
        for index, member in enumerate(archive):
            name = '/' + member.name
            if copied >= len(archive_names) or name != archive_names[copied]:
                raise ValueError('boot archive namespace changed during staging')
            copied += 1
            item = entries[name]
            # The outer boot filesystem is a projection of /boot. Aliases in
            # the installed root remain there; only internal aliases exist here.
            links = [n for n in item.get('hardlinks', []) if n in entries]
            if item['type'] == 'symlink' and len(links) > 1:
                raise ValueError('makefs boot stage does not yet support hardlinked symlinks')
            projected = dict(item)
            projected.pop('hardlinks', None)
            if len(links) > 1:
                projected['hardlinks'] = links
            expected[name] = projected
            kind = {'directory': 'dir', 'file': 'file', 'symlink': 'link'}[item['type']]
            fields = [escape('.' + name), 'type=' + kind, 'uid=' + str(item['uid']),
                      'gid=' + str(item['gid']), 'mode=%04o' % item['mode'],
                      'flags=' + flags_text(item['flags_set']),
                      'time=%d.%09d' % (item['mtime'], item['mtime_nsec'])]
            if kind == 'file':
                path = payloads / str(index)
                group = tuple(links) if len(links) > 1 else (name,)
                if group in groups:
                    os.link(groups[group], path)
                else:
                    with path.open('xb') as target, archive.extractfile(member) as source:
                        os.fchmod(target.fileno(), 0o600)
                        while chunk := source.read(1048576):
                            target.write(chunk)
                    groups[group] = path
                with path.open('rb') as payload:
                    if path.stat().st_size != item['size'] or hashlib.file_digest(payload, 'sha256').hexdigest() != item['sha256']:
                        raise ValueError('boot payload changed during staging')
                fields.append('contents=' + escape(str(path)))
                sources[str(path)] = item['sha256']
                file_payloads[name] = dict(path=str(path), size=item['size'], sha256=item['sha256'])
            elif kind == 'link':
                fields.append('link=' + escape(item['target']))
            lines.append(' '.join(fields))
    if copied != len(archive_names):
        raise ValueError('boot archive namespace changed during staging')
    for index, (name, binding) in enumerate(sorted(additions.items())):
        item = binding['observation']
        path = payloads / ('generated-' + str(index))
        with opened(binding['source']) as source, path.open('xb') as target:
            os.fchmod(target.fileno(), 0o600)
            digest = hashlib.sha256()
            size = 0
            while chunk := source.read(1048576):
                size += len(chunk)
                if size > item['size']:
                    raise ValueError('generated boot input exceeds expected size')
                digest.update(chunk)
                target.write(chunk)
        if size != item['size'] or digest.hexdigest() != item['sha256']:
            raise ValueError('generated boot input differs from binding')
        expected[name] = dict(item)
        sources[str(path)] = item['sha256']
        file_payloads[name] = dict(path=str(path), size=item['size'], sha256=item['sha256'])
        fields = [escape('.' + name), 'type=file', 'uid=' + str(item['uid']),
                  'gid=' + str(item['gid']), 'mode=%04o' % item['mode'],
                  'flags=' + flags_text(item['flags_set']),
                  'time=%d.%09d' % (item['mtime'], item['mtime_nsec']),
                  'contents=' + escape(str(path))]
        lines.append(' '.join(fields))
    if verify(image, archive_path, receipt_path, **verification_options) != report:
        raise ValueError('boot inputs changed during staging')
    if efi is not None:
        if (signing is None or not isinstance(efi, dict) or set(efi) not in ({'path', 'signer', 'build_receipt', 'build_sha256', 'manifest_verifier', 'signature_verifier'}, {'path', 'signer', 'build_receipt', 'build_sha256', 'manifest_verifier', 'signature_verifier', 'key', 'certificate'}) or
                efi['path'] not in file_payloads):
            raise ValueError('EFI signing requires a regular boot inventory path and manifest signing inputs')
        build_record, build_binding = bind_loader_build(file_payloads[efi['path']],
            efi['build_receipt'], efi['build_sha256'],
            required_transition_version=1 if BOOT_TRANSITION_PATH in combined else 0)
    signing_report = None
    if signing is not None:
        manifest_bytes = loader_manifest(manifest_bindings(combined))
        artifacts, signing_report = sign_loader_manifest(manifest_bytes, signing, output)
        for name, data in artifacts.items():
            path = payloads / name
            with path.open('xb') as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(data)
            digest = hashlib.sha256(data).hexdigest()
            logical = '/boot/' + name
            expected[logical] = dict(type='file', uid=0, gid=0, mode=0o444,
                flags_set=0, mtime=0, mtime_nsec=0, size=len(data), sha256=digest)
            sources[str(path)] = digest
            file_payloads[logical] = dict(path=str(path), size=len(data), sha256=digest)
            lines.append(escape('.' + logical) + ' type=file uid=0 gid=0 mode=0444 flags=none time=0.000000000 contents=' + escape(str(path)))
    if efi is not None:
        signing_report['compiled_generation_trust'] = verify_generation_manifest(
            build_binding, efi['manifest_verifier'], artifacts, payloads, output)
    manifest = output / 'filesystem.mtree'
    manifest.write_text('\n'.join(lines) + '\n')
    with manifest.open('rb') as stream:
        manifest_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    result = dict(report, scope='boot-transport-makefs-input',
        filesystem_mtree_sha256=manifest_hash, expected_observations=expected, payloads_sha256=sources,
        file_payloads=file_payloads,
        metadata_reconstruction_required=True, filesystem_readback_verified=False)
    if root_binding is not None:
        result['root_image_binding'] = root_binding
    if generated is not None:
        manifest_bytes = loader_manifest(manifest_bindings(combined))
        (output / 'loader.manifest.unsigned').write_bytes(manifest_bytes)
        result['generated_inputs'] = additions
        result['loader_manifest_sha256'] = hashlib.sha256(manifest_bytes).hexdigest()
        result['loader_manifest_signed'] = signing is not None
        if signing_report is not None:
            result['manifest_signing'] = signing_report
    if efi is not None:
        separate = 'key' in efi
        efi_signing = dict(signing, key=efi['key']) if separate else signing
        certificate = efi['certificate'] if separate else payloads / 'manifest.certs'
        result['efi_loader'] = sign_efi_loader(file_payloads[efi['path']], efi_signing,
            efi['signer'], certificate, output / 'efi')
        result['efi_loader'].update(verify_efi_signature(result['efi_loader'],
            efi['signature_verifier'], signing['openssl'], output / 'efi'))
        result['efi_loader']['credential_selection'] = 'explicit-efi' if separate else 'manifest-signing'
        result['efi_loader']['inventory_path'] = efi['path']
        (output / 'efi/loader-build.json').write_bytes(build_record)
        result['efi_loader']['build_binding'] = build_binding
    if media is not None:
        result['media'] = assemble_media(output, result, media)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'boot-archive', 'image-receipt'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument("--output", type=Path, help="prepare new makefs inputs after verification")
    parser.add_argument('--generated', type=Path, help='explicit generated boot file bindings (JSON)')
    parser.add_argument('--boot-policy', type=Path, help='explicit startup contract (JSON)')
    parser.add_argument('--verity-image', type=Path, help='explicit combined image for offline checking only')
    parser.add_argument('--verity-descriptor', type=Path, help='explicit root descriptor for offline checking only')
    for name in ('signing-key', 'signing-certificate', 'openssl'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--root-path', help='logical boot path of the receipt-bound root image; required for media')
    parser.add_argument('--efi-path')
    parser.add_argument('--efi-signer', type=Path)
    parser.add_argument('--efi-signature-verifier', type=Path)
    parser.add_argument('--loader-build-receipt', type=Path)
    parser.add_argument('--loader-build-sha256')
    parser.add_argument('--manifest-verifier', type=Path)
    parser.add_argument('--efi-signing-key', type=Path)
    parser.add_argument('--efi-signing-certificate', type=Path)
    for name in ('media-makefs', 'media-mkimg'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--efi-fallback-name')
    parser.add_argument('--esp-mib', type=int)
    parser.add_argument('--boot-free-percent', type=int)
    args = parser.parse_args()
    if args.verity_image is not None or args.verity_descriptor is not None:
        if args.verity_image is None or args.verity_descriptor is None:
            parser.error('verity artifact inputs require both files')
    if args.root_path is not None and args.output is None:
        parser.error('--root-path requires --output')
    media = None
    media_values = (args.media_makefs, args.media_mkimg, args.efi_fallback_name, args.esp_mib, args.boot_free_percent)
    if any(value is not None for value in media_values):
        if not all(value is not None for value in media_values) or args.efi_path is None:
            parser.error('media requires both tools, fallback name, ESP capacity, free percentage and EFI inputs')
        media = dict(makefs=args.media_makefs, mkimg=args.media_mkimg,
                     fallback_name=args.efi_fallback_name, esp_mib=args.esp_mib,
                     free_percent=args.boot_free_percent)
    efi = None
    if any(value is not None for value in (args.efi_path, args.efi_signer, args.loader_build_receipt, args.loader_build_sha256, args.manifest_verifier, args.efi_signature_verifier)):
        if any(value is None for value in (args.efi_path, args.efi_signer, args.signing_key, args.loader_build_receipt, args.loader_build_sha256, args.manifest_verifier, args.efi_signature_verifier)):
            parser.error('EFI artifact requires inventory path, signer, signature verifier, pinned loader build record and manifest signing inputs')
        efi = dict(path=args.efi_path, signer=args.efi_signer,
                   build_receipt=args.loader_build_receipt, build_sha256=args.loader_build_sha256,
                   manifest_verifier=args.manifest_verifier, signature_verifier=args.efi_signature_verifier)
    if args.efi_signing_key is not None or args.efi_signing_certificate is not None:
        if efi is None or args.efi_signing_key is None or args.efi_signing_certificate is None:
            parser.error('separate EFI signing requires EFI inputs and both key and certificate')
        efi.update(key=args.efi_signing_key, certificate=args.efi_signing_certificate)
    signing = None
    values = (args.signing_key, args.signing_certificate, args.openssl)
    if any(value is not None for value in values):
        if not all(value is not None for value in values) or args.generated is None or args.output is None:
            parser.error('signing requires key, certificate, openssl, generated bindings and output')
        signing = dict(key=args.signing_key, certificate=args.signing_certificate, openssl=args.openssl)
    generated = None
    if args.generated is not None:
        if args.output is None:
            parser.error('--generated requires --output')
        with opened(args.generated) as stream:
            if os.fstat(stream.fileno()).st_size > 64 * 1048576:
                raise ValueError('generated boot bindings too large')
            generated = json.load(stream, object_pairs_hook=unique)
        if not isinstance(generated, dict):
            raise ValueError('generated boot bindings must be an object')
    boot_policy = None
    if args.boot_policy is not None:
        with opened(args.boot_policy) as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise ValueError('boot policy input too large')
        boot_policy = json.loads(raw, object_pairs_hook=unique)
    result = (stage(args.image, args.boot_archive, args.image_receipt, args.output, generated=generated, signing=signing, efi=efi, media=media, root_path=args.root_path, boot_policy=boot_policy, verity_image=args.verity_image, verity_descriptor=args.verity_descriptor) if args.output is not None
              else verify(args.image, args.boot_archive, args.image_receipt,
                          verity_image=args.verity_image, verity_descriptor=args.verity_descriptor))
    if boot_policy is not None and args.output is None:
        payload = render_boot_policy(boot_policy, result)
        if 'transition' in boot_policy:
            transition = render_boot_transition(boot_policy, result)
            result['root_transition'] = dict(version=1, bytes=len(transition),
                sha256=hashlib.sha256(transition).hexdigest(), manifest_signed=False,
                loader_consumed=False, kernel_admission_enabled=False,
                target_resource_limits_verified=False)
        result['startup_contract'] = dict(payload=payload.decode('ascii'),
            sha256=hashlib.sha256(payload).hexdigest(), signed=False,
            transport_paths_bound=False, startup_integration_verified=False)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
