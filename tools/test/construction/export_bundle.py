#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Fixed-member tar transport for an image, boot archive and their unsigned receipt.

Never extract archive paths. The boot archive remains opaque here; its metadata
must be reconstructed and reconciled separately before boot-media signing.
"""
import hashlib
import io
import json
import os
import re
from pathlib import Path
import tarfile

NAMES = ('image.ufs', 'boot.tar', 'image-receipt.json')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def bindings(receipt):
    boot = receipt.get('boot_archive', {})
    if (receipt.get('scope') != 'trusted-builder-filesystem-image' or receipt.get('result') != 'PASS' or
            receipt.get('generation_authenticated') is not False or receipt.get('activation_authorized') is not False or
            not isinstance(boot, dict) or boot.get('scope') != 'generation-boot-transport' or boot.get('result') != 'PASS' or
            boot.get('generation_authenticated') is not False or boot.get('activation_authorized') is not False or
            boot.get('metadata_reconstruction_required') is not True or
            not isinstance(receipt.get('source_observation_sha256'), str) or
            not re.fullmatch('[0-9a-f]{64}', receipt['source_observation_sha256']) or
            boot.get('source_observation_sha256') != receipt['source_observation_sha256']):
        raise ValueError('image and boot archive lack a common completed observation')
    return {'image.ufs': (receipt.get('image_bytes'), receipt.get('image_sha256')),
            'boot.tar': (boot.get('archive_bytes'), boot.get('archive_sha256'))}


def create(image, boot, receipt, destination):
    files = {'image.ufs': Path(image), 'boot.tar': Path(boot)}
    expected = bindings(receipt)
    for name, path in files.items():
        if (path.is_symlink() or not path.is_file() or
                (path.stat().st_size, digest(path)) != expected[name]):
            raise ValueError('bundle source differs from image receipt: ' + name)
    destination = Path(destination)
    with destination.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name, path in files.items():
                entry = tarfile.TarInfo(name); entry.mode = 0o600; entry.size = path.stat().st_size
                with path.open('rb') as data:
                    archive.addfile(entry, data)
            data = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode()
            entry = tarfile.TarInfo('image-receipt.json'); entry.mode = 0o600; entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    for name, path in files.items():
        if (path.stat().st_size, digest(path)) != expected[name]:
            raise ValueError('bundle source changed: ' + name)
    return {'scope': 'verified-image-boot-bundle', 'result': 'PASS',
            'bundle_bytes': destination.stat().st_size, 'bundle_sha256': digest(destination)}


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate receipt key')
        result[key] = value
    return result


def collect(path, destination):
    """Validate every member before creating a fresh private collection directory."""
    destination = Path(destination)
    with tarfile.open(path, mode='r:') as archive:
        members = archive.getmembers()
        if tuple(m.name for m in members) != NAMES or any(not m.isfile() for m in members):
            raise ValueError('bundle must contain exactly three ordered regular members')
        # Bound metadata allocation separately from large streaming payloads.
        if not 0 < members[2].size <= 64 * 1048576:
            raise ValueError('bundle receipt size invalid')
        with archive.extractfile(members[2]) as stream:
            receipt = json.loads(stream.read(), object_pairs_hook=unique)
        if not isinstance(receipt, dict):
            raise ValueError('invalid bundle receipt')
        expected = bindings(receipt)
        for member in members[:2]:
            size, sha = expected[member.name]
            if type(size) is not int or size <= 0 or member.size != size:
                raise ValueError('bundle member size differs from receipt')
            with archive.extractfile(member) as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != sha:
                    raise ValueError('bundle member digest differs from receipt')
        destination.mkdir(mode=0o700)
        for member in members:
            # Names come from our fixed schema; tarfile never creates any paths.
            with (destination / member.name).open('xb') as output, archive.extractfile(member) as source:
                os.fchmod(output.fileno(), 0o600)
                while chunk := source.read(1048576):
                    output.write(chunk)
                output.flush(); os.fsync(output.fileno())
        for name, (size, sha) in expected.items():
            if ((destination / name).stat().st_size, digest(destination / name)) != (size, sha):
                raise ValueError('collected bundle member changed')
    return {'directory': str(destination), 'image_sha256': receipt['image_sha256'],
            'boot_archive_sha256': receipt['boot_archive']['archive_sha256'],
            'source_observation_sha256': receipt['source_observation_sha256']}
