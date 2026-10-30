#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Transport all split-image artifacts; does not authenticate or approve a layout.

Collection checks bytes against the transported receipt. The caller must run
verify_layout with independently selected construction inputs before acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile

LIMIT = 64 * 1024 * 1024


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def decode(raw):
    if not 0 < len(raw) <= LIMIT:
        raise ValueError('layout receipt exceeds metadata limit')
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError('layout receipt must be an object')
    return value


def members(report):
    """Derive names locally; never use archive or receipt paths for extraction."""
    if (report.get('format') != 1 or report.get('result') != 'PASS' or
            report.get('scope') != 'trusted-builder-storage-images' or
            any(report.get(k) is not False for k in ('generation_authenticated',
                'activation_authorized', 'seeds_installed', 'attachments_constructed'))):
        raise ValueError('requires completed unauthenticated layout receipt')
    images = report.get('images')
    if not isinstance(images, list) or not images:
        raise ValueError('missing layout images')
    result = {}
    for index, entry in enumerate(images):
        directory = 'base' if index == 0 else 'seed-' + str(index)
        if not isinstance(entry, dict) or entry.get('directory') != directory:
            raise ValueError('unexpected partition directory')
        receipt = entry.get('receipt')
        if (not isinstance(receipt, dict) or receipt.get('result') != 'PASS' or
                receipt.get('scope') != 'trusted-builder-partition-image' or
                receipt.get('source_observation_sha256') != report.get('source_observation_sha256') or
                any(receipt.get(k) is not False for k in ('inputs_authenticated',
                    'generation_authenticated', 'activation_authorized'))):
            raise ValueError('incomplete partition receipt')
        result[directory + '/receipt.json'] = (None, None, receipt)
        result[directory + '/filesystem.mtree'] = (None, receipt.get('manifest_sha256'), None)
        result[directory + '/system.ufs'] = (receipt.get('image_bytes'), receipt.get('image_sha256'), None)
        verity = receipt.get('verity')
        if verity is not None:
            if index != 0 or not isinstance(verity, dict):
                raise ValueError('unexpected verity image')
            result[directory + '/system.verity'] = (verity.get('image_bytes'), verity.get('image_sha256'), None)
            result[directory + '/root.descriptor'] = (384, verity.get('descriptor_sha256'), None)
        boot = receipt.get('boot_archive')
        if boot is not None:
            if index != 0 or not isinstance(boot, dict) or boot.get('result') != 'PASS':
                raise ValueError('unexpected boot archive')
            result[directory + '/boot.tar'] = (boot.get('archive_bytes'), boot.get('archive_sha256'), None)
    for name, (size, sha, record) in result.items():
        if record is None and (not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha)):
            raise ValueError('missing artifact hash: ' + name)
        if name.endswith(('.ufs', '.tar', '.verity', '.descriptor')) and (type(size) is not int or size <= 0):
            raise ValueError('invalid artifact size: ' + name)
    return result


def check(stream, size, expected):
    length, sha, record = expected
    if length is not None and size != length:
        raise ValueError('artifact size differs')
    if record is not None:
        if size > LIMIT or decode(stream.read(LIMIT + 1)) != record:
            raise ValueError('partition receipt differs')
    elif hashlib.file_digest(stream, 'sha256').hexdigest() != sha:
        raise ValueError('artifact hash differs')


def physical(root, name):
    path = root
    for part in name.split('/'):
        path = path / part
        if path.is_symlink():
            raise ValueError('symlink in layout transport input')
    if not path.is_file():
        raise ValueError('missing regular layout artifact')
    return path


def create(work, destination):
    work = Path(work)
    if work.is_symlink() or not work.is_dir():
        raise ValueError('layout directory must be physical')
    report = decode(physical(work, 'receipt.json').read_bytes())
    expected = members(report)
    names = ['receipt.json', *expected]
    hashes = {}
    for name in names:
        path = physical(work, name)
        if name in expected:
            with path.open('rb') as stream:
                check(stream, path.stat().st_size, expected[name])
        hashes[name] = digest(path)
    with Path(destination).open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name in names:
                path = physical(work, name)
                entry = tarfile.TarInfo(name); entry.mode = 0o600; entry.size = path.stat().st_size
                with path.open('rb') as source:
                    archive.addfile(entry, source)
        stream.flush(); os.fsync(stream.fileno())
    if any(digest(physical(work, name)) != sha for name, sha in hashes.items()):
        raise ValueError('layout artifact changed during transport')
    return dict(scope='split-image-layout-transport', result='PASS',
        layout_bytes=Path(destination).stat().st_size, layout_sha256=digest(destination),
        generation_authenticated=False, selected_inputs_verified=False)


def collect(path, destination):
    destination = Path(destination)
    with tarfile.open(path, mode='r:') as archive:
        first = archive.next()
        if first is None or first.name != 'receipt.json' or not first.isfile() or not 0 < first.size <= LIMIT:
            raise ValueError('layout receipt must be first regular member')
        with archive.extractfile(first) as stream:
            report = decode(stream.read(LIMIT + 1))
        expected = members(report)
        entries = [first]
        for name, binding in expected.items():
            entry = archive.next()
            if entry is None or entry.name != name or not entry.isfile():
                raise ValueError('layout member missing or unexpected')
            with archive.extractfile(entry) as stream:
                check(stream, entry.size, binding)
            entries.append(entry)
        if archive.next() is not None:
            raise ValueError('extra layout member')
        destination.mkdir(mode=0o700)
        for entry in entries:
            # All names matched locally derived names; tar never extracts paths.
            target = destination / entry.name
            target.parent.mkdir(mode=0o700, exist_ok=True)
            with target.open('xb') as output, archive.extractfile(entry) as source:
                os.fchmod(output.fileno(), 0o600)
                while chunk := source.read(1048576):
                    output.write(chunk)
                output.flush(); os.fsync(output.fileno())
        if decode((destination / 'receipt.json').read_bytes()) != report:
            raise ValueError('collected layout receipt changed')
        for name, binding in expected.items():
            target = physical(destination, name)
            with target.open('rb') as stream:
                check(stream, target.stat().st_size, binding)
    return dict(scope='collected-split-image-layout', result='PASS', directory=str(destination),
        receipt_sha256=digest(destination / 'receipt.json'), generation_authenticated=False,
        selected_inputs_verified=False, filesystem_readback_repeated=False)
