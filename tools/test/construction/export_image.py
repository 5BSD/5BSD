#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Export an image to the disposable verifier VM's declared new output disk."""
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def export(image, receipt, capacity_mib, *, kind="image"):
    if kind not in ("image", "bundle", "layout"):
        raise ValueError("unsupported export kind")
    receipt_scope = {"image": "trusted-builder-filesystem-image",
                     "bundle": "verified-image-boot-bundle",
                     "layout": "split-image-layout-transport"}[kind]
    payload_hash = receipt.get(kind + "_sha256")
    if os.geteuid() != 0 or subprocess.check_output(
            ['/sbin/sysctl', '-n', 'kern.vm_guest'], text=True).strip() in ('', 'none'):
        raise ValueError('image export requires root in the disposable verifier VM')
    if type(capacity_mib) is not int or not 16 <= capacity_mib <= 16384:
        raise ValueError('explicit output capacity required')
    image = Path(image)
    if image.is_symlink() or not image.is_file():
        raise ValueError('image must be a regular nonsymlink file')
    if (receipt.get('scope') != receipt_scope or receipt.get('result') != 'PASS' or
            receipt.get(kind + '_bytes') != image.stat().st_size or
            payload_hash != file_hash(image)):
        raise ValueError('image does not match successful read-back receipt')
    if Path('/tests/output-device').read_text() != '/dev/vtbd2\n':
        raise ValueError('unexpected declared output device')
    device = '/dev/vtbd2'
    fields = subprocess.check_output(['/usr/sbin/diskinfo', device], text=True).split()
    if len(fields) < 3 or fields[0] != device or not all(x.isdecimal() for x in fields[1:3]):
        raise ValueError('invalid output disk geometry')
    sector, capacity = map(int, fields[1:3])
    size = image.stat().st_size
    if (sector <= 0 or 1048576 % sector or capacity != capacity_mib * 1048576 or
            size <= 0 or size > capacity or size % sector):
        raise ValueError('image does not fit the declared output disk geometry')
    fd = os.open(device, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISCHR(os.fstat(fd).st_mode):
            raise ValueError('output device is not a character device')
        expected = hashlib.sha256()
        offset = 0
        with image.open('rb') as stream:
            while offset < capacity:
                count = min(1048576, capacity - offset)
                if offset < size:
                    chunk = stream.read(min(count, size - offset))
                    if not chunk:
                        raise ValueError('image shortened during export')
                else:
                    chunk = bytes(count)
                written = os.pwrite(fd, chunk, offset)
                if written != len(chunk):
                    raise ValueError('short output disk write')
                expected.update(chunk); offset += len(chunk)
        os.fsync(fd)
        actual = hashlib.sha256(); offset = 0
        while offset < capacity:
            chunk = os.pread(fd, min(1048576, capacity - offset), offset)
            if not chunk:
                raise ValueError('short output disk read-back')
            actual.update(chunk); offset += len(chunk)
        if actual.digest() != expected.digest() or file_hash(image) != payload_hash:
            raise ValueError('image export changed bytes')
    finally:
        os.close(fd)
    return dict({'result': 'PASS', 'scope': 'private-' + kind + '-export',
                 kind + '_bytes': size, kind + '_sha256': payload_hash}, output_bytes=capacity,
                output_sha256=actual.hexdigest(), generation_authenticated=False,
                activation_authorized=False)


def collect(work):
    """Bind post-shutdown output to one successful guest export and extract UFS."""
    work = Path(work)
    vm = work / 'vm'
    result = json.loads((vm / 'result.json').read_text())
    if (not isinstance(result, dict) or result.get('result') != 'PASS' or
            result.get('forced_termination') is not False or result.get('qemu_exit') != 0 or
            result.get('input_disk_readonly') is not True or
            not isinstance(result.get('input_disk_sha256'), str) or
            not re.fullmatch('[0-9a-f]{64}', result['input_disk_sha256']) or
            result.get('input_disk_final_sha256') != result['input_disk_sha256']):
        raise ValueError('VM did not finish with an unchanged input')
    records = [json.loads(line.split(' ', 1)[1]) for line in (vm / 'serial.log').read_text().splitlines()
               if line.startswith('IMAGE_EXPORT_RESULT ')]
    if len(records) != 1:
        raise ValueError('requires exactly one completed image export')
    record = records[0]
    if not isinstance(record, dict):
        raise ValueError('invalid image export record')
    kind = {'private-image-export': 'image', 'private-bundle-export': 'bundle',
            'private-layout-export': 'layout'}.get(record.get('scope'))
    if kind is None:
        raise ValueError('unknown export scope')
    raw = vm / 'output.img'
    size, capacity = record.get(kind + '_bytes'), record.get('output_bytes')
    if (type(result.get('output_disk_mib')) is not int or
            not 16 <= result['output_disk_mib'] <= 16384 or
            capacity != result['output_disk_mib'] * 1048576 or
            record.get('generation_authenticated') is not False or record.get('activation_authorized') is not False or
            record.get('result') != 'PASS' or record.get('scope') != 'private-' + kind + '-export' or
            type(size) is not int or type(capacity) is not int or not 0 < size <= capacity or
            raw.is_symlink() or not raw.is_file() or raw.stat().st_size != capacity or
            result.get('output_disk_sha256') != record.get('output_sha256') or
            file_hash(raw) != record.get('output_sha256')):
        raise ValueError('post-shutdown output does not match guest export')
    target = work / {'image': 'image.ufs', 'bundle': 'generation.tar', 'layout': 'layout.tar'}[kind]
    digest = hashlib.sha256()
    with target.open('xb') as output, raw.open('rb') as source:
        os.fchmod(output.fileno(), 0o600)
        remaining = size
        while remaining:
            chunk = source.read(min(1048576, remaining))
            if not chunk:
                raise ValueError('short exported image')
            output.write(chunk); digest.update(chunk); remaining -= len(chunk)
        output.flush(); os.fsync(output.fileno())
    if digest.hexdigest() != record.get(kind + '_sha256'):
        raise ValueError('extracted image digest differs')
    artifacts = {}
    if kind == 'bundle':
        from export_bundle import collect as collect_bundle
        artifacts = collect_bundle(target, work / 'generation')
    elif kind == 'layout':
        from export_layout import collect as collect_layout
        artifacts = collect_layout(target, work / 'layout')
    report = dict(record, artifact_path=str(target), artifacts=artifacts, vm_result_sha256=file_hash(vm / 'result.json'),
                  scope='post-shutdown-' + kind + '-export', generation_authenticated=False,
                  activation_authorized=False)
    if kind == 'image':
        report['image_path'] = str(target)
    with (work / (kind + '.json')).open('x') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    return report
