# SPDX-License-Identifier: BSD-2-Clause
"""Bind original Make archive inputs to explicit passed reference receipts."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_path(value, object_path=False):
    if not isinstance(value, str) or not re.fullmatch(r'/[A-Za-z0-9_./+\-]+', value):
        raise ValueError('library inputs require absolute Make/shell-safe paths')
    path = Path(value).resolve(strict=True)
    if object_path and not path.is_relative_to('/usr/obj'):
        raise ValueError('library reference/artifact must remain under /usr/obj')
    return path


def load(config_path, architecture, source_root, compiler):
    config_path = safe_path(str(config_path))
    before = digest(config_path)
    value = json.loads(config_path.read_text())
    if not isinstance(value, dict) or set(value) != {'format', 'libraries'} or type(value['format']) is not int or value['format'] != 1:
        raise ValueError('exact original library input format 1 required')
    libraries = value['libraries']
    if not isinstance(libraries, dict) or not libraries:
        raise ValueError('nonempty original library inventory required')
    bindings = {str(config_path): before}
    records = {}
    compiler_sha = digest(compiler)
    for variable, item in libraries.items():
        if not re.fullmatch(r'LIB[A-Z0-9_]+', variable):
            raise ValueError('original archive override must name a LIB variable')
        if not isinstance(item, dict) or set(item) != {'receipt', 'receipt_sha256', 'artifact', 'artifact_sha256'}:
            raise ValueError('exact original library receipt/artifact binding required')
        reference = safe_path(item['receipt'], True)
        if digest(reference) != item['receipt_sha256']:
            raise ValueError('original library receipt digest mismatch')
        receipt = json.loads(reference.read_text())
        if type(receipt.get('format')) is not int or receipt.get('format') != 1 or receipt.get('status') != 'passed' or receipt.get('target_architecture') != architecture:
            raise ValueError('original library reference must pass for the selected architecture')
        component = safe_path(receipt.get('component'))
        if not component.is_relative_to(source_root) or component == source_root:
            raise ValueError('original library component differs from source tree')
        environment = receipt.get('environment', {})
        selected = safe_path(environment.get('compiler_selected'), True)
        if digest(selected) != compiler_sha or not any(
                Path(name).is_file() and selected.samefile(name) and expected == compiler_sha
                for name, expected in environment.get('input_sha256', {}).items()):
            raise ValueError('original library compiler differs from selected compiler')
        relative = item['artifact']
        if (not isinstance(relative, str) or not relative or
                PurePosixPath(relative).is_absolute() or '..' in relative.split('/') or
                str(PurePosixPath(relative)) != relative):
            raise ValueError('canonical relative original archive path required')
        unresolved = reference.parent / relative
        artifact = safe_path(str(unresolved), True)
        if artifact != unresolved or not artifact.is_relative_to(reference.parent / 'objects' / str(component).lstrip('/')) or artifact.suffix != '.a':
            raise ValueError('original archive must be a regular object-tree artifact')
        if digest(artifact) != item['artifact_sha256']:
            raise ValueError('original library artifact digest mismatch')
        with artifact.open('rb') as stream:
            if stream.read(8) != b'!<arch>\n':
                raise ValueError('regular original archive required; thin/script inputs are not supported')
        records[variable] = dict(receipt=str(reference), receipt_sha256=item['receipt_sha256'],
            artifact=str(artifact), artifact_sha256=item['artifact_sha256'], component=str(component))
        bindings.update({str(reference): item['receipt_sha256'], str(artifact): item['artifact_sha256'], str(selected): compiler_sha})
    verify(bindings)
    return records, bindings


def verify(bindings):
    for name, expected in bindings.items():
        if digest(Path(name)) != expected:
            raise ValueError('original library input changed: ' + name)
