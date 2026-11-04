# SPDX-License-Identifier: BSD-2-Clause
"""Bind original Make archive inputs to explicit passed reference receipts."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex


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


def audit_links(objects, libraries):
    """Prove bound archives occur in completed original compiler/linker recipes.

    Custom boot Makefiles do not use LDADD. Fresh metadata is required instead
    of assuming that a queried Make variable was actually consumed.
    """
    objects = Path(objects).resolve(strict=True)
    found = {}
    commands = []
    for meta in sorted(objects.rglob('*.meta')):
        text = meta.read_text()
        cwd_rows = [line[4:] for line in text.splitlines() if line.startswith('CWD ')]
        if len(cwd_rows) != 1:
            continue
        cwd = Path(cwd_rows[0]).resolve(strict=True)
        if not cwd.is_relative_to(objects):
            raise ValueError('original link metadata CWD escapes reference objects')
        for line in text.splitlines():
            if not line.startswith('CMD ') or not line[4:].strip():
                continue
            lexer = shlex.shlex(line[4:], posix=True, punctuation_chars=';&|<>()')
            lexer.whitespace_split = True
            argv = list(lexer)
            # A path printed by a later shell command is not a linker operand.
            if any(token and all(c in ';&|<>()' for c in token) for token in argv):
                continue
            if any('$' in token or '`' in token for token in argv):
                continue
            if (not argv or Path(argv[0]).name not in ('cc', 'c++', 'clang', 'clang++', 'ld', 'ld.lld', 'lld') or
                    any(flag in argv for flag in ('-c', '-E', '-S')) or argv.count('-o') != 1):
                continue
            selected = {name for name, record in libraries.items() if record['artifact'] in argv}
            if not selected:
                continue
            output_arg = argv[argv.index('-o') + 1]
            output = (cwd / output_arg).resolve(strict=True)
            expected = meta.with_suffix('').resolve(strict=True)
            if output != expected or not output.is_relative_to(objects) or not output.is_file():
                raise ValueError('original link metadata output differs from completed target')
            item = dict(metadata=str(meta), metadata_sha256=digest(meta), argv=argv,
                        output=str(output), output_sha256=digest(output), libraries=sorted(selected))
            commands.append(item)
            for name in selected:
                found.setdefault(name, []).append(str(meta))
    if set(found) != set(libraries):
        raise ValueError('bound original archives absent from completed link recipes: ' +
                         ', '.join(sorted(set(libraries) - set(found))))
    return dict(libraries=found, commands=commands)
