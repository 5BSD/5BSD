# SPDX-License-Identifier: BSD-2-Clause
"""Bind original Make library inputs to explicit passed reference receipts."""
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
            raise ValueError('original library override must name a LIB variable')
        required = {'receipt', 'receipt_sha256', 'artifact', 'artifact_sha256'}
        if not isinstance(item, dict) or not required <= set(item) <= required | {'kind', 'include_directories'}:
            raise ValueError('exact original library receipt/artifact binding required')
        kind = item.get('kind', 'archive')
        if kind not in ('archive', 'shared'):
            raise ValueError('original library kind must be archive or shared')
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
        if artifact != unresolved or not artifact.is_relative_to(reference.parent / 'objects' / str(component).lstrip('/')):
            raise ValueError('original archive must be a regular object-tree artifact')
        if digest(artifact) != item['artifact_sha256']:
            raise ValueError('original library artifact digest mismatch')
        with artifact.open('rb') as stream:
            header = stream.read(20)
        if kind == 'archive':
            if artifact.suffix != '.a' or header[:8] != b'!<arch>\n':
                raise ValueError('regular original archive required; thin/script inputs are not supported')
        else:
            machine = {'amd64': 62, 'aarch64': 183, 'riscv64': 243}[architecture]
            if (not re.fullmatch(r'lib.+\.so(?:\.[0-9]+)*', artifact.name) or
                    header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[16:18], 'little') != 3 or
                    int.from_bytes(header[18:20], 'little') != machine):
                raise ValueError('original shared input must be a target ELF64 dynamic library')
        records[variable] = dict(receipt=str(reference), receipt_sha256=item['receipt_sha256'],
            artifact=str(artifact), artifact_sha256=item['artifact_sha256'], component=str(component), kind=kind)
        if 'include_directories' in item:
            headers, header_bindings = load_headers(reference.parent, receipt, item['include_directories'])
            records[variable]['include_directories'] = headers
            bindings.update(header_bindings)
        bindings.update({str(reference): item['receipt_sha256'], str(artifact): item['artifact_sha256'], str(selected): compiler_sha})
    verify(bindings)
    verify_headers(records)
    return records, bindings


def verify(bindings):
    for name, expected in bindings.items():
        if digest(Path(name)) != expected:
            raise ValueError('original library input changed: ' + name)


def linked_archives(argv, cwd, libraries):
    """Resolve bound operands and ordinary -L/-l archive search, fail closed.

    Only explicit search directories are considered. A shared library or another
    archive earlier in the search order cannot witness the requested archive.
    Response files, alternate search syntax and mode switches require a separate
    resolver before they can witness a named archive.
    """
    selected = {name for name, row in libraries.items() if row['artifact'] in argv}
    pending = {name: row for name, row in libraries.items() if name not in selected}
    if not pending:
        return selected
    flags = []
    directories = []
    index = 1
    ambiguous = False
    while index < len(argv):
        arg = argv[index]
        if arg == '-L':
            index += 1
            if index == len(argv):
                return selected
            value = argv[index]
            directories.append(value)
        elif arg.startswith('-L'):
            directories.append(arg[2:])
        elif arg == '-l':
            index += 1
            if index == len(argv):
                return selected
            flags.append(argv[index])
        elif arg.startswith('-l'):
            flags.append(arg[2:])
        elif (arg.startswith(('@', '--library-path')) or
              (arg.startswith('-Wl,') and any(v.startswith(('-L', '-l', '--library-path'))
                  for v in arg[4:].split(','))) or
              arg in ('-static', '--static', '-Bstatic', '-Bdynamic') or
              '-Bstatic' in arg or '-Bdynamic' in arg):
            ambiguous = True
        index += 1
    if ambiguous:
        return selected
    for name, row in pending.items():
        artifact = Path(row['artifact']).resolve(strict=True)
        if row.get('kind', 'archive') == 'shared':
            match = re.fullmatch(r'lib(.+)\.so(?:\.[0-9]+)*', artifact.name)
            if not match:
                continue
            ordinary = match.group(1)
        else:
            if not artifact.name.startswith('lib') or artifact.suffix != '.a':
                continue
            ordinary = artifact.name[3:-2]
        for flag in flags:
            if flag not in (ordinary, ':' + artifact.name):
                continue
            candidates = [artifact.name] if flag.startswith(':') else ['lib' + flag + '.so', 'lib' + flag + '.a']
            first = None
            for directory in directories:
                if not directory or directory.startswith('='):
                    # The sysroot-relative linker syntax is not a filesystem path.
                    first = False
                    break
                base = Path(directory)
                if not base.is_absolute():
                    base = cwd / base
                for filename in candidates:
                    candidate = base / filename
                    if candidate.exists() or candidate.is_symlink():
                        first = candidate.resolve(strict=True)
                        break
                if first is not None:
                    break
            if first == artifact:
                selected.add(name)
    return selected


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
            selected = linked_archives(argv, cwd, libraries)
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


def load_headers(root, receipt, directories):
    """Bind explicitly selected original stage include directories and payloads."""
    if not isinstance(directories, list) or not directories or any(not isinstance(value, str) for value in directories) or len(set(directories)) != len(directories):
        raise ValueError('distinct nonempty original include directory list required')
    metadata = root / 'component.METALOG'
    expected = receipt.get('metadata_phases', {}).get('component.METALOG')
    if not expected or digest(metadata) != expected:
        raise ValueError('original header installation metadata digest mismatch')
    installed = {}
    for line in metadata.read_text().splitlines():
        words = shlex.split(line)
        if not words:
            continue
        values = dict(word.split('=', 1) for word in words[1:])
        if values.get('type') == 'file':
            installed[words[0].removeprefix('./')] = values.get('sha256')
    records = []
    bindings = {str(metadata): expected}
    stage = (root / 'stage').resolve(strict=True)
    for relative in directories:
        if not isinstance(relative, str) or not relative or PurePosixPath(relative).is_absolute() or '..' in relative.split('/') or str(PurePosixPath(relative)) != relative:
            raise ValueError('canonical relative original include directory required')
        unresolved = root / relative
        directory = safe_path(str(unresolved), True)
        if directory != unresolved or directory == stage or not directory.is_relative_to(stage) or not directory.is_dir():
            raise ValueError('original include directory must be contained in reference stage')
        files = header_inventory(directory)
        if not files:
            raise ValueError('original include directory is empty')
        for name, content in files.items():
            installed_name = str((directory / name).relative_to(stage))
            if installed.get(installed_name) != content:
                raise ValueError('original include payload differs from installation metadata')
            bindings[str(directory / name)] = content
        records.append(dict(directory=str(directory), files=files))
    return records, bindings


def header_inventory(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            raise ValueError('original include directory cannot contain symlinks')
        if path.is_file():
            result[str(path.relative_to(directory))] = digest(path)
        elif not path.is_dir():
            raise ValueError('unsupported original include directory entry')
    return result


def verify_headers(libraries):
    for library in libraries.values():
        for record in library.get('include_directories', []):
            if header_inventory(Path(record['directory'])) != record['files']:
                raise ValueError('original include directory contents changed')


def audit_header_dependencies(objects, libraries):
    records = {record['directory']: [] for library in libraries.values() for record in library.get('include_directories', [])}
    for dependency in sorted(objects.rglob('.depend.*')):
        if not dependency.is_file() or dependency.name.endswith('.meta'):
            continue
        words = shlex.split(dependency.read_text().replace('\\\n', ' '))
        for directory in records:
            used = [word for word in words if word.startswith(directory + '/')]
            if used:
                records[directory].append(dict(dependency=str(dependency), sha256=digest(dependency), headers=used))
    if any(not values for values in records.values()):
        raise ValueError('bound original include directory absent from compiler dependencies')
    return records
