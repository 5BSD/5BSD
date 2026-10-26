#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Inventory package payloads without extraction or executing package scripts.

Authentication is the caller's responsibility: deployment calls this only on
archives fetched through its authenticated pkg catalogue. This module does not
consult the installed package database, assign BIP classes, or certify a system.
"""
import ctypes as C
from ctypes.util import find_library
import hashlib
import json
import os
import re
from pathlib import Path
import stat
from urllib.parse import unquote_to_bytes


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate package manifest key: ' + key)
        result[key] = value
    return result


def canonical_path(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise ValueError('invalid package pathname')
    value = value.removeprefix('./')
    if not value.startswith('/'):
        value = '/' + value
    # libarchive directory headers conventionally carry a trailing slash.
    value = value.removesuffix('/')
    if not value or any(p in ('', '.', '..') for p in value.split('/')[1:]):
        raise ValueError('noncanonical package pathname: ' + repr(value))
    return value



def manifest_path(value):
    # pkg's url_decode performs one percent-decoding pass; '+' is literal.
    # Archive headers already contain raw pathnames and must not use this.
    if not isinstance(value, str):
        raise ValueError('invalid package manifest pathname')
    return canonical_path(unquote_to_bytes(value).decode('utf-8', errors='strict'))


def invalid_constant(value):
    raise ValueError('non-JSON package manifest constant: ' + value)


def archive_library():
    library = C.CDLL(find_library('archive') or 'libarchive.so')
    functions = {
        'archive_read_new': (C.c_void_p, []),
        'archive_read_support_filter_none': (C.c_int, [C.c_void_p]),
        'archive_read_support_filter_gzip': (C.c_int, [C.c_void_p]),
        'archive_read_support_filter_bzip2': (C.c_int, [C.c_void_p]),
        'archive_read_support_filter_xz': (C.c_int, [C.c_void_p]),
        'archive_read_support_filter_zstd': (C.c_int, [C.c_void_p]),
        'archive_read_support_format_tar': (C.c_int, [C.c_void_p]),
        'archive_read_open_fd': (C.c_int, [C.c_void_p, C.c_int, C.c_size_t]),
        'archive_read_next_header': (C.c_int, [C.c_void_p, C.POINTER(C.c_void_p)]),
        'archive_read_data': (C.c_ssize_t, [C.c_void_p, C.c_void_p, C.c_size_t]),
        'archive_read_free': (C.c_int, [C.c_void_p]),
        'archive_error_string': (C.c_char_p, [C.c_void_p]),
        'archive_entry_pathname': (C.c_char_p, [C.c_void_p]),
        'archive_entry_hardlink': (C.c_char_p, [C.c_void_p]),
        'archive_entry_symlink': (C.c_char_p, [C.c_void_p]),
        'archive_entry_uname': (C.c_char_p, [C.c_void_p]),
        'archive_entry_gname': (C.c_char_p, [C.c_void_p]),
        'archive_entry_filetype': (C.c_uint, [C.c_void_p]),
        'archive_entry_perm': (C.c_uint, [C.c_void_p]),
        'archive_entry_uid': (C.c_int64, [C.c_void_p]),
        'archive_entry_gid': (C.c_int64, [C.c_void_p]),
        'archive_entry_size': (C.c_int64, [C.c_void_p]),
        'archive_entry_mtime': (C.c_int64, [C.c_void_p]),
        'archive_entry_mtime_nsec': (C.c_long, [C.c_void_p]),
        'archive_entry_new': (C.c_void_p, []),
        'archive_entry_free': (None, [C.c_void_p]),
        'archive_entry_copy_fflags_text': (C.c_char_p, [C.c_void_p, C.c_char_p]),
        'archive_entry_fflags': (None, [C.c_void_p, C.POINTER(C.c_ulong), C.POINTER(C.c_ulong)]),
        'archive_entry_acl_count': (C.c_int, [C.c_void_p, C.c_int]),
        'archive_entry_xattr_count': (C.c_int, [C.c_void_p]),
    }
    for name, (result, args) in functions.items():
        function = getattr(library, name)
        function.restype, function.argtypes = result, args
    return library


def directory_attributes(path, attributes):
    """Validate every manifest assertion, including ones backed by a header."""
    if not isinstance(attributes, dict) or set(attributes) - {'uname', 'gname', 'perm', 'fflags'}:
        raise ValueError('unsupported package directory metadata: ' + path)
    result = {'type': 'directory'}
    for key in ('uname', 'gname'):
        if key in attributes:
            value = attributes[key]
            if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
                raise ValueError('invalid package directory metadata: ' + path)
            result[key] = value
    if 'perm' in attributes:
        value = attributes['perm']
        if not isinstance(value, str) or not re.fullmatch(r'0?[0-7]{3,4}', value):
            raise ValueError('invalid package directory metadata: ' + path)
        result['mode'] = int(value, 8)
    if 'fflags' in attributes:
        value = attributes['fflags']
        if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
            raise ValueError('invalid package directory metadata: ' + path)
        library = archive_library()
        entry = library.archive_entry_new()
        if not entry:
            raise MemoryError('directory metadata allocation failed')
        try:
            if library.archive_entry_copy_fflags_text(entry, value.encode()) is not None:
                raise ValueError('unsupported package directory metadata flags: ' + path)
            flags, clear = C.c_ulong(), C.c_ulong()
            library.archive_entry_fflags(entry, C.byref(flags), C.byref(clear))
            if flags.value & clear.value:
                raise ValueError('conflicting package directory metadata flags: ' + path)
            result.update(flags_set=flags.value, flags_clear=clear.value)
        finally:
            library.archive_entry_free(entry)
    return result


def merge_directory(path, previous, item):
    """Combine compatible assertions without choosing an input by order.

    Named archive ownership supersedes the numeric placeholder in that same
    header. An independently asserted numeric owner cannot be discarded in favor
    of a name: that combination needs account resolution and is rejected here.
    Directory timestamps are intentionally not installation expectations.
    """
    def normalized(source):
        if source.get('type') != 'directory':
            raise ValueError('conflicting package directory metadata: ' + path)
        result = {k: source[k] for k in ('type', 'mode', 'flags_set', 'flags_clear') if k in source}
        for name, numeric in (('uname', 'uid'), ('gname', 'gid')):
            if source.get(name):
                result[name] = source[name]
            elif numeric in source:
                result[numeric] = source[numeric]
        return result

    left, right = normalized(previous), normalized(item)
    for name, numeric in (('uname', 'uid'), ('gname', 'gid')):
        if (name in left and numeric in right) or (numeric in left and name in right):
            raise ValueError('ambiguous package directory metadata ownership: ' + path)
    for key in left.keys() & right.keys() - {'flags_clear'}:
        if left[key] != right[key]:
            raise ValueError('conflicting package directory metadata: ' + path)
    result = dict(left, **right)
    if 'flags_clear' in left or 'flags_clear' in right:
        result['flags_clear'] = left.get('flags_clear', 0) | right.get('flags_clear', 0)
    if result.get('flags_set', 0) & result.get('flags_clear', 0):
        raise ValueError('conflicting package directory metadata flags: ' + path)
    return result


def package_directories(package):
    result = {}
    for path, item in package['entries'].items():
        if item['type'] == 'directory':
            result[path] = merge_directory(path, {'type': 'directory'}, item)
    for path, attributes in package['directories'].items():
        if path in package['entries'] and package['entries'][path]['type'] != 'directory':
            raise ValueError('conflicting package directory metadata: ' + path)
        result[path] = merge_directory(path, result.get(path, {'type': 'directory'}),
                                       directory_attributes(path, attributes))
    return result


def inventory_archive(path, *, manifest_only=False, capture=None):
    # Optional bounded payload reads share the full inventory validation path.
    capture = {} if capture is None else capture
    if manifest_only and capture:
        raise ValueError("payload capture requires full inventory")
    if not isinstance(capture, dict) or any(
            canonical_path(name) != name or type(limit) is not int or
            not 1 <= limit <= 64 * 1024 * 1024 for name, limit in capture.items()):
        raise ValueError("invalid payload capture bounds")
    captured = {}
    path = Path(path)
    archive_path = str(path)
    library = archive_library()
    archive = library.archive_read_new()
    if not archive:
        raise MemoryError('archive allocation failed')
    fd = -1
    entries = {}
    manifests = {}
    buffer = C.create_string_buffer(65536)

    def checked(result):
        if result != 0:
            error = library.archive_error_string(archive)
            raise ValueError('package archive error: ' + (error.decode(errors='replace') if error else str(result)))

    def string(function, entry):
        value = getattr(library, function)(entry)
        return value.decode('utf-8', errors='strict') if value is not None else None

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('package is not a regular file')
        if not manifest_only:
            with os.fdopen(os.dup(fd), 'rb') as stream:
                archive_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
            os.lseek(fd, 0, os.SEEK_SET)
        # pkg compression formats with built-in libarchive support only.
        # Refuse a missing codec rather than enabling external filter programs.
        for codec in ('none', 'gzip', 'bzip2', 'xz', 'zstd'):
            checked(getattr(library, 'archive_read_support_filter_' + codec)(archive))
        checked(library.archive_read_support_format_tar(archive))
        checked(library.archive_read_open_fd(archive, fd, len(buffer)))
        entry = C.c_void_p()
        while True:
            result = library.archive_read_next_header(archive, C.byref(entry))
            if result == 1:  # ARCHIVE_EOF
                break
            checked(result)
            name = string('archive_entry_pathname', entry)
            kind = library.archive_entry_filetype(entry)
            hardlink = string('archive_entry_hardlink', entry)
            target = string('archive_entry_symlink', entry)
            size = library.archive_entry_size(entry)
            if size < 0:
                raise ValueError('negative package member size')
            is_manifest = name in ('+MANIFEST', '+COMPACT_MANIFEST')
            if is_manifest and (kind != stat.S_IFREG or hardlink or size > 64 * 1024 * 1024):
                raise ValueError('invalid package manifest member')
            # Selection reads metadata only; the chosen archives are fully
            # inventoried and checked before any output can be accepted.
            if manifest_only and not is_manifest:
                continue
            selected = (canonical_path(name) if not is_manifest and name and not name.startswith("+") else None)
            limit = capture.get(selected)
            if limit is not None and (kind != stat.S_IFREG or hardlink or size > limit):
                raise ValueError("invalid captured payload: " + selected)
            digest = hashlib.sha256()
            data, count = bytearray(), 0
            while True:
                amount = library.archive_read_data(archive, buffer, len(buffer))
                if amount == 0:
                    break
                if amount < 0:
                    checked(amount)
                count += amount
                digest.update(buffer.raw[:amount])
                if is_manifest or limit is not None:
                    data.extend(buffer.raw[:amount])
                    if len(data) > (limit if limit is not None else 64 * 1024 * 1024):
                        raise ValueError('package manifest exceeds bound')
            if is_manifest:
                if name in manifests or count != size:
                    raise ValueError('duplicate or truncated package manifest')
                manifests[name] = json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)
                if manifest_only and name == '+MANIFEST':
                    manifest = manifests[name]
                    if not isinstance(manifest, dict) or any(
                            not isinstance(manifest.get(key), str) or not manifest[key]
                            for key in ('name', 'version')):
                        raise ValueError('package lacks a complete identity manifest')
                    return manifest
                continue
            if name is None or name.startswith('+'):
                raise ValueError('unsupported package metadata member: ' + repr(name))
            name = canonical_path(name)
            if name in entries:
                raise ValueError('duplicate package payload path: ' + name)
            if limit is not None:
                captured[name] = bytes(data)
            # ACCESS, DEFAULT, ALLOW, DENY, AUDIT and ALARM from archive_entry.h.
            acl_types = 0x3f00
            if library.archive_entry_acl_count(entry, acl_types) or library.archive_entry_xattr_count(entry):
                raise ValueError('ACL/xattr inventory support required: ' + name)
            flags, clear_flags = C.c_ulong(), C.c_ulong()
            library.archive_entry_fflags(entry, C.byref(flags), C.byref(clear_flags))
            item = {'mode': library.archive_entry_perm(entry),
                    'uid': library.archive_entry_uid(entry), 'gid': library.archive_entry_gid(entry),
                    'uname': string('archive_entry_uname', entry),
                    'gname': string('archive_entry_gname', entry),
                    'mtime': library.archive_entry_mtime(entry),
                    'mtime_nsec': library.archive_entry_mtime_nsec(entry),
                    'flags_set': flags.value, 'flags_clear': clear_flags.value}
            if hardlink is not None:
                item.update(type='hardlink', target=canonical_path(hardlink))
                if count:
                    raise ValueError('hardlink carries unexpected data: ' + name)
            elif kind == stat.S_IFREG:
                if count != size:
                    raise ValueError('truncated package payload: ' + name)
                item.update(type='file', size=size, sha256=digest.hexdigest())
            elif kind == stat.S_IFDIR:
                item.update(type='directory')
            elif kind == stat.S_IFLNK and target is not None:
                item.update(type='symlink', target=target)
            else:
                raise ValueError('unsupported package object type: ' + name)
            entries[name] = item
        if manifest_only:
            raise ValueError('package lacks a complete identity manifest')
        os.lseek(fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(fd), 'rb') as stream:
            final_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(fd)
        if archive_hash != final_hash or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('package changed during inventory')
    finally:
        library.archive_read_free(archive)
        if fd >= 0:
            os.close(fd)
    manifest = manifests.get('+MANIFEST')
    if not isinstance(manifest, dict) or any(not isinstance(manifest.get(k), str) or not manifest[k]
                                           for k in ('name', 'version')):
        raise ValueError('package lacks a complete identity manifest')
    declared = manifest.get('files', {})
    if not isinstance(declared, dict):
        raise ValueError('invalid package file map')
    paths = [manifest_path(p) for p in declared]
    if len(paths) != len(set(paths)) or set(paths) != {p for p, item in entries.items() if item['type'] != 'directory'}:
        raise ValueError('package manifest and payload paths disagree')
    compact = manifests.get('+COMPACT_MANIFEST')
    if compact is not None and (not isinstance(compact, dict) or any(
            compact.get(k) != manifest[k] for k in ('name', 'version'))):
        raise ValueError('package manifest identities disagree')
    if compact is not None:
        # pkg repo consumes the compact manifest. pkg 2.8.4's emitter omits
        # only payload/configuration lists and hook bodies in compact mode.
        # Validate the catalogue-facing fields in both directions, including
        # omitted dependencies, rather than checking identity alone.
        full_only = {'files', 'directories', 'config', 'scripts', 'lua_scripts'}
        project = lambda record: {k: v for k, v in record.items() if k not in full_only}
        if (project(compact) != project(manifest) or
                any(compact[k] != manifest.get(k) for k in compact.keys() & full_only)):
            raise ValueError('package compact and full manifest metadata disagree')
    directories = manifest.get('directories', {})
    if not isinstance(directories, dict):
        raise ValueError('invalid package directory map')
    directory_map = {}
    for path, attributes in directories.items():
        path = manifest_path(path)
        if path in directory_map or (path in entries and entries[path]['type'] != 'directory'):
            raise ValueError('conflicting package directory: ' + path)
        directory_map[path] = attributes
    if any(item['type'] == 'directory' and path not in directory_map
           for path, item in entries.items()):
        raise ValueError('undeclared package directory payload')
    package_directories({'entries': entries, 'directories': directory_map})
    config = manifest.get('config', [])
    if not isinstance(config, list):
        raise ValueError('invalid package config list')
    config = [manifest_path(path) for path in config]
    if len(config) != len(set(config)):
        raise ValueError('duplicate package config path')
    if set(captured) != set(capture):
        raise ValueError('captured payload is missing')
    result = {'name': manifest['name'], 'version': manifest['version'],
            'archive_sha256': archive_hash, 'archive': archive_path,
            'entries': dict(sorted(entries.items())),
            'directories': dict(sorted(directory_map.items())),
            'config': config,
            'manifest': manifest,
            'manifest_sha256': hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    if capture:
        result['captured_payloads'] = captured
    return result


# Immutable installation templates are package-owned inputs, not mutable pkg
# configuration and not permission for a running system to replace them.
def installation_templates(package):
    annotations = package.get('manifest', {}).get('annotations', {})
    if not isinstance(annotations, dict):
        raise ValueError('invalid package annotations')
    text = annotations.get('5bsd.installation-templates')
    if text is None:
        return []
    if not isinstance(text, str) or len(text.encode()) > 65536:
        raise ValueError('invalid installation template annotation')
    value = json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    if (not isinstance(value, dict) or set(value) != {'format', 'paths'} or
            type(value['format']) is not int or value['format'] != 1 or
            not isinstance(value['paths'], list) or not 1 <= len(value['paths']) <= 256):
        raise ValueError('invalid installation template declaration')
    result = []
    for path in value['paths']:
        if (not isinstance(path, str) or canonical_path(path) != path or
                path == '/' or path in result):
            raise ValueError('invalid or duplicate installation template path')
        entry = package['entries'].get(path, {})
        if (entry.get('type') != 'file' or entry.get('mode', 0) & 0o111 or
                entry.get('flags_set', 0) or path in package.get('config', [])):
            raise ValueError('installation template must be an owned nonexecutable non-config payload')
        result.append(path)
    return result


# Package-owned construction declarations are data, never an execution grant.
# The completed-generation builder must still verify input bytes, execute in its
# isolated construction environment, and retain a receipt before accepting output.
CONSTRUCTION_ANNOTATION = '5bsd.construction'


def construction_declarations(package):
    annotations = package['manifest'].get('annotations', {})
    if not isinstance(annotations, dict):
        raise ValueError('invalid package annotations')
    if CONSTRUCTION_ANNOTATION not in annotations:
        return []
    text = annotations[CONSTRUCTION_ANNOTATION]
    if not isinstance(text, str) or len(text.encode()) > 1024 * 1024:
        raise ValueError('invalid package construction annotation')
    document = json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    if (not isinstance(document, dict) or set(document) != {'format', 'actions'} or
            type(document['format']) is not int or document['format'] != 1 or
            not isinstance(document['actions'], list) or not 1 <= len(document['actions']) <= 64):
        raise ValueError('invalid package construction declaration')
    actions, names = [], set()

    def path(value):
        if not isinstance(value, str) or canonical_path(value) != value or value == '/':
            raise ValueError('construction paths must be canonical absolute non-root paths')
        return value

    for action in document['actions']:
        if not isinstance(action, dict) or set(action) != {'name', 'argv', 'inputs', 'outputs'}:
            raise ValueError('invalid construction action fields')
        name, argv, inputs, outputs = (action[k] for k in ('name', 'argv', 'inputs', 'outputs'))
        if (not isinstance(name, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name)
                or name in names):
            raise ValueError('invalid or duplicate construction action name')
        names.add(name)
        if (not isinstance(argv, list) or not 1 <= len(argv) <= 4096 or
                any(not isinstance(v, str) or not v or len(v.encode()) > 4096 or
                    any(ord(c) < 32 for c in v) for v in argv)):
            raise ValueError('invalid construction argv')
        if sum(len(v.encode()) + 1 for v in argv) > 128 * 1024:
            raise ValueError('construction argv exceeds byte limit')
        path(argv[0])
        if not isinstance(inputs, list) or not 1 <= len(inputs) <= 1024:
            raise ValueError('invalid construction inputs')
        inputs = [path(v) for v in inputs]
        if len(inputs) != len(set(inputs)):
            raise ValueError('duplicate construction input')
        if not isinstance(outputs, dict) or not 1 <= len(outputs) <= 1024:
            raise ValueError('invalid construction outputs')
        for output, metadata in outputs.items():
            path(output)
            if (not isinstance(metadata, dict) or
                    set(metadata) != {'type', 'uid', 'gid', 'mode', 'flags_set', 'replace'} or
                    metadata['type'] != 'file' or type(metadata['replace']) is not bool):
                raise ValueError('invalid construction output metadata')
            for key, limit in [('uid', 2**32 - 2), ('gid', 2**32 - 2), ('mode', 0o7777), ('flags_set', 2**64 - 1)]:
                if type(metadata[key]) is not int or not 0 <= metadata[key] <= limit:
                    raise ValueError('invalid construction output ' + key)
            if output == argv[0] or output in inputs:
                raise ValueError('construction action cannot overwrite its own inputs')
        actions.append(dict(action, package=package['name'],
                            package_sha256=package['archive_sha256'],
                            declaration_sha256=hashlib.sha256(text.encode()).hexdigest()))
    return actions


def construction_plan(packages, objects, owners, directories):
    actions = [action for package in packages for action in construction_declarations(package)]
    producers = {}
    packages_by_name = {p['name']: p for p in packages}
    # A declaration can generate a new file or explicitly replace its own
    # package payload. It cannot silently take another package's pathname.
    for action in actions:
        for path, metadata in action['outputs'].items():
            if path in producers:
                raise ValueError('conflicting construction output: ' + path)
            owner = owners.get(path)
            if path in directories or (path in objects and objects[path]['type'] != 'file'):
                raise ValueError('construction output conflicts with non-file: ' + path)
            if metadata['replace'] != (owner is not None) or (owner is not None and owner != action['package']):
                raise ValueError('construction replacement must explicitly name its own payload: ' + path)
            producers[path] = action
    all_paths = set(objects) | set(directories) | set(producers)
    for path in all_paths:
        if any(str(parent) in producers or str(parent) in objects for parent in Path(path).parents):
            raise ValueError('construction object has a nondirectory ancestor: ' + path)

    bindings = {}

    def payload_binding(path):
        chain = set()
        while path not in bindings:
            if path in chain:
                raise ValueError('cyclic construction input link')
            chain.add(path)
            item = objects.get(path)
            if item is not None and item['type'] == 'hardlink':
                path = item['target']
                continue
            bindings[path] = (None if item is None or item['type'] != 'file' else
                {'path': path, 'sha256': item['sha256'], 'mode': item['mode'],
                 'archive_sha256': packages_by_name[owners[path]]['archive_sha256']})
        binding = bindings[path]
        for alias in chain:
            bindings[alias] = binding
        return binding

    # A regular payload can have archive hardlink aliases. Replacing it may
    # affect those aliases (depending on the generator's write strategy), so
    # the finite-output format cannot describe that replacement safely.
    for path, item in objects.items():
        if item['type'] == 'hardlink' and payload_binding(path)['path'] in producers:
            raise ValueError('construction output has a package hardlink alias: ' + path)

    pending = list(actions)
    ordered, completed = [], set()
    while pending:
        ready = []
        for action in pending:
            program = action['argv'][0]
            binding = payload_binding(program)
            if program in producers or binding is None or not binding['mode'] & 0o111:
                raise ValueError('construction executable must be a package payload: ' + program)
            for path in action['inputs']:
                if path not in producers and payload_binding(path) is None:
                    raise ValueError('construction input lacks a regular package payload or producer: ' + path)
            dependencies = {id(producers[p]) for p in action['inputs'] if p in producers}
            if dependencies <= completed:
                ready.append(action)
        if not ready:
            raise ValueError('cyclic package construction inputs')
        for action in sorted(ready, key=lambda a: (a['package'], a['name'])):
            ordered.append(dict(action, executable_payload=payload_binding(action['argv'][0]),
                input_sources={p: ({'producer_package': producers[p]['package'],
                                    'producer_action': producers[p]['name']} if p in producers
                                   else {'payload': payload_binding(p)}) for p in action['inputs']}))
            completed.add(id(action))
            pending.remove(action)
    return {'status': 'declared-not-executed', 'outputs_approved': False,
            'actions': ordered}


# Requirements are review inputs, never permission to create/mount/write paths.
STATE_ANNOTATION = '5bsd.state-requirements'


def state_path_review(requirements):
    """Group declared paths for review, without selecting storage or writers.

    Lexical ancestry is a review relationship, not filesystem resolution. The
    generation reconciler must separately account for links and mount boundaries.
    """
    paths = {}
    for item in requirements:
        row = paths.setdefault(item['path'], {'types': set(), 'lifetimes': set(),
            'consumers': [], 'policy_review': 'required'})
        row['types'].add(item['type'])
        row['lifetimes'].add(item['lifetime'])
        row['consumers'].append({key: item[key] for key in ('package', 'name', 'program')})
        if 'directory_mapping' in item:
            row['consumers'][-1]['directory_mapping'] = item['directory_mapping']
    for path, row in paths.items():
        row['types'] = sorted(row['types'])
        row['lifetimes'] = sorted(row['lifetimes'])
        row['consumers'].sort(key=lambda item: (item['package'], item['name']))
        row['conflicts'] = [key for key in ('types', 'lifetimes') if len(row[key]) > 1]
        parts = path.split('/')
        row['declared_ancestors'] = ['/'.join(parts[:n]) for n in range(2, len(parts))
            if '/'.join(parts[:n]) in paths]
        row['file_ancestors'] = [parent for parent in row['declared_ancestors']
            if 'file' in paths[parent]['types']]
        if row['file_ancestors']:
            row['conflicts'].append('file_ancestor')
    return dict(sorted(paths.items()))


def state_requirements(packages):
    requirements, undeclared = [], []
    for package in packages:
        annotations = package.get('manifest', {}).get('annotations', {})
        if not isinstance(annotations, dict):
            raise ValueError('invalid package annotations')
        if STATE_ANNOTATION not in annotations:
            undeclared.append(package['name'])
            continue
        text = annotations[STATE_ANNOTATION]
        if not isinstance(text, str) or len(text.encode()) > 1024 * 1024:
            raise ValueError('invalid state requirements annotation')
        document = json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)
        if (not isinstance(document, dict) or set(document) != {'format', 'requirements'} or
                type(document['format']) is not int or document['format'] not in (1, 2) or
                not isinstance(document['requirements'], list) or len(document['requirements']) > 256):
            raise ValueError('invalid state requirements document')
        names = set()
        for item in document['requirements']:
            required = {'name', 'program', 'path', 'type', 'lifetime', 'purpose'}
            allowed = required | ({'directory_mapping'} if document['format'] == 2 else set())
            if not isinstance(item, dict) or not required <= set(item) <= allowed:
                raise ValueError('invalid state requirement fields')
            if 'directory_mapping' in item:
                mapping = item['directory_mapping']
                if (item['type'] != 'directory' or not isinstance(mapping, str) or
                        canonical_path(mapping) != mapping or mapping in ('/', item['path'])):
                    raise ValueError('invalid state directory mapping')
            name = item['name']
            if (not isinstance(name, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name)
                    or name in names):
                raise ValueError('invalid or duplicate state requirement name')
            names.add(name)
            for key in ('program', 'path'):
                value = item[key]
                if not isinstance(value, str) or canonical_path(value) != value or value == '/':
                    raise ValueError('state requirement needs a canonical non-root ' + key)
            if item['type'] not in ('file', 'directory', 'socket') or item['lifetime'] not in ('boot', 'persistent', 'cache'):
                raise ValueError('invalid state type or lifetime')
            if item['type'] == 'socket' and item['lifetime'] != 'boot':
                raise ValueError('socket state must have boot lifetime')
            purpose = item['purpose']
            if (not isinstance(purpose, str) or not purpose or len(purpose.encode()) > 1024 or
                    any(ord(c) < 32 for c in purpose)):
                raise ValueError('invalid state purpose')
            # Bind the named consumer to this package's executable bytes. A
            # declaration cannot claim another package's executable identity.
            program, seen = item['program'], set()
            while True:
                if program in seen:
                    raise ValueError('cyclic state consumer hardlink')
                seen.add(program)
                payload = package['entries'].get(program)
                if payload is None:
                    raise ValueError('state consumer is not owned by declaring package')
                if payload['type'] != 'hardlink':
                    break
                program = payload['target']
            if (payload['type'] != 'file' or not payload.get('mode', 0) & 0o111 or
                    not re.fullmatch('[0-9a-f]{64}', payload.get('sha256', ''))):
                raise ValueError('state consumer lacks an executable payload binding')
            requirements.append(dict(item, package=package['name'],
                archive_sha256=package['archive_sha256'],
                declaration_sha256=hashlib.sha256(text.encode()).hexdigest(),
                program_payload={'path': program, 'sha256': payload['sha256']},
                policy_review='required'))
    return {'format': 1, 'scope': 'declared-state-requirements',
        'authority_assigned': False, 'runtime_paths_complete': False,
        'path_review': state_path_review(requirements),
        'requirements': sorted(requirements, key=lambda r: (r['package'], r['name'])),
        'packages_without_declarations': sorted(undeclared)}


def inventory_packages(archives):
    packages, owners, directories = [], {}, {}
    names = set()
    for archive in sorted(map(Path, archives)):
        try:
            package = inventory_archive(archive)
        except (ValueError, OSError) as error:
            raise ValueError(str(archive) + ': ' + str(error)) from error
        package['archive'] = str(archive)
        if package['name'] in names:
            raise ValueError('duplicate package identity: ' + package['name'])
        names.add(package['name'])
        for path, item in package['entries'].items():
            if item['type'] == 'directory':
                continue
            if path in owners:
                raise ValueError('conflicting package ownership: ' + path)
            owners[path] = package['name']
        for path, item in package_directories(package).items():
            directories[path] = merge_directory(path, directories.get(path, {'type': 'directory'}), item)
        packages.append(package)
    if not packages:
        raise ValueError('empty package payload inventory')
    if set(owners) & set(directories):
        raise ValueError('package file/directory ownership conflict')
    objects = {path: item for package in packages for path, item in package['entries'].items()
               if item['type'] != 'directory'}
    for path in set(owners) | set(directories):
        if any(str(parent) in owners for parent in Path(path).parents):
            raise ValueError('package object has a nondirectory ancestor: ' + path)
    resolved = {path for path, item in objects.items() if item['type'] == 'file'}
    for path, item in objects.items():
        if item['type'] != 'hardlink' or path in resolved:
            continue
        chain = set()
        target = path
        while target not in resolved:
            if target in chain:
                raise ValueError('cyclic package hardlink: ' + path)
            chain.add(target)
            linked = objects.get(target)
            if linked is None or linked['type'] != 'hardlink':
                raise ValueError('package hardlink lacks a regular payload target: ' + path)
            target = linked['target']
        resolved.update(chain)
    for package in packages:
        installation_templates(package)
    return {'format': 1, 'scope': 'package-payload-inventory',
            'authentication': 'not-performed-by-inventory-reader',
            'filesystem_reconciled': False, 'bip_policy_applied': False,
            'construction': construction_plan(packages, objects, owners, directories),
            'state_requirements': state_requirements(packages),
            'packages': packages}


def repository_inventory(selection):
    """Select dependency roots in a quiescent repository, without trust inference."""
    if set(selection) != {'format', 'repository', 'roots'}:
        raise ValueError('invalid repository selection fields')
    repository, roots = selection['repository'], selection['roots']
    if (not isinstance(repository, str) or not repository.startswith('/') or
            any(part in ('', '.', '..') for part in repository.split('/')[1:])):
        raise ValueError('repository must be a canonical absolute directory')
    repository = Path(repository)
    if not repository.is_dir() or repository.resolve(strict=True) != repository:
        raise ValueError('repository must be a canonical physical directory')
    if (not isinstance(roots, list) or not roots or
            any(not isinstance(name, str) or not name or
                any(ord(c) < 32 for c in name) for name in roots) or
            len(set(roots)) != len(roots)):
        raise ValueError('explicit unique package roots required')
    candidates = {}
    # These are pkg catalogue filenames, not program or package selections.
    for path in sorted(repository.glob('*.pkg')):
        if path.name in ('data.pkg', 'packagesite.pkg', 'meta.pkg'):
            continue
        manifest = inventory_archive(path, manifest_only=True)
        name = manifest['name']
        if name in candidates:
            raise ValueError('duplicate repository package identity: ' + name)
        candidates[name] = (path, manifest)
    pending, selected = list(roots), {}
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        if name not in candidates:
            raise ValueError('repository lacks selected root or dependency: ' + name)
        path, manifest = candidates[name]
        dependencies = manifest.get('deps', {})
        if (not isinstance(dependencies, dict) or
                any(not isinstance(key, str) or not key for key in dependencies)):
            raise ValueError('invalid repository dependency map: ' + name)
        selected[name] = (path, manifest)
        pending.extend(dependencies)
    result = inventory_packages(path for path, _ in selected.values())
    for package in result['packages']:
        if package['name'] not in selected or package['manifest'] != selected[package['name']][1]:
            raise ValueError('selected package manifest changed during inventory')
    result['repository_selection'] = dict(repository=str(repository), roots=sorted(roots))
    return result


def selected_inventory(selection_path):
    """Read explicit archive bindings or repository roots; never infer trust."""
    import importlib.util
    fd = os.open(selection_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('selection must be a regular file')
        raw = stream.read(64 * 1024 * 1024 + 1)
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError('package selection too large')
    selection = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    if not isinstance(selection, dict) or type(selection.get('format')) is not int:
        raise ValueError('invalid package selection format')
    if selection['format'] == 2:
        result = repository_inventory(selection)
    elif selection['format'] == 1:
        if (set(selection) != {'format', 'archives'} or
                not isinstance(selection['archives'], list) or not selection['archives']):
            raise ValueError('requires format-1 nonempty archive selection')
        expected = {}
        for entry in selection['archives']:
            if not isinstance(entry, dict) or set(entry) != {'path', 'sha256'}:
                raise ValueError('invalid selected archive binding')
            path, digest = entry['path'], entry['sha256']
            if (not isinstance(path, str) or not path.startswith('/') or '\0' in path or
                    any(part in ('', '.', '..') for part in path.split('/')[1:]) or
                    path in expected or not isinstance(digest, str) or
                    re.fullmatch('[0-9a-f]{64}', digest) is None):
                raise ValueError('invalid or duplicate selected archive binding')
            expected[path] = digest
        result = inventory_packages(expected)
        for package in result['packages']:
            if package['archive_sha256'] != expected[package['archive']]:
                raise ValueError('selected archive hash mismatch: ' + package['archive'])
    else:
        raise ValueError('unsupported package selection format')
    spec = importlib.util.spec_from_file_location('package_closure', Path(__file__).with_name('package_closure.py'))
    closure = importlib.util.module_from_spec(spec); spec.loader.exec_module(closure)
    manifests = [package['manifest'] for package in result['packages']]
    closure.require_selected_set(manifests)
    result['selection_sha256'] = hashlib.sha256(raw).hexdigest()
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = selected_inventory(args.selection)
    encoded = json.dumps(result, sort_keys=True, indent=2) + '\n'
    with args.output.open('x') as stream:
        stream.write(encoded)
    print('Inventoried %d selected packages; publisher authentication not performed' % len(result['packages']))


if __name__ == '__main__':
    main()
