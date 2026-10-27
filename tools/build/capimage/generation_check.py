#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Reconcile a quiescent alternate filesystem with explicit generation inputs.

This is an offline trusted-builder check, not input authentication, a policy
signer, or a race-proof verifier of a live hostile filesystem.
"""
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

spec = importlib.util.spec_from_file_location('package_inventory', Path(__file__).with_name('package_inventory.py'))
pkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)


# Target VFS lookup limit (sys/sys/param.h), not a host Python/Linux limit.
# Keep the source-alignment regression when changing target lookup semantics.
TARGET_MAXSYMLINKS = 32


def read_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('input is not a regular file: ' + str(path))
        data = stream.read()
    return json.loads(data, object_pairs_hook=pkg.unique_object,
                      parse_constant=pkg.invalid_constant), hashlib.sha256(data).hexdigest()


def pathname(path):
    if path == '/':
        return path
    if not isinstance(path, str) or pkg.canonical_path(path) != path:
        raise ValueError('generation path must be canonical and absolute')
    return path


def scan(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or root.resolve() == Path('/'):
        raise ValueError('requires an alternate directory, not a symlink or live root')
    root = root.resolve(strict=True)
    lib = pkg.archive_library()
    functions = {
        'archive_read_disk_new': (C.c_void_p, []),
        'archive_read_disk_open': (C.c_int, [C.c_void_p, C.c_char_p]),
        'archive_read_disk_set_symlink_physical': (C.c_int, [C.c_void_p]),
        'archive_read_disk_descend': (C.c_int, [C.c_void_p]),
        'archive_read_disk_current_filesystem': (C.c_int, [C.c_void_p]),
        'archive_entry_dev': (C.c_uint64, [C.c_void_p]),
        'archive_entry_ino64': (C.c_int64, [C.c_void_p]),
        'archive_entry_nlink': (C.c_uint, [C.c_void_p]),
        'archive_entry_ctime': (C.c_int64, [C.c_void_p]),
        'archive_entry_ctime_nsec': (C.c_long, [C.c_void_p]),
    }
    for name, (result, args) in functions.items():
        function = getattr(lib, name)
        function.restype, function.argtypes = result, args
    reader = lib.archive_read_disk_new()
    if not reader:
        raise MemoryError('disk reader allocation failed')

    def checked(value):
        if value != 0:
            error = lib.archive_error_string(reader)
            raise ValueError('filesystem inventory: ' + (error.decode(errors='replace') if error else str(value)))

    entries, inodes, contents = {}, {}, {}
    buffer = C.create_string_buffer(65536)
    filesystem = None
    try:
        checked(lib.archive_read_disk_set_symlink_physical(reader))
        checked(lib.archive_read_disk_open(reader, os.fsencode(root)))
        entry = C.c_void_p()
        while True:
            status = lib.archive_read_next_header(reader, C.byref(entry))
            if status == 1:
                break
            checked(status)
            current_fs = lib.archive_read_disk_current_filesystem(reader)
            if filesystem is None:
                filesystem = current_fs
            if current_fs < 0 or current_fs != filesystem:
                raise ValueError('nested filesystem in generation')
            source = Path(lib.archive_entry_pathname(entry).decode('utf-8', errors='strict'))
            source_name = str(source)
            root_name = str(root)
            if source_name == root_name:
                path = '/'
            elif source_name.startswith(root_name + '/'):
                path = pathname(source_name[len(root_name):])
            else:
                raise ValueError('filesystem path escapes generation: ' + source_name)
            if path in entries:
                raise ValueError('duplicate filesystem path: ' + path)
            if lib.archive_entry_acl_count(entry, 0x3f00) or lib.archive_entry_xattr_count(entry):
                raise ValueError('ACL/xattr reconciliation support required: ' + path)
            flags, clear = C.c_ulong(), C.c_ulong()
            lib.archive_entry_fflags(entry, C.byref(flags), C.byref(clear))
            item = {'mode': lib.archive_entry_perm(entry),
                    'uid': lib.archive_entry_uid(entry), 'gid': lib.archive_entry_gid(entry),
                    'flags_set': flags.value,
                    'mtime': lib.archive_entry_mtime(entry),
                    'mtime_nsec': lib.archive_entry_mtime_nsec(entry)}
            identity = (lib.archive_entry_dev(entry), lib.archive_entry_ino64(entry))
            ctime_ns = lib.archive_entry_ctime(entry) * 1000000000 + lib.archive_entry_ctime_nsec(entry)
            kind = lib.archive_entry_filetype(entry)
            if kind == stat.S_IFDIR:
                item['type'] = 'directory'
                checked(lib.archive_read_disk_descend(reader))
            elif kind == stat.S_IFREG:
                # A scan is quiescent. Hardlink aliases name one inode, so
                # read its bytes once per scan while validating every alias's
                # identity/metadata and the complete link set. Never retain
                # this cache across generator executions or separate scans.
                signature = (ctime_ns, lib.archive_entry_size(entry),
                             item['mode'], item['uid'], item['gid'],
                             item['flags_set'], item['mtime'], item['mtime_nsec'])
                if identity in contents:
                    previous, size, sha256 = contents[identity]
                    if signature != previous:
                        raise ValueError('hardlinked file changed during reconciliation: ' + path)
                else:
                    digest, size = hashlib.sha256(), 0
                    while True:
                        amount = lib.archive_read_data(reader, buffer, len(buffer))
                        if amount == 0:
                            break
                        if amount < 0:
                            checked(amount)
                        size += amount
                        digest.update(buffer.raw[:amount])
                    if size != lib.archive_entry_size(entry):
                        raise ValueError('file size changed during reconciliation: ' + path)
                    sha256 = digest.hexdigest()
                    contents[identity] = signature, size, sha256
                item.update(type='file', size=size, sha256=sha256)
                inodes.setdefault(identity, []).append((path, lib.archive_entry_nlink(entry)))
            elif kind == stat.S_IFLNK:
                target = lib.archive_entry_symlink(entry)
                if target is None:
                    raise ValueError('symlink without target: ' + path)
                item.update(type='symlink', target=target.decode('utf-8', errors='strict'))
                inodes.setdefault(identity, []).append((path, lib.archive_entry_nlink(entry)))
            else:
                raise ValueError('unsupported generation object: ' + path)
            after = source.lstat()
            if (after.st_dev, after.st_ino) != identity or after.st_ctime_ns != ctime_ns:
                raise ValueError('filesystem changed during reconciliation: ' + path)
            entries[path] = item
    finally:
        lib.archive_read_free(reader)
    # The complete link set is part of the generation, including undeclared
    # links to otherwise byte-identical objects and links outside the root.
    for links in inodes.values():
        paths = sorted(path for path, count in links)
        if any(count != len(paths) for path, count in links):
            raise ValueError('hardlink escapes generation or changed: ' + paths[0])
        if len(paths) > 1:
            for path in paths:
                entries[path]['hardlinks'] = paths
    return dict(sorted(entries.items()))


def hardlink_groups(expected):
    """Resolve composed hardlinks once per node, without filesystem access."""
    resolved = {path: path for path, item in expected.items() if item['type'] == 'file'}
    groups = {}
    for path, item in expected.items():
        if item['type'] != 'hardlink':
            continue
        target, chain = path, set()
        while target not in resolved:
            if target in chain:
                raise ValueError('cyclic expected hardlink: ' + path)
            chain.add(target)
            linked = expected.get(target)
            if linked is None or linked['type'] != 'hardlink':
                raise ValueError('expected hardlink lacks a regular payload target: ' + path)
            target = linked['target']
        canonical = resolved[target]
        for alias in chain:
            resolved[alias] = canonical
        groups.setdefault(canonical, {canonical}).add(path)
    return groups


def expected_objects(inventory, generated):
    if not isinstance(inventory, dict) or inventory.get('format') != 1 or inventory.get('scope') != 'package-payload-inventory':
        raise ValueError('unsupported package inventory')
    if not isinstance(generated, dict) or set(generated) != {'format', 'entries'} or generated['format'] != 1 or not isinstance(generated['entries'], dict):
        raise ValueError('invalid generated-input manifest')
    expected, owners = {}, {}
    for package in inventory['packages']:
        directories = pkg.package_directories(package)
        for path, item in package['entries'].items():
            pathname(path)
            owners.setdefault(path, set()).add(package['archive_sha256'])
            if item['type'] == 'directory':
                continue
            if path in expected:
                raise ValueError('conflicting package object: ' + path)
            expected[path] = dict(item)
        for path, item in directories.items():
            pathname(path)
            owners.setdefault(path, set()).add(package['archive_sha256'])
            expected[path] = pkg.merge_directory(path, expected.get(path, {'type': 'directory'}), item)
    for path, item in expected.items():
        if item['type'] != 'directory':
            continue
        if ('mode' not in item or not ('uname' in item or 'uid' in item) or
                not ('gname' in item or 'gid' in item)):
            raise ValueError('incomplete package directory metadata: ' + path)
        # A declaration with no flags and no archive header creates an ordinary
        # directory. All explicit assertions have already been checked above.
        item.setdefault('flags_set', 0)
    for path, item in generated['entries'].items():
        pathname(path)
        if not isinstance(item, dict):
            raise ValueError('invalid generated object: ' + path)
        required = {'type', 'uid', 'gid', 'mode', 'flags_set', 'source', 'replaces'}
        kind = item.get('type')
        if kind == 'file':
            required |= {'size', 'sha256'}
        elif kind == 'symlink':
            required |= {'target'}
        elif kind != 'directory':
            raise ValueError('unsupported generated object: ' + path)
        if set(item) != required or not isinstance(item['source'], str) or not item['source'].strip():
            raise ValueError('incomplete generated provenance/metadata: ' + path)
        for key in ('uid', 'gid', 'mode', 'flags_set'):
            if type(item[key]) is not int or item[key] < 0:
                raise ValueError('invalid generated metadata: ' + path)
        if item['uid'] >= 2**32 - 1 or item['gid'] >= 2**32 - 1 or item['mode'] > 0o7777:
            raise ValueError('out-of-range generated metadata: ' + path)
        if kind == 'file' and (type(item['size']) is not int or item['size'] < 0 or
                               not isinstance(item['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', item['sha256'])):
            raise ValueError('invalid generated file content: ' + path)
        if kind == 'symlink' and (not isinstance(item['target'], str) or not item['target'] or '\0' in item['target']):
            raise ValueError('invalid generated link: ' + path)
        replacements = item['replaces']
        if not isinstance(replacements, list) or any(not isinstance(x, str) for x in replacements) or len(replacements) != len(set(replacements)):
            raise ValueError('invalid generated replacement declaration: ' + path)
        if set(replacements) != owners.get(path, set()):
            raise ValueError('generated replacement does not name exact package inputs: ' + path)
        expected[path] = {key: value for key, value in item.items() if key not in ('source', 'replaces')}
    # Replacement provenance does not make an impossible filesystem valid.
    # Check the composed map, after every generated replacement, before any
    # extractor or package script can consume it. Leaf aliases remain allowed.
    if '/' in expected and expected['/']['type'] != 'directory':
        raise ValueError('generation root must be a directory')
    for path in expected:
        for ancestor in Path(path).parents:
            parent = expected.get(str(ancestor))
            if parent is not None and parent['type'] != 'directory':
                raise ValueError('non-directory ancestor in generation inputs: ' +
                                 str(ancestor) + ' for ' + path)
    hardlink_groups(expected)
    return expected


def parse_account_data(path, fields, data):
    mapping = {}
    for line in data.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        row = line.split(':')
        if len(row) != fields or not row[0] or row[0] in mapping or not row[2].isascii() or not row[2].isdigit() or int(row[2]) >= 2**32 - 1:
            raise ValueError('ambiguous or invalid generation account entry: ' + path)
        mapping[row[0]] = int(row[2])
    return mapping


def account_maps(root, expected, observed):
    maps = []
    for path, fields in [('/etc/master.passwd', 10), ('/etc/group', 4)]:
        declared = state_alias_review(path, expected)
        measured = state_alias_review(path, observed)
        if (declared != measured or declared['status'] != 'resolved' or
                declared['resolved_type'] != 'file'):
            raise ValueError('account input missing or not matched to declared path: ' + path)
        resolved = declared['resolved_path']
        wanted, actual = expected[resolved], observed[resolved]
        if wanted.get('sha256') != actual.get('sha256'):
            raise ValueError('account input missing or not matched to declared content: ' + path)
        # Resolve only the declared/measured candidate-tree aliases above.
        # Open the resulting physical path without following any symlink, then
        # recheck bytes before using them. Never call host pwd/grp lookup.
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for component in resolved.split('/')[1:]:
                child = os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = child
            with os.fdopen(fd, 'rb') as stream:
                fd = -1
                data = stream.read()
        finally:
            if fd >= 0:
                os.close(fd)
        if hashlib.sha256(data).hexdigest() != wanted['sha256']:
            raise ValueError('account input changed during reconciliation: ' + path)
        maps.append(parse_account_data(path, fields, data))
    return maps


def state_consumer_bindings(inventory, observed):
    """Bind declarations to completed executable bytes, without assigning grants.

    Generated replacements are valid construction inputs, but cannot silently
    inherit a different package payload's declared state requirements. Inspect
    the named program itself: following a substituted symlink would turn a
    pathname alias into authority. scan() records hardlinks as regular files.
    """
    declarations = pkg.state_requirements(inventory['packages'])
    bindings, differences = [], []
    for requirement in declarations['requirements']:
        path = requirement['program']
        actual = observed.get(path, {})
        wanted = requirement['program_payload']['sha256']
        matches = (actual.get('type') == 'file' and
                   bool(actual.get('mode', 0) & 0o111) and
                   actual.get('sha256') == wanted)
        bindings.append({'package': requirement['package'],
            'requirement': requirement['name'], 'program': path,
            'package_payload_sha256': wanted,
            'observed_sha256': actual.get('sha256'),
            'payload_matches': matches, 'authority_assigned': False})
        if not matches:
            differences.append({'path': path, 'reason': 'state-consumer-binding',
                'package': requirement['package'], 'requirement': requirement['name'],
                'expected_sha256': wanted, 'actual': {key: actual.get(key)
                    for key in ('type', 'mode', 'sha256')}})
    return bindings, differences


def state_alias_review(path, observed):
    """Resolve candidate-tree links for review, never the host filesystem.

    Process components in lookup order: lexical normalization before following
    a link would interpret link/.. incorrectly. Missing runtime objects remain
    unresolved, and no successful resolution assigns authority. Retain every
    looked-up path, including directories later removed by .., for trust review.
    """
    pathname(path)
    pending, resolved, links = path.split('/')[1:], [], []
    seen = set()
    traversed = []
    while pending:
        component = pending.pop(0)
        if component in ('', '.'):
            continue
        if component == '..':
            if not resolved:
                return {'status': 'above-root', 'links': links,
                    'traversed_paths': traversed, 'resolved_path': None}
            resolved.pop()
            continue
        candidate = '/' + '/'.join([*resolved, component])
        traversed.append(candidate)
        item = observed.get(candidate)
        if item is None:
            return {'status': 'missing', 'links': links,
                    'traversed_paths': traversed, 'resolved_path': candidate,
                    'remaining_components': pending}
        if item['type'] == 'symlink':
            state = (candidate, tuple(pending))
            if state in seen or len(links) >= TARGET_MAXSYMLINKS:
                return {'status': 'cycle-or-limit', 'links': links,
                    'traversed_paths': traversed, 'resolved_path': candidate}
            seen.add(state)
            target = item.get('target')
            if not isinstance(target, str) or not target or '\0' in target:
                raise ValueError('invalid observed link target: ' + candidate)
            links.append({'path': candidate, 'target': target})
            if target.startswith('/'):
                resolved = []
            pending = target.split('/') + pending
            continue
        if pending and item['type'] != 'directory':
            return {'status': 'non-directory', 'links': links,
                    'traversed_paths': traversed, 'resolved_path': candidate}
        resolved.append(component)
    final = '/' + '/'.join(resolved)
    item = observed.get(final)
    return {'status': 'resolved' if item is not None else 'missing',
            'links': links, 'traversed_paths': traversed, 'resolved_path': final,
            'resolved_type': item.get('type') if item else None}


def state_requirement_path(requirement, observed):
    """Select a package-declared optional directory without inventing authority.

    Only absence selects the fallback.  In particular, a present dangling alias
    cannot turn a failed mapping into permission to write the fallback tree.
    Construction requires physical mapping parents so its presence check cannot
    silently miss a mapping behind an unresolved ancestor.
    """
    mapping = requirement.get('directory_mapping')
    if mapping is None:
        return requirement['path']
    for parent in Path(mapping).parents:
        if observed.get(str(parent), {}).get('type') != 'directory':
            raise ValueError('state directory mapping requires physical parents: ' + mapping)
    if mapping not in observed:
        return requirement['path']
    review = state_alias_review(mapping, observed)
    if review['status'] != 'resolved' or review['resolved_type'] != 'directory':
        raise ValueError('invalid present state directory mapping: ' + mapping)
    return mapping


def state_layout_review(inventory, observed):
    """Map declared state onto the scanned tree without following aliases.

    These are construction-time facts, not approved mount boundaries or grants.
    Missing state may be created at runtime, but its initialization and coverage
    still require explicit policy. No pathname prefix implies write authority.
    """
    rows = []
    ordered_paths = sorted(observed)
    for requirement in pkg.state_requirements(inventory['packages'])['requirements']:
        path = state_requirement_path(requirement, observed)
        parts = path.split('/')[1:]
        nearest, missing, blocked = '/', None, None
        for n in range(1, len(parts)):
            ancestor = '/' + '/'.join(parts[:n])
            item = observed.get(ancestor)
            if item is None:
                missing = ancestor
                break
            if item['type'] != 'directory':
                blocked = ancestor
                break
            nearest = ancestor
        actual = observed.get(path) if missing is None and blocked is None else None
        if blocked is not None:
            resolution = 'blocked-ancestor'
        elif missing is not None or actual is None:
            resolution = 'missing'
            missing = missing or path
        elif actual['type'] != requirement['type']:
            resolution = 'type-mismatch'
        else:
            resolution = 'existing'
        covered = []
        if resolution == 'existing':
            covered = [name for name in ordered_paths if name == path or
                (requirement['type'] == 'directory' and name.startswith(path + '/'))]
        inside = set(covered)
        crossings = {name: sorted(alias for alias in observed[name].get('hardlinks', [])
                                if alias not in inside) for name in covered}
        rows.append({'package': requirement['package'], 'requirement': requirement['name'],
            'path': path, 'declared_type': requirement['type'],
            'resolution': resolution, 'nearest_existing_directory': nearest,
            'first_missing_component': missing, 'blocked_ancestor': blocked,
            'observed_object': path if actual is not None else None,
            'covered_objects': covered,
            'cross_boundary_hardlinks': {name: aliases for name, aliases in crossings.items() if aliases},
            'alias_review': state_alias_review(path, observed),
            'policy_review': 'required'})
        if 'directory_mapping' in requirement:
            rows[-1].update(path=requirement['path'], selected_path=path,
                            directory_mapping=requirement['directory_mapping'])
    return {'format': 1, 'scope': 'observed-generation-state-layout',
            'authority_assigned': False, 'mount_coverage_approved': False, 'requirements': rows}



def elf_inspector():
    spec = importlib.util.spec_from_file_location('elf_dependencies',
        Path(__file__).with_name('elf_dependencies.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def protected_input_bindings(inventory, observed, declarations, boundary, target=None):
    """Validate declared immutable inputs, not completeness or runtime authority.

    The outer reconciliation binds generated outputs and package payloads to
    this tree. Owner policy names consumers by package archive digest; package
    membership alone does not decide which consumers or inputs are protected.
    """
    if not isinstance(declarations, list):
        raise ValueError('invalid protected consumer declarations')
    bindings, seen = [], set()

    def immutable_path(path, optional=False):
        review = state_alias_review(path, observed)
        if any(boundary(step) is not None for step in review['traversed_paths']):
            raise ValueError('protected input traverses mutable storage: ' + path)
        if review['status'] == 'missing' and optional and not review.get('remaining_components'):
            return review
        if review['status'] != 'resolved' or review['resolved_type'] != 'file':
            raise ValueError('protected input requires a resolved regular file: ' + path)
        return review

    for declaration in declarations:
        if (not isinstance(declaration, dict) or
                set(declaration) != ({'consumer', 'package_archive_sha256', 'inputs'} |
                    ({'code_loading'} if target is not None and 'code_loading' in declaration else set()))):
            raise ValueError('invalid protected consumer declaration')
        if 'code_loading' in declaration and declaration['code_loading'] != 'bip':
            raise ValueError('invalid protected consumer code-loading requirement')
        consumer = pathname(declaration['consumer'])
        archive = declaration['package_archive_sha256']
        if (not isinstance(archive, str) or not re.fullmatch('[0-9a-f]{64}', archive) or
                consumer in seen):
            raise ValueError('invalid or duplicate protected consumer identity')
        seen.add(consumer)
        owners = [package for package in inventory['packages']
                  if package.get('archive_sha256') == archive and
                  consumer in package.get('entries', {})]
        if len(owners) != 1:
            raise ValueError('protected consumer requires an exact package owner: ' + consumer)
        payload = owners[0]['entries'][consumer]
        actual = observed.get(consumer, {})
        # Direct payload identity prevents generated replacements or aliases
        # from silently inheriting another program's declarations.
        if (payload.get('type') != 'file' or actual.get('type') != 'file' or
                not isinstance(payload.get('sha256'), str) or
                not re.fullmatch('[0-9a-f]{64}', payload['sha256']) or
                actual.get('sha256') != payload['sha256']):
            raise ValueError('protected consumer payload mismatch: ' + consumer)
        immutable_path(consumer)
        inputs = declaration['inputs']
        if not isinstance(inputs, list) or not inputs:
            raise ValueError('protected consumer requires explicit inputs')
        rows, paths = [], set()
        for item in inputs:
            if (not isinstance(item, dict) or set(item) != {'path', 'presence'} or
                    item['presence'] not in ('required', 'optional')):
                raise ValueError('invalid protected input declaration')
            path = pathname(item['path'])
            if path in paths:
                raise ValueError('duplicate protected input: ' + path)
            paths.add(path)
            review = immutable_path(path, item['presence'] == 'optional')
            row = dict(path=path, presence=item['presence'], resolution=review)
            if review['status'] == 'resolved':
                digest = observed[review['resolved_path']].get('sha256')
                if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
                    raise ValueError('protected input lacks reconciled digest: ' + path)
                row['sha256'] = digest
            rows.append(row)
        bindings.append(dict(consumer=consumer, package_archive_sha256=archive,
                             consumer_sha256=payload['sha256'], inputs=rows))
        if 'code_loading' in declaration:
            bindings[-1]['code_loading'] = declaration['code_loading']
    return dict(scope='declared-immutable-consumer-inputs', bindings=bindings,
                dependency_coverage_complete=False, runtime_enforcement_verified=False)


def storage_layout(inventory, observed, policy):
    """Partition a reconciled tree for construction; never authorize live writes.

    Everything outside explicit mutable boundaries stays in the immutable base.
    Seed objects are retained verbatim in the plan, not silently hidden by mounts.
    Dataset allocation, seed installation and authenticated activation are later
    construction steps and cannot be inferred from this partition.
    """
    if not isinstance(policy, dict) or type(policy.get('format')) is not int:
        raise ValueError('invalid storage layout policy')
    version = policy['format']
    keys = {'format', 'boundaries'} | ({'protected_consumers'} if version in (2, 3) else set()) | ({'target_elf'} if version == 3 else set())
    if version not in (1, 2, 3) or set(policy) != keys or not isinstance(policy['boundaries'], list):
        raise ValueError('invalid storage layout policy')
    target = elf_inspector().bip_target(policy['target_elf']) if version == 3 else None
    boundaries = {}
    for item in policy['boundaries']:
        if (not isinstance(item, dict) or set(item) != {'path', 'content'} or
                item['content'] not in ('ordinary', 'protected')):
            raise ValueError('invalid storage layout boundary')
        path = pathname(item['path'])
        if path == '/' or path in boundaries:
            raise ValueError('root or duplicate storage boundary')
        for parent in [path, *(str(p) for p in Path(path).parents)]:
            if observed.get(parent, {}).get('type') != 'directory':
                raise ValueError('storage boundary requires physical existing directories: ' + path)
        boundaries[path] = item['content']
    ordered = sorted(boundaries)

    def boundary(path):
        # Paths are canonical. Probe complete ancestors instead of scanning
        # every boundary for every package object and hardlink alias.
        while path:
            if path in boundaries:
                return path
            path = path.rpartition('/')[0]
        return None

    for path in ordered:
        if boundary(path.rpartition('/')[0]) is not None:
            raise ValueError('overlapping storage boundaries: ' + path)

    protected_inputs = (protected_input_bindings(inventory, observed,
                        policy['protected_consumers'], boundary, target) if version in (2, 3) else None)

    seeds = {path: {} for path in ordered}
    immutable = []
    for path, item in sorted(observed.items()):
        root = boundary(path)
        if any(boundary(alias) != root for alias in item.get('hardlinks', [])):
            raise ValueError('hardlink crosses storage boundary: ' + path)
        if root is None:
            immutable.append(path)
            continue
        seeds[root][path] = item

    assigned = []
    for requirement in pkg.state_requirements(inventory['packages'])['requirements']:
        selected = state_requirement_path(requirement, observed)
        review = state_alias_review(selected, observed)
        # A missing runtime leaf is acceptable, but an unresolved alias or missing
        # intermediate directory cannot be promoted into a validated layout.
        if review['status'] not in ('resolved', 'missing') or (
                review['status'] == 'missing' and review.get('remaining_components')):
            raise ValueError('unresolved state requirement: ' + requirement['path'])
        path = review['resolved_path']
        root = boundary(path)
        if root is None:
            raise ValueError('state requirement lacks a writable boundary: ' + requirement['path'])
        if review['status'] == 'resolved' and review['resolved_type'] != requirement['type']:
            raise ValueError('state requirement type mismatch: ' + requirement['path'])
        if boundaries[root] == 'protected':
            traversed = list(review['traversed_paths'])
            # An absent optional mapping can become present at runtime. Its
            # namespace must not let ordinary writers redirect protected state.
            if 'directory_mapping' in requirement:
                mapping_review = state_alias_review(requirement['directory_mapping'], observed)
                traversed.extend(mapping_review['traversed_paths'])
            for component in traversed:
                traversed_root = boundary(component)
                if traversed_root is not None and boundaries[traversed_root] == 'ordinary':
                    raise ValueError('protected state traverses ordinary storage: ' +
                                     requirement['path'] + ' via ' + component)
        assigned.append({'package': requirement['package'], 'requirement': requirement['name'],
                         'path': requirement['path'], 'resolved_path': path,
                         'boundary': root, 'content': boundaries[root]})
        if 'directory_mapping' in requirement:
            assigned[-1].update(selected_path=selected,
                                directory_mapping=requirement['directory_mapping'])
    result = {'format': version, 'scope': 'reconciled-storage-partition',
            'immutable_objects': immutable,
            'boundaries': [{'path': path, 'content': boundaries[path], 'seed_objects': seeds[path]}
                           for path in ordered],
            'requirements': assigned, 'runtime_authority_assigned': False,
            'seed_installed': False, 'attachments_constructed': False}
    if target is not None:
        result['target_elf'] = target
    if protected_inputs is not None:
        result['protected_inputs'] = protected_inputs
    return result


def immutable_code_reference(path, observed, layout):
    """Bind a declared code path to the reconciled immutable partition.

    This does not model kernel interpreter substitutions or validate executable
    ABI semantics. Resolve only candidate observations, never host paths.
    """
    review = state_alias_review(path, observed)
    if review['status'] != 'resolved' or review['resolved_type'] != 'file':
        raise ValueError('code reference is not a resolved file: ' + path)
    resolved = review['resolved_path']
    item = observed[resolved]
    immutable = set(layout['immutable_objects'])
    traversed = ['/', *review['traversed_paths'], *item.get('hardlinks', [])]
    for component in traversed:
        if component not in immutable:
            raise ValueError('code reference traverses mutable storage: ' + path + ' via ' + component)
    return dict(path=path, resolved_path=resolved, sha256=item['sha256'],
                links=review['links'], traversed_paths=review['traversed_paths'])


def reconciled_code_bytes(root, resolved, wanted, expected_digest):
    """Read observed code through directory descriptors, without following links."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parts = resolved.split('/')[1:]
        for index, component in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if index + 1 < len(parts):
                flags |= os.O_DIRECTORY
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != wanted['size']:
            raise ValueError('consumer code changed after reconciliation: ' + resolved)
        with os.fdopen(fd, 'rb') as stream:
            fd = -1
            data = stream.read(before.st_size + 1)
            after = os.fstat(stream.fileno())
        if (len(data) != before.st_size or before.st_size != after.st_size or
                before.st_mtime_ns != after.st_mtime_ns or
                before.st_ctime_ns != after.st_ctime_ns or
                hashlib.sha256(data).hexdigest() != expected_digest or
                expected_digest != wanted['sha256']):
            raise ValueError('consumer code changed after reconciliation: ' + resolved)
    finally:
        if fd >= 0:
            os.close(fd)
    return data


def protected_consumer_code(root, observed, layout):
    """Inspect declared consumer bytes in a quiescent, reconciled builder tree.

    This binds the declared interpreter and checks its bounded target ELF
    metadata for BIP consumers. It records other direct references without
    establishing transitive dependencies or full loading semantics.
    Re-open through directory descriptors and verify the measured digest; do not
    execute candidate code or allow an intervening symlink to select host files.
    """
    elf = elf_inspector()
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or root.resolve() == Path('/'):
        raise ValueError('consumer inspection requires an alternate physical root')
    rows = []
    declarations = (layout or {}).get('protected_inputs', {}).get('bindings', [])
    for binding in declarations:
        path = binding['consumer']
        review = state_alias_review(path, observed)
        if review['status'] != 'resolved' or review['resolved_type'] != 'file':
            raise ValueError('consumer code is not a resolved file: ' + path)
        resolved = review['resolved_path']
        wanted = observed[resolved]
        data = reconciled_code_bytes(root, resolved, wanted, binding['consumer_sha256'])
        row = dict(consumer=path, resolved_path=resolved,
                   package_archive_sha256=binding['package_archive_sha256'],
                   sha256=binding['consumer_sha256'])
        if data.startswith(b'\x7fELF'):
            metadata = elf.inspect(data)
            if binding.get('code_loading') == 'bip':
                row['bip_image_admission'] = elf.validate_bip_image(metadata, layout['target_elf'])
            interpreter = metadata['interpreter']
            row.update(kind='elf', metadata=metadata,
                interpreter_reference=(immutable_code_reference(interpreter, observed, layout)
                    if interpreter is not None else None))
            if interpreter is not None and binding.get('code_loading') == 'bip':
                reference = row['interpreter_reference']
                loader_path = reference['resolved_path']
                loader = elf.inspect(reconciled_code_bytes(root, loader_path,
                    observed[loader_path], reference['sha256']))
                target = layout['target_elf']
                if (any(loader[key] != target[key] for key in
                        ('elf_class', 'byte_order', 'machine')) or
                        not loader['program_header_count'] or
                        not loader['program_regions_bounded']):
                    raise ValueError('BIP interpreter does not match bounded target ELF profile: ' + interpreter)
                row['interpreter_metadata'] = loader
        else:
            # Scripts and non-ELF modules need distinct dependency semantics.
            # Never turn their absence of ELF metadata into an empty closure.
            if binding.get('code_loading') == 'bip':
                raise ValueError('BIP image requires native ELF: ' + path)
            row.update(kind='non-elf', metadata=None)
        rows.append(row)
    return dict(scope='declared-consumer-code-metadata', consumers=rows,
                configured_manager_coverage_complete=False, dependency_coverage_complete=False, runtime_enforcement_verified=False)


def reconcile(root, inventory, generated, layout_policy=None):
    expected = expected_objects(inventory, generated)
    observed = scan(root)
    named = any(item.get('uname') or item.get('gname') for item in expected.values())
    users, groups = account_maps(root, expected, observed) if named else ({}, {})
    for path, item in expected.items():
        for name, numeric, mapping in [('uname', 'uid', users), ('gname', 'gid', groups)]:
            if item.get(name):
                if item[name] not in mapping:
                    raise ValueError('unknown generation owner ' + item[name] + ': ' + path)
                item[numeric] = mapping[item[name]]
    # Resolve expected archive hardlinks into complete regular-file link sets.
    links = hardlink_groups(expected)
    for target, paths in links.items():
        canonical = expected[target]
        for path in paths:
            original = expected[path]
            if any(original.get(key) != canonical.get(key) for key in ('uid', 'gid', 'mode', 'flags_set')):
                raise ValueError('inconsistent expected hardlink metadata: ' + path)
            expected[path] = dict(canonical, hardlinks=sorted(paths))
    differences = []
    for path in sorted(set(expected) | set(observed)):
        if path not in expected:
            differences.append({'path': path, 'reason': 'unexplained-object'})
            continue
        if path not in observed:
            differences.append({'path': path, 'reason': 'missing-object'})
            continue
        wanted, actual = expected[path], observed[path]
        keys = ['type', 'uid', 'gid', 'mode', 'flags_set', 'hardlinks']
        if wanted['type'] == 'file':
            keys += ['size', 'sha256']
        if wanted['type'] == 'symlink':
            keys += ['target']
        # Directory mtimes change when children are installed. Generated
        # timestamps are measured, not prescribed; all remain in the result.
        if wanted['type'] != 'directory':
            keys += [key for key in ('mtime', 'mtime_nsec') if key in wanted]
        mismatches = {key: {'expected': wanted.get(key), 'actual': actual.get(key)}
                      for key in keys if wanted.get(key) != actual.get(key)}
        if mismatches:
            differences.append({'path': path, 'reason': 'object-mismatch', 'fields': mismatches})
    bindings, state_differences = state_consumer_bindings(inventory, observed)
    differences.extend(state_differences)
    layout = None
    if layout_policy is not None:
        if differences:
            raise ValueError('storage layout requires an exactly reconciled filesystem')
        layout = storage_layout(inventory, observed, layout_policy)
    return {'format': 1, 'scope': 'offline-filesystem-reconciliation',
            'result': 'FAIL' if differences else 'PASS', 'inputs_authenticated': False,
            'bip_policy_applied': False, 'generation_authenticated': False,
            'state_consumer_bindings': bindings,
            'state_layout_review': state_layout_review(inventory, observed),
            'storage_layout': layout,
            'protected_consumer_code': protected_consumer_code(root, observed, layout)
                if layout is not None else None,
            'differences': differences, 'objects': observed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--generated', type=Path, required=True)
    parser.add_argument('--storage-layout-policy', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve(strict=False)
    if output.is_relative_to(args.root.resolve()):
        raise ValueError('report output must be outside generation')
    inventory, inventory_hash = read_json(args.inventory)
    generated, generated_hash = read_json(args.generated)
    layout, layout_hash = read_json(args.storage_layout_policy) if args.storage_layout_policy else (None, None)
    result = reconcile(args.root, inventory, generated, layout)
    result['input_sha256'] = {'inventory': inventory_hash, 'generated': generated_hash}
    if layout_hash is not None:
        result['input_sha256']['storage_layout_policy'] = layout_hash
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    (output / 'reconciliation.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(result['result'] + ': ' + str(len(result['objects'])) + ' objects, ' + str(len(result['differences'])) + ' unexplained differences')
    return 0 if result['result'] == 'PASS' else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        print('generation reconciliation: ' + str(error), file=sys.stderr)
        sys.exit(1)
