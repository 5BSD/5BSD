# SPDX-License-Identifier: BSD-2-Clause
"""Explicit configuration creation and replacement in an offline trusted builder.

Package configuration membership is inventory, never runtime write authority.
The builder and kernel are trusted; hostile concurrent host mutation is excluded.
"""
import copy
import hashlib
import os
from pathlib import Path
import stat
import tempfile


def source_open(name, root):
    source = Path(name)
    if not source.is_absolute() or str(source) != name or source.resolve(strict=True) != source:
        raise ValueError('installation source must be canonical and unaliased')
    if source.is_relative_to(root):
        raise ValueError('installation source must be outside candidate')
    fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('installation source must be a regular file')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def check_source(name, root, size, digest, destination=None):
    count, hashed = 0, hashlib.sha256()
    with source_open(name, root) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            count += len(block)
            if count > size:
                raise ValueError('installation source size changed')
            hashed.update(block)
            if destination is not None:
                destination.write(block)
    if count != size or hashed.hexdigest() != digest:
        raise ValueError('installation source differs from explicit size/hash')


def alias_record(name, item, inventory, observed, generated, outputs, c):
    if set(item) != {'operation', 'target', 'package', 'requirement'}:
        raise ValueError('invalid installation alias fields')
    c.generation.pathname(item['target'])
    if item['target'] == '/' or item['target'] == name:
        raise ValueError('invalid installation alias target')
    requirements = c.generation.pkg.state_requirements(inventory['packages'])['requirements']
    matches = [r for r in requirements if r['package'] == item['package'] and
               r['name'] == item['requirement'] and
               (r['path'] == name or r.get('directory_mapping') == name)]
    if len(matches) != 1:
        raise ValueError('alias requires one matching package state requirement')
    packaged = {path for p in inventory['packages'] for path in p['entries']}
    if name in observed or name in packaged or name in generated['entries'] or name in outputs:
        raise ValueError('alias destination must be absent and unowned')
    for parent in Path(name).parents:
        if observed.get(str(parent), {}).get('type') != 'directory':
            raise ValueError('alias destination has undeclared or aliased parent')
    return dict(type='symlink', target=item['target'], uid=0, gid=0, mode=0o777,
                flags_set=0, replaces=[])


def relocation_requests(inventory, policy, c):
    """Validate explicitly selected moves; no filesystem mutation or classification."""
    if policy.get('format') not in (4, 5):
        return {}
    requirements = c.generation.pkg.state_requirements(inventory['packages'])['requirements']
    moves = {}
    for name, item in policy['entries'].items():
        if not isinstance(item, dict) or item.get('operation') != 'relocate':
            continue
        if set(item) != {'operation', 'target', 'package', 'requirement'}:
            raise ValueError('invalid relocation fields')
        c.generation.pathname(name)
        c.generation.pathname(item['target'])
        if name == '/' or item['target'] in ('/', name):
            raise ValueError('invalid relocation path')
        matched = [r for r in requirements if r['package'] == item['package'] and
                   r['name'] == item['requirement'] and r['path'] == name and r['type'] == 'file']
        if len(matched) != 1:
            raise ValueError('relocation requires one matching file state requirement')
        moves[name] = dict(item)
    targets = [item['target'] for item in moves.values()]
    if len(targets) != len(set(targets)) or set(targets).intersection(policy['entries']):
        raise ValueError('conflicting relocation targets')
    return moves


def prepare_relocations(inventory, observed, generated, policy, c):
    moves = relocation_requests(inventory, policy, c)
    owners = {}
    for package in inventory['packages']:
        for name in package['entries']:
            owners.setdefault(name, []).append(package['archive_sha256'])
    records, inputs = {}, {}
    for name, move in moves.items():
        target = move['target']
        original = observed.get(name, {})
        if (original.get('type') != 'file' or original.get('hardlinks') or
                original.get('flags_set') != 0 or original.get('mode', 0) & 0o111):
            raise ValueError('relocation source must be an unlinked, unflagged nonexecutable file: ' + name)
        if target in observed or target in owners or target in generated['entries']:
            raise ValueError('relocation target must be absent and unowned: ' + target)
        for path in (name, target):
            for parent in Path(path).parents:
                if observed.get(str(parent), {}).get('type') != 'directory':
                    raise ValueError('relocation requires physical existing parents: ' + path)
        inputs[name] = dict(original)
        records[target] = {key: original[key] for key in
                           ('type', 'uid', 'gid', 'mode', 'flags_set', 'size', 'sha256')}
        records[target].update(source='installation relocation policy sha256:' + c.digest(policy), replaces=[])
        records[name] = dict(type='symlink', target=target, uid=0, gid=0, mode=0o777,
            flags_set=0, source='installation relocation policy sha256:' + c.digest(policy),
            replaces=sorted(set(owners.get(name, []))))
    proposed = copy.deepcopy(generated)
    proposed['entries'].update(records)
    c.generation.expected_objects(inventory, proposed)
    parents = {str(Path(path).parent) for name, move in moves.items()
               for path in (name, move['target'])}
    return dict(policy_sha256=c.digest(policy), moves=moves, inputs=inputs, records=records,
                parent_observations={path: dict(observed[path]) for path in sorted(parents)},
                runtime_storage_authorized=False)


def relocate(root, inventory, generated, policy, c):
    """Move reconciled files in a private builder; failure invalidates the candidate."""
    if os.geteuid() != 0:
        raise PermissionError('installation relocation requires a trusted root builder')
    root = Path(root)
    if root.is_symlink() or root.resolve() != root or root == Path('/'):
        raise ValueError('relocation requires a canonical alternate root')
    parent = root.parent.stat()
    if parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError('relocation requires a private root-owned builder parent')
    observed = c.require_match(root, inventory, generated)
    plan = prepare_relocations(inventory, observed, generated, policy, c)
    temporary = []
    try:
        # Pre-stage aliases before any move; never overwrite an occupied target.
        for name, move in plan['moves'].items():
            source = root / name.lstrip('/')
            fd, tmp = tempfile.mkstemp(prefix='.relocation-', dir=source.parent)
            os.close(fd)
            os.unlink(tmp)
            temporary.append((Path(tmp), source, root / move['target'].lstrip('/')))
            os.symlink(move['target'], tmp)
            metadata = plan['records'][name]
            os.chown(tmp, metadata['uid'], metadata['gid'], follow_symlinks=False)
            os.chmod(tmp, metadata['mode'], follow_symlinks=False)
            os.chflags(tmp, metadata['flags_set'], follow_symlinks=False)
        for alias, source, target in temporary:
            if target.exists() or target.is_symlink():
                raise ValueError('relocation target appeared during construction')
            os.rename(source, target)
            os.replace(alias, source)
        for alias, source, target in temporary:
            for path in (target, target.parent, source.parent):
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        result = copy.deepcopy(generated)
        result['entries'].update(plan['records'])
        after = c.require_match(root, inventory, result)
        receipt = dict(plan, scope='trusted-builder-installation-relocation',
                       before_sha256=c.digest(observed), after_sha256=c.digest(after))
        return result, after, receipt
    finally:
        for alias, source, target in temporary:
            alias.unlink(missing_ok=True)


def prepare(inventory, observed, generated, policy, root, c):
    if (not isinstance(policy, dict) or set(policy) != {'format', 'entries'} or
            type(policy['format']) is not int or policy['format'] not in (1, 2, 3, 4, 5) or
            not isinstance(policy['entries'], dict) or not policy['entries']):
        raise ValueError('installation policy requires format 1, 2, 3, 4 or 5 and nonempty entries')
    deferred = relocation_requests(inventory, policy, c)
    configs, templates = {}, {}
    packaged = {name for package in inventory['packages'] for name in package['entries']}
    for package in inventory['packages']:
        for name in c.generation.pkg.installation_templates(package):
            templates.setdefault(name, []).append(package)
        for name in package.get('config', []):
            configs.setdefault(name, []).append(package)
    outputs = {name for action in inventory['construction']['actions'] for name in action['outputs']}
    records, sources = {}, {}
    for name, item in policy['entries'].items():
        c.generation.pathname(name)
        if name in deferred:
            continue
        if policy['format'] >= 3 and isinstance(item, dict) and item.get('operation') == 'alias':
            records[name] = alias_record(name, item, inventory, observed, generated, outputs, c)
            records[name]['source'] = 'installation policy sha256:' + c.digest(policy)
            continue
        fields = {'source', 'sha256', 'size', 'uid', 'gid', 'mode', 'replaces'}
        if policy['format'] >= 2:
            fields.add('operation')
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError('invalid installation entry fields')
        if not isinstance(item['source'], str):
            raise ValueError('invalid installation source')
        operation = item.get('operation', 'replace')
        allowed = ('create', 'replace', 'replace-template') if policy['format'] == 5 else ('create', 'replace')
        if operation not in allowed:
            raise ValueError('unknown installation operation')
        owners = (templates if operation == 'replace-template' else configs).get(name, [])
        replacing = operation in ('replace', 'replace-template')
        if replacing and (len(owners) != 1 or
                owners[0]['entries'].get(name, {}).get('type') != 'file'):
            raise ValueError('installation destination requires one regular package ' +
                             ('template owner' if operation == 'replace-template' else 'configuration owner'))
        if operation == 'create' and (name in observed or name in packaged or item['replaces'] != []):
            raise ValueError('installation creation requires an absent unowned destination and no replacements')
        if name in generated['entries'] or name in outputs:
            raise ValueError('installation destination conflicts with generated output')
        actual = observed.get(name, {})
        if replacing and (actual.get('type') != 'file' or
                actual.get('hardlinks') or actual.get('flags_set', 0)):
            raise ValueError('installation destination must be an unaliased unflagged regular file')
        for parent in Path(name).parents:
            if observed.get(str(parent), {}).get('type') != 'directory':
                raise ValueError('installation destination has undeclared or aliased parent')
        records[name] = dict(type='file', **{k: item[k] for k in
            ('sha256', 'size', 'uid', 'gid', 'mode', 'replaces')}, flags_set=0,
            source='installation policy sha256:' + c.digest(policy))
        # Validate generated-object schema and exact package replacement owners
        # with the same verifier that will accept the final generation.
        candidate = copy.deepcopy(generated)
        candidate['entries'].update(records)
        c.generation.expected_objects(inventory, candidate)
        if item['uid'] != 0 or item['mode'] & 0o7133:
            raise ValueError('installation configuration must be root-owned, nonexecutable and not group/other-writable')
        check_source(item['source'], root, item['size'], item['sha256'])
        sources[name] = item['source']
    candidate = copy.deepcopy(generated)
    candidate['entries'].update(records)
    c.generation.expected_objects(inventory, candidate)
    proposed = {**observed, **records}
    for name, record in records.items():
        if record['type'] == 'symlink':
            review = c.generation.state_alias_review(name, proposed)
            if review['status'] not in ('resolved', 'missing'):
                raise ValueError('invalid compatibility alias chain: ' + name)
            requirement = next(r for r in c.generation.pkg.state_requirements(inventory['packages'])['requirements']
                               if r['package'] == policy['entries'][name]['package'] and
                               r['name'] == policy['entries'][name]['requirement'])
            if review['status'] == 'resolved' and review['resolved_type'] != requirement['type']:
                raise ValueError('compatibility alias target type differs from requirement: ' + name)
    return dict(policy_sha256=c.digest(policy), records=records, sources=sources,
                inputs_authenticated=False, runtime_storage_authorized=False)



def preflight(inventory, generated, policy, root, c):
    """Check declared package bindings and input bytes before extracting a root.

    The expected object graph is not an observed filesystem. Installation must
    still reconcile the real root and recheck all sources before applying it.
    """
    expected = c.generation.expected_objects(inventory, generated)
    return prepare(inventory, expected, generated, policy, Path(root), c)


def install(root, inventory, generated, policy, c):
    if os.geteuid() != 0:
        raise PermissionError('installation configuration requires a trusted root builder')
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or root.resolve() != root or root == Path('/'):
        raise ValueError('installation requires a canonical alternate root')
    parent = root.parent.stat()
    if parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError('installation requires a private root-owned builder parent')
    observed = c.require_match(root, inventory, generated)
    plan = prepare(inventory, observed, generated, policy, root, c)
    pending = []
    try:
        # Stage all bytes before replacing anything. New inodes avoid modifying
        # a package inode through another link. The private builder is trusted.
        for name, record in plan['records'].items():
            destination = root / name.lstrip('/')
            fd, temporary = tempfile.mkstemp(prefix='.installation-', dir=destination.parent)
            pending.append((Path(temporary), destination))
            if record['type'] == 'symlink':
                os.close(fd)
                os.unlink(temporary)
                os.symlink(record['target'], temporary)
                os.chown(temporary, record['uid'], record['gid'], follow_symlinks=False)
                continue
            with os.fdopen(fd, 'wb') as stream:
                check_source(plan['sources'][name], root, record['size'], record['sha256'], stream)
                stream.flush()
                os.fchown(stream.fileno(), record['uid'], record['gid'])
                os.fchmod(stream.fileno(), record['mode'])
                c.fchflags(stream.fileno(), 0)
                os.fsync(stream.fileno())
        for temporary, destination in pending:
            os.replace(temporary, destination)
        c.finalize_outputs(root, {'outputs': plan['records']}, observed, c.generation.scan(root), allow_aliases=True)
        result = copy.deepcopy(generated)
        result['entries'].update(plan['records'])
        after = c.require_match(root, inventory, result)
        receipt = dict(plan, scope='trusted-builder-installation-configuration',
                       before_sha256=c.digest(observed), after_sha256=c.digest(after))
        return result, after, receipt
    finally:
        for temporary, destination in pending:
            temporary.unlink(missing_ok=True)
