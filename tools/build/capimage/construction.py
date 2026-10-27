#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run package-declared generators in an offline trusted builder's private root.

The builder and its kernel are trusted. This does not authenticate inputs, sign a
release, authorize a runtime update, or protect against hostile host concurrency.
"""
import argparse
import copy
import contextlib
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('generation_check', Path(__file__).with_name('generation_check.py'))
generation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generation)
pkg = generation.pkg
spec = importlib.util.spec_from_file_location('certificate_policy', Path(__file__).with_name('certificate_policy.py'))
certificates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(certificates)
spec = importlib.util.spec_from_file_location('module_policy', Path(__file__).with_name('module_policy.py'))
modules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(modules)
spec = importlib.util.spec_from_file_location('library_policy', Path(__file__).with_name('library_policy.py'))
libraries = importlib.util.module_from_spec(spec)
spec.loader.exec_module(libraries)
spec = importlib.util.spec_from_file_location('installation_policy', Path(__file__).with_name('installation_policy.py'))
installations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installations)
spec = importlib.util.spec_from_file_location('package_closure', Path(__file__).with_name('package_closure.py'))
closure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(closure)
LIBC = C.CDLL(None, use_errno=True)

def native_archive_flag():
    # Python and libarchive do not expose this ZFS bookkeeping flag by name.
    # Resolve its native value with the same public parser used by chflags.
    parse = LIBC.strtofflags
    parse.argtypes = [C.POINTER(C.c_char_p), C.POINTER(C.c_ulong), C.POINTER(C.c_ulong)]
    parse.restype = C.c_int
    name, flags, clear = C.c_char_p(b'uarch'), C.c_ulong(), C.c_ulong()
    if parse(C.byref(name), C.byref(flags), C.byref(clear)) != 0 or not flags.value or clear.value:
        raise ValueError('native archive bookkeeping flag unavailable')
    return flags.value


ARCHIVE_FLAG = native_archive_flag()
_fchflags = LIBC.fchflags
_fchflags.argtypes = [C.c_int, C.c_ulong]
_fchflags.restype = C.c_int


def fchflags(fd, flags):
    if _fchflags(fd, flags) != 0:
        error = C.get_errno()
        raise OSError(error, os.strerror(error))


ENVIRONMENT = {'PATH': '/sbin:/bin:/usr/sbin:/usr/bin', 'LC_ALL': 'C',
               'TZ': 'UTC', 'HOME': '/', 'USER': 'root', 'LOGNAME': 'root'}
JAIL_PARAMETERS = ['persist', 'ip4=disable', 'ip6=disable', 'sysvmsg=disable',
    'sysvsem=disable', 'sysvshm=disable', 'children.max=0', 'enforce_statfs=2',
    'allow.mount=0', 'allow.raw_sockets=0', 'allow.socket_af=0',
    'allow.chflags=0', 'allow.mlock=0', 'allow.set_hostname=0',
    'allow.reserved_ports=0', 'host.hostname=construction.invalid']


def canonical_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def write_record(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('xb') as stream:
        stream.write(canonical_bytes(value))
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def inventory_from_archives(record):
    if (not isinstance(record, dict) or record.get('format') != 1 or
            record.get('scope') != 'package-payload-inventory' or
            not isinstance(record.get('packages'), list) or not record['packages']):
        raise ValueError('requires a package payload inventory')
    archives, expected = [], {}
    for item in record['packages']:
        if not isinstance(item, dict):
            raise ValueError('invalid package inventory entry')
        archive, sha256 = item.get('archive'), item.get('archive_sha256')
        if (not isinstance(archive, str) or not Path(archive).is_absolute() or
                Path(archive).is_symlink() or not Path(archive).is_file() or
                not isinstance(sha256, str) or archive in expected):
            raise ValueError('invalid or duplicate archive reference')
        archives.append(Path(archive))
        expected[archive] = sha256
    # Re-read archive metadata and declarations. Caller-written derived actions
    # or an authentication label in a JSON file cannot select executable code.
    inventory = pkg.inventory_packages(archives)
    for item in inventory['packages']:
        if item['archive_sha256'] != expected[item['archive']]:
            raise ValueError('package archive changed: ' + item['archive'])
    manifests = [item['manifest'] for item in inventory['packages']]
    closure.require_selected_set(manifests)
    return inventory


def require_match(root, inventory, generated):
    result = generation.reconcile(root, inventory, generated)
    if result['result'] != 'PASS':
        raise ValueError('candidate does not match construction inputs: ' +
                         json.dumps(result['differences'][:10], sort_keys=True))
    return result['objects']


def check_action_inputs(action, observed):
    program = action['executable_payload']
    actual = observed.get(program['path'], {})
    if actual.get('type') != 'file' or actual.get('sha256') != program['sha256']:
        raise ValueError('generator executable differs from package payload')
    for path in action['inputs']:
        if observed.get(path, {}).get('type') != 'file':
            raise ValueError('generator input is not a verified regular file: ' + path)
    for path, expected in action.get('input_payloads', {}).items():
        if observed.get(path, {}).get('sha256') != expected:
            raise ValueError('module input changed after selection: ' + path)
    for path, expected in action.get('directory_inputs', {}).items():
        if any(observed.get(path, {}).get(k) != v for k, v in expected.items()):
            raise ValueError('library directory changed after policy selection: ' + path)
    replacement = action.get('replacement_payload')
    if replacement is not None and observed.get(replacement['path'], {}).get('sha256') != replacement['sha256']:
        raise ValueError('module replacement payload changed after selection')
    for path in action['outputs']:
        parent = str(Path(path).parent)
        if observed.get(parent, {}).get('type') != 'directory':
            raise ValueError('output parent must already be a verified directory: ' + parent)


def open_object(root, path, directory=False):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parts = Path(path).parts[1:]
        for index, component in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if directory or index < len(parts) - 1:
                flags |= os.O_DIRECTORY
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def finalize_outputs(root, action, before, after, *, allow_aliases=False):
    outputs = action['outputs']
    parents = {str(Path(path).parent) for path in outputs}
    # Check every output before changing metadata on any inode.
    for path in outputs:
        item = after.get(path, {})
        if outputs[path].get('type') == 'symlink':
            if not allow_aliases:
                raise ValueError('generator output must be an unaliased regular file: ' + path)
            if item.get('type') != 'symlink' or item.get('target') != outputs[path]['target']:
                raise ValueError('installation alias changed: ' + path)
            continue
        if item.get('type') != 'file' or item.get('hardlinks'):
            raise ValueError('generator output must be an unaliased regular file: ' + path)
    for path in set(before) | set(after):
        if path in outputs:
            continue
        if path not in before or path not in after:
            raise ValueError('unexplained construction object: ' + path)
        wanted, actual = dict(before[path]), dict(after[path])
        if path in parents:
            for key in ('mtime', 'mtime_nsec'):
                wanted.pop(key, None)
                actual.pop(key, None)
            # ZFS maintains this backup bookkeeping bit when children change.
            # Restore it below; no other flag or metadata difference is exempt.
            wanted['flags_set'] &= ~ARCHIVE_FLAG
            actual['flags_set'] &= ~ARCHIVE_FLAG
        if wanted != actual:
            raise ValueError('undeclared construction change: ' + path)
    for path, metadata in outputs.items():
        if metadata.get('type') == 'symlink':
            target = root / path.lstrip('/')
            os.chown(target, metadata['uid'], metadata['gid'], follow_symlinks=False)
            os.chmod(target, metadata['mode'], follow_symlinks=False)
            os.chflags(target, metadata['flags_set'], follow_symlinks=False)
            continue
        fd = open_object(root, path)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('unsafe output during metadata application: ' + path)
            os.fchown(fd, metadata['uid'], metadata['gid'])
            os.fchmod(fd, metadata['mode'])
            if os.fstat(fd).st_flags != metadata['flags_set']:
                fchflags(fd, metadata['flags_set'])
        finally:
            os.close(fd)
    for path in parents:
        if before[path]['flags_set'] != after[path]['flags_set']:
            fd = open_object(root, path, directory=True)
            try:
                fchflags(fd, before[path]['flags_set'])
            finally:
                os.close(fd)


def output_records(action, observed):
    result = {}
    for path, metadata in action['outputs'].items():
        actual = observed.get(path)
        if actual is None or actual.get('type') != 'file' or actual.get('hardlinks'):
            raise ValueError('generator output must be an unaliased regular file: ' + path)
        for key in ('uid', 'gid', 'mode', 'flags_set'):
            if actual[key] != metadata[key]:
                raise ValueError('generator output metadata mismatch: ' + path + ': ' + key)
        result[path] = {key: actual[key] for key in
                       ('type', 'uid', 'gid', 'mode', 'flags_set', 'size', 'sha256')}
        result[path]['replaces'] = [action['package_sha256']] if metadata['replace'] else []
    return result


def command(argv, **kwargs):
    return subprocess.run(argv, check=True, env=ENVIRONMENT, stdin=subprocess.DEVNULL,
                          close_fds=True, umask=0o022, **kwargs)


def jail_list():
    data = command(['/usr/sbin/jls', '--libxo', 'json', '-d', 'jid', 'name', 'path'],
                   capture_output=True, text=True, timeout=30)
    value = json.loads(data.stdout, object_pairs_hook=pkg.unique_object)
    rows = value.get('jail-information', {}).get('jail')
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError('invalid jail lifecycle response')
    return rows


def find_jail(name, root):
    rows = [row for row in jail_list() if row.get('name') == name]
    if not rows:
        return None
    if len(rows) != 1 or rows[0].get('path') != str(root):
        raise ValueError('construction jail identity mismatch')
    jid = str(rows[0].get('jid'))
    if not jid.isascii() or not jid.isdigit() or int(jid) <= 0:
        raise ValueError('invalid construction jail ID')
    return jid


@contextlib.contextmanager
def private_jail(root):
    """Own a builder jail through final descendant exit, including failures."""
    name = 'bsd-build-' + secrets.token_hex(16)
    if find_jail(name, root) is not None:
        raise ValueError('construction jail already exists')
    # No devfs, mounts, sockets, signing keys or host-directory descriptors are
    # supplied. The fully reconciled root cannot contain device nodes or links
    # to files outside it. Ordinary action streams are diagnostic. Certificate
    # planning parses a bounded stream and separately checks the unchanged root.
    try:
        command(['/usr/sbin/jail', '-f', '/dev/null', '-c', 'name=' + name,
                 'path=' + str(root), *JAIL_PARAMETERS],
                capture_output=True, text=True, timeout=30)
        jid = find_jail(name, root)
        if jid is None:
            raise ValueError('construction jail was not created')
        yield jid
    finally:
        # Removal sends termination to descendants asynchronously. Do not scan
        # or approve outputs until the jail, including its dying state, is gone.
        jid = find_jail(name, root)
        if jid is not None:
            command(['/usr/sbin/jail', '-f', '/dev/null', '-r', name],
                    capture_output=True, text=True, timeout=30)
            deadline = time.monotonic() + 30
            while find_jail(name, root) is not None:
                if time.monotonic() >= deadline:
                    raise TimeoutError('construction descendants have not exited; root retained')
                time.sleep(0.1)


def run_jailed(root, argv, log, timeout):
    with private_jail(root) as jid:
        with log.open('xb') as stream:
            command(['/usr/sbin/jexec', jid, *argv], stdout=stream,
                    stderr=subprocess.STDOUT, timeout=timeout)


def construct(root, inventory, initial, output, timeout=300, execute=run_jailed, certificate_policy=None, module_policy=None, database=None, extraction=None, progress=None, library_policy=None, installation_policy=None, storage_layout_policy=None):
    if progress: progress('reconcile-inputs')
    generated = copy.deepcopy(initial)
    actions = list(inventory['construction']['actions'])
    if any(path in initial['entries'] for action in actions for path in action['outputs']):
        raise ValueError('declared outputs cannot be preapproved in initial generated inputs')
    observed = require_match(root, inventory, generated)
    module_plan = modules.prepare(inventory, observed, module_policy) if module_policy is not None else None
    if module_plan is not None:
        actions.extend(module_plan['actions'])
    library_plan = libraries.prepare(inventory, observed, library_policy, pkg, digest) if library_policy is not None else None
    if library_plan is not None:
        actions.extend(library_plan['actions'])
    outputs = [path for action in actions for path in action['outputs']]
    if len(outputs) != len(set(outputs)):
        raise ValueError('conflicting construction outputs')
    if installation_policy is not None:
        installation_plan = installations.prepare(inventory, observed, generated,
            installation_policy, Path(root), _construction_context())
        if set(installation_plan['records']).intersection(outputs):
            raise ValueError('installation configuration conflicts with planned generator output')
    if certificate_policy is not None:
        certificates.prepare(inventory, observed, certificate_policy)
    for action in actions:
        # Generated dependencies need not exist until their producer has run.
        # All output parent directories must exist before any execution.
        for path in action['outputs']:
            if observed.get(str(Path(path).parent), {}).get('type') != 'directory':
                raise ValueError('missing verified output directory: ' + path)
    output.mkdir(mode=0o700)
    report = {'format': 1, 'scope': 'trusted-builder-construction', 'result': 'RUNNING',
              'inputs_authenticated': False, 'generation_authenticated': False,
              'bip_policy_applied': False, 'inventory_sha256': digest(inventory),
              'initial_generated_sha256': digest(initial), 'environment': ENVIRONMENT,
              'umask': 0o022, 'jail_parameters': JAIL_PARAMETERS, 'timeout_seconds': timeout,
              'receipts': [], 'module_plan': module_plan, 'library_plan': library_plan, 'payload_extraction': extraction}
    write_record(output / 'construction.json', report)
    try:
        if installation_policy is not None:
            if progress: progress('installation-configuration')
            generated, observed, receipt = installations.install(root, inventory, generated, installation_policy, _construction_context())
            report['installation_configuration'] = receipt
            write_record(output / 'construction.json', report)
        for index in range(len(actions) + (certificate_policy is not None)):
            if index == len(actions):
                action, plan = certificates.compile_recipe(root, inventory, observed,
                    certificate_policy, output / 'certificate-plan.mtree', timeout, execute, generation.scan)
                report['certificate_plan'] = plan
                write_record(output / 'construction.json', report)
            else:
                action = actions[index]
            check_action_inputs(action, observed)
            before_hash = digest(observed)
            if progress: progress('action-' + str(index) + '-execute')
            execute(root, action['argv'], output / ('action-' + str(index) + '.log'), timeout)
            if progress: progress('action-' + str(index) + '-verify')
            raw_after = generation.scan(root)
            for path, size in action.get('planned_sizes', {}).items():
                if raw_after.get(path, {}).get('size') != size:
                    raise ValueError('certificate output differs from planned size: ' + path)
            if progress: progress('action-' + str(index) + '-finalize-metadata')
            for path, expected_hash in action.get('planned_hashes', {}).items():
                if raw_after.get(path, {}).get('sha256') != expected_hash:
                    raise ValueError('generated library hints differ from approved search order: ' + path)
            finalize_outputs(root, action, observed, raw_after)
            if progress: progress('action-' + str(index) + '-scan-finalized')
            after = generation.scan(root)
            records = output_records(action, after)
            receipt = {'action': action, 'before_sha256': before_hash,
                       'after_execution_sha256': digest(raw_after),
                       'after_sha256': digest(after), 'outputs': records,
                       'inputs': {p: observed[p] for p in action['inputs']}}
            receipt_hash = digest(receipt)
            for path, record in records.items():
                generated['entries'][path] = dict(record, source='construction receipt sha256:' + receipt_hash)
            # The declared output set is the only change permitted. This full
            # comparison includes package inputs, prior outputs and site inputs.
            if progress: progress('action-' + str(index) + '-reconcile-finalized')
            observed = require_match(root, inventory, generated)
            report['receipts'].append(dict(receipt, sha256=receipt_hash))
            write_record(output / 'construction.json', report)
        if database is not None:
            if progress: progress('database-construction')
            helper, plan = database
            accepted = helper.construct(plan['pkg'], plan['sqlite'], inventory, plan['contract'],
                plan['abi'], plan['osversion'], output / 'database', timeout, progress=progress)
            generated, receipt = helper.install(root, inventory, generated, output / 'database',
                plan['contract'], plan['sqlite'], plan['policy'], progress=progress)
            if progress: progress('database-generation-reconcile-finalized')
            observed = require_match(root, inventory, generated)
            report['receipts'].append(receipt)
            report['database_construction_sha256'] = digest(accepted)
        if installation_policy is not None and installations.relocation_requests(inventory, installation_policy, _construction_context()):
            if progress: progress('installation-relocation')
            generated, observed, receipt = installations.relocate(root, inventory, generated,
                installation_policy, _construction_context())
            report['installation_relocation'] = receipt
            write_record(output / 'construction.json', report)
        if storage_layout_policy is not None:
            if progress: progress('storage-layout-finalized')
            layout = generation.storage_layout(inventory, observed, storage_layout_policy)
            report['protected_consumer_code'] = generation.protected_consumer_code(
                root, observed, layout)
            write_record(output / 'storage-layout.json', layout)
            report['storage_layout'] = dict(policy_sha256=digest(storage_layout_policy),
                layout_sha256=digest(layout), filesystem_sha256=digest(observed),
                authority_assigned=False, coverage_complete=False, runtime_qualified=False)
        report['result'] = 'PASS'
        report['generated_sha256'] = digest(generated)
        report['filesystem_sha256'] = digest(observed)
        write_record(output / 'generated.json', generated)
        write_record(output / 'construction.json', report)
    except BaseException as error:
        # A failed final receipt write must not leave an apparently usable
        # generated manifest from this incomplete transaction.
        (output / 'generated.json').unlink(missing_ok=True)
        (output / 'storage-layout.json').unlink(missing_ok=True)
        report['result'] = 'FAIL'
        report['error'] = str(error)
        write_record(output / 'construction.json', report)
        raise
    return report


def _construction_context():
    from types import SimpleNamespace
    return SimpleNamespace(generation=generation, digest=digest, require_match=require_match,
                           finalize_outputs=finalize_outputs, fchflags=fchflags)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--generated', type=Path, required=True)
    parser.add_argument('--certificate-policy', type=Path)
    parser.add_argument('--module-policy', type=Path)
    parser.add_argument('--library-policy', type=Path)
    parser.add_argument('--installation-policy', type=Path)
    parser.add_argument('--storage-layout-policy', type=Path)
    for name in ('pkg', 'sqlite', 'contract', 'policy'):
        parser.add_argument('--database-' + name, type=Path)
    parser.add_argument('--database-osversion', type=int)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--extract-tar', type=Path, help='materialize archives into an empty root with this explicit tar tool')
    parser.add_argument('--plan', action='store_true')
    args = parser.parse_args()
    if args.timeout < 1 or args.timeout > 86400:
        raise ValueError('construction timeout must be between 1 and 86400 seconds')
    if args.root.is_symlink() or not args.root.is_dir() or args.root.resolve() == Path('/'):
        raise ValueError('construction requires a private alternate root')
    root = args.root.resolve(strict=True)
    output = args.output.resolve(strict=False)
    if args.output.is_symlink() or output.exists() or output.is_relative_to(root):
        raise ValueError('construction report directory must be new and outside the root')
    record, _ = generation.read_json(args.inventory)
    initial, _ = generation.read_json(args.generated)
    certificate_policy = (certificates.read_policy(args.certificate_policy, pkg)
                          if args.certificate_policy is not None else None)
    module_policy = modules.read_policy(args.module_policy, pkg) if args.module_policy is not None else None
    library_policy = modules.read_policy(args.library_policy, pkg) if args.library_policy is not None else None
    installation_policy = modules.read_policy(args.installation_policy, pkg) if args.installation_policy is not None else None
    storage_layout_policy = generation.read_json(args.storage_layout_policy)[0] if args.storage_layout_policy is not None else None
    inventory = inventory_from_archives(record)
    if any(Path(p['archive']).resolve().is_relative_to(root) for p in inventory['packages']):
        raise ValueError('package archives must be outside the candidate')
    # Reject stale package-owner bindings and changed configuration sources
    # before payload extraction. The real candidate is reconciled again below.
    if installation_policy is not None:
        installations.preflight(inventory, initial, installation_policy, root,
                                _construction_context())
    extractor = None
    if args.extract_tar is not None:
        spec = importlib.util.spec_from_file_location('payload_extract', Path(__file__).with_name('payload_extract.py'))
        extractor = importlib.util.module_from_spec(spec); spec.loader.exec_module(extractor)
        root, observed = extractor.prepare(root, inventory, initial)
    else:
        observed = require_match(root, inventory, initial)
    database = None
    database_args = [args.database_pkg, args.database_sqlite, args.database_contract,
                     args.database_policy, args.database_osversion]
    if any(value is not None for value in database_args):
        if any(value is None for value in database_args):
            raise ValueError('database construction requires all explicit database inputs')
        spec = importlib.util.spec_from_file_location('database_construction',
            Path(__file__).with_name('database_construction.py'))
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        contract = helper.payload.preflight.decode(args.database_contract.read_bytes())
        policy = helper.payload.preflight.decode(args.database_policy.read_bytes())
        path = helper.validate_output_policy(policy)
        if path in observed or observed.get(str(Path(path).parent), {}).get('type') != 'directory':
            raise ValueError('database output must be absent beneath a verified directory')
        program, sqlite, checked, abi = helper.prepare(args.database_pkg, args.database_sqlite,
            inventory, contract, args.database_osversion)
        if digest(checked) != digest(inventory):
            raise ValueError('database archive inventory differs from generation inventory')
        database = (helper, dict(pkg=program, sqlite=sqlite, contract=contract, policy=policy,
                                abi=abi, osversion=args.database_osversion))
    if args.plan:
        if extractor is not None:
            observed = extractor.planning_objects(inventory, observed)
        selection = (certificates.prepare(inventory, observed, certificate_policy)
                     if certificate_policy is not None else None)
        print(json.dumps({'scope': 'trusted-builder-construction', 'actions': inventory['construction']['actions'],
                          'installation_configuration': installations.prepare(inventory, observed, initial, installation_policy, root, _construction_context()) if installation_policy is not None else None,
                          'certificate_selection': selection,
                          'certificate_outputs': 'require-isolated-planning' if selection else None,
                          'library_plan': libraries.prepare(inventory, observed, library_policy, pkg, digest) if library_policy is not None else None,
                          'module_plan': modules.prepare(inventory, observed, module_policy) if module_policy is not None else None,
                          'storage_layout_policy_sha256': digest(storage_layout_policy) if storage_layout_policy is not None else None,
                          'storage_layout_validation': 'requires-finalized-filesystem' if storage_layout_policy is not None else None,
                          'database_construction': database is not None, 'payload_extraction': extractor is not None,
                          'inputs_authenticated': False, 'activation_authorized': False}, indent=2))
        return
    if os.geteuid() != 0:
        raise PermissionError('construction requires a root shell for temporary jail creation; use a disposable builder VM')
    extraction = (extractor.extract(root, inventory, initial, args.extract_tar, args.timeout,
                      progress=lambda phase: print('PAYLOAD_EXTRACTION_PHASE ' + phase, flush=True))
                  if extractor is not None else None)
    report = construct(root, inventory, initial, output, args.timeout, certificate_policy=certificate_policy, module_policy=module_policy, library_policy=library_policy, installation_policy=installation_policy, storage_layout_policy=storage_layout_policy, database=database, extraction=extraction,
                       progress=lambda phase: print("CONSTRUCTION_PHASE " + phase, flush=True))
    print('CONSTRUCTION_VERIFIED scope=' + report['scope'] + ' report=' + str(output / 'construction.json'))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('build-bsd construct: ' + str(error), file=sys.stderr)
        sys.exit(1)
