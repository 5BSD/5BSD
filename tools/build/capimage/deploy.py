#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Explicit pkgbase deployment to a new root or inactive boot environment.

Never activates a boot environment or modifies the running root's pkg database.
Package scripts execute inside the target chroot, using the host kernel.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile


RUN_ROOT = Path('/usr/obj/usr/src/build-runs')

_closure_spec = importlib.util.spec_from_file_location('package_closure',
    Path(__file__).with_name('package_closure.py'))
package_closure = importlib.util.module_from_spec(_closure_spec)
_closure_spec.loader.exec_module(package_closure)


def command(*args, capture=False):
    print('+ ' + shlex.join(str(x) for x in args), flush=True)
    return subprocess.run([str(x) for x in args], check=True, text=True,
                          capture_output=capture)


def regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('expected regular file: ' + str(path))
    return path.resolve(strict=True)


def new_root(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('destination must be an absolute path without traversal')
    if path.exists() or path.is_symlink():
        raise ValueError('destination must not exist')
    parent = path.parent.resolve(strict=True)
    if parent == Path('/') or str(parent).startswith(('/dev/', '/proc/')):
        raise ValueError('use a dedicated destination parent')
    return parent / path.name


def private_builder_parent(root):
    # Extraction may restore public directory modes from package metadata.
    # Keep the enclosing namespace inaccessible throughout construction.
    info = root.parent.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('deployment root requires a root-owned mode-0700 parent')


def select_packages(names, kernel):
    required = ['5BSD-set-base', '5BSD-kernel-' + kernel.lower().replace('_', '-')]
    missing = set(required) - set(names)
    if missing:
        raise ValueError('repository lacks required packages: ' + ', '.join(sorted(missing)))
    selected = required + sorted(n for n in names if n.startswith(('5BSD-hw-', '5BSD-hardware-abi-')))
    if 'pkg' in names:
        selected.append('pkg')
    return selected



def require_package_closure(inventory, selected):
    packages = {}
    for package in inventory['packages']:
        name = package['name']
        if name in packages or package['manifest'].get('name') != name:
            raise ValueError('duplicate or inconsistent fetched package identity: ' + name)
        packages[name] = package
    if not selected:
        raise ValueError('explicit selected package roots required')
    missing = set(selected) - packages.keys()
    if missing:
        raise ValueError('fetched inventory lacks selected packages: ' + ', '.join(sorted(missing)))
    package_closure.require_selected_set(p['manifest'] for p in packages.values())
    reached, pending = set(), list(selected)
    while pending:
        name = pending.pop()
        if name not in reached:
            reached.add(name)
            pending.extend(packages[name]['manifest'].get('deps', {}))
    extra = packages.keys() - reached
    if extra:
        raise ValueError('fetched inventory includes unrequested packages: ' + ', '.join(sorted(extra)))
    return sorted(packages)


def repository_definition(repository, public):
    # pkg's file transport takes a literal absolute path, not percent escapes.
    # Serialize as JSON so path characters cannot alter repository settings.
    return json.dumps({'bsd_build': {'url': 'file://' + str(repository.resolve()), 'enabled': True,
        'signature_type': 'pubkey', 'pubkey': str(public), 'mirror_type': 'none'}}) + '\n'


def clean_result(result):
    # pkg may return zero while reporting failed signature verification.
    if result.stderr:
        raise ValueError('pkg verification diagnostic: ' + result.stderr.strip())
    return result.stdout


def load_package_inventory():
    spec = importlib.util.spec_from_file_location('package_inventory',
        Path(__file__).with_name('package_inventory.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_generation_check():
    spec = importlib.util.spec_from_file_location('generation_check',
        Path(__file__).with_name('generation_check.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_hardware():
    spec = importlib.util.spec_from_file_location('hardware_packages',
        Path(__file__).resolve().parents[3] / 'release/scripts/hardware-packages.py')
    hw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hw)
    return hw


# These are directories this backend itself creates/uses, not an OS inventory.
DEPLOYMENT_WORK_DIRECTORIES = ('dev', 'var', 'var/db', 'var/db/pkg', 'bin', 'etc')


def deployment_private_paths(expected):
    """Derive traversal directories from validated package/generated objects."""
    paths = set(DEPLOYMENT_WORK_DIRECTORIES)
    for name, item in expected.items():
        path = Path(name)
        if not path.is_absolute() or '..' in path.parts:
            raise ValueError('invalid deployment object path: ' + name)
        directories = list(path.parents)
        if item['type'] == 'directory':
            directories.append(path)
        paths.update(str(p).lstrip('/') for p in directories if p != Path('/'))
    return tuple(sorted(paths))


def be_name(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', value):
        raise ValueError('invalid boot environment name')
    return value


def mount_inventory():
    result = command('/sbin/mount', '-p', capture=True)
    if result.stderr:
        raise ValueError('cannot read mount inventory: ' + result.stderr.strip())
    rows = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 6:
            raise ValueError('malformed mount inventory')
        source, target, kind = fields[:3]
        target = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), target)
        rows.append((source, Path(target), kind, fields[3].split(',')))
    return rows


def devfs_identity(path):
    # Exclusive-builder consistency check, not an atomic mount reference.
    # A retained descriptor would itself prevent unmount; reject observed
    # replacement before operating by name and leave ambiguous state intact.
    if path.resolve(strict=True) != path:
        raise ValueError('temporary devfs path was redirected')
    rows = mount_inventory()
    matching = [row for row in rows if row[1] == path]
    if (len(matching) != 1 or matching[0][0] != 'devfs' or
            matching[0][2] != 'devfs' or
            any(path in row[1].parents for row in rows)):
        raise ValueError('temporary devfs mount topology changed')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        node, filesystem = os.fstat(fd), os.fstatvfs(fd)
        return (node.st_dev, node.st_ino, filesystem.f_fsid)
    finally:
        os.close(fd)


def unmount_devfs(path, expected):
    if expected is None or devfs_identity(path) != expected:
        raise ValueError('temporary devfs identity changed; retained for diagnosis')
    command('umount', path)


def zfs_properties(dataset):
    result = command('/sbin/zfs', 'get', '-Hp', '-o', 'property,value',
                     'guid,origin,readonly', dataset, capture=True)
    props = {}
    for line in result.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) != 2 or fields[0] in props:
            raise ValueError('invalid ZFS identity response')
        props[fields[0]] = fields[1]
    if (result.stderr or set(props) != {'guid', 'origin', 'readonly'} or
            not re.fullmatch(r'[0-9]+', props['guid']) or
            not 0 < int(props['guid']) < 2**64 or
            props['readonly'] not in ('on', 'off') or not props['origin']):
        raise ValueError('invalid ZFS identity response')
    return props



def zfs_guid(dataset):
    result = command('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'guid', dataset, capture=True)
    value = result.stdout.strip()
    if (result.stderr or not re.fullmatch(r'[0-9]+', value) or
            not 0 < int(value) < 2**64):
        raise ValueError('invalid ZFS GUID response')
    return value


def be_check_source_identity(source, phase):
    if zfs_properties(source['source'])['guid'] != source['guid']:
        raise ValueError('boot-environment source identity changed ' + phase)
    if '@' in source['selector']:
        expected = source.get('snapshot_guid')
        if expected is None or zfs_guid(source['root'] + '/' + source['selector']) != expected:
            raise ValueError('boot-environment snapshot identity changed ' + phase)


def be_source(clone_from=None, be_root=None, *, private_paths):
    mounts = mount_inventory()
    active = [row for row in mounts if row[1] == Path('/')]
    if be_root is None:
        if len(active) != 1 or active[0][2] != 'zfs':
            raise ValueError('boot-environment deployment requires a ZFS root')
        be_root, active_name = active[0][0].rsplit('/', 1)
        clone_from = clone_from or active_name
    elif not clone_from:
        raise ValueError('--be-root requires an explicit --clone-from')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:-]*', be_root) or any(x in ('', '.', '..') for x in be_root.split('/')):
        raise ValueError('invalid boot-environment root dataset')
    if clone_from.startswith(be_root + '/'):
        clone_from = clone_from[len(be_root)+1:]
    parts = clone_from.split('@')
    if len(parts) > 2:
        raise ValueError('invalid source snapshot')
    be_name(parts[0])
    if len(parts) == 2 and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', parts[1]):
        raise ValueError('invalid source snapshot')
    source = be_root + '/' + parts[0]
    props = zfs_properties(source)
    snapshot_guid = zfs_guid(be_root + '/' + clone_from) if len(parts) == 2 else None
    # Reject mounts covering package/generated traversal directories or backend
    # state. Candidate mount topology is checked independently before chroot.
    for row in mounts:
        if row[1] == Path('/'):
            continue
        for relative in private_paths:
            critical = Path('/') / relative
            if row[1] == critical or row[1] in critical.parents:
                raise ValueError('shared or separately mounted deployment state requires explicit migration: ' + str(row[1]))
    return {'root': be_root, 'selector': clone_from, 'source': source, 'guid': props['guid'],
            'snapshot_guid': snapshot_guid, 'private_paths': private_paths}


def be_create(name, source):
    # Dataset names can be reused between planning and creation. Refuse an
    # observed replacement; these checks do not serialize other ZFS writers.
    be_check_source_identity(source, 'before creation')
    prefix = ['bectl', '-r', source['root']]
    command(*prefix, 'create', '-r', '-e', source['selector'], name)
    target = source['root'] + '/' + name
    props = zfs_properties(target)
    if props['guid'] == source['guid'] or not props['origin'].startswith(source['source'] + '@'):
        raise ValueError('new boot environment does not have an independent clone identity')
    if '@' in source['selector'] and props['origin'] != source['root'] + '/' + source['selector']:
        raise ValueError('new boot environment has the wrong snapshot origin')
    # Preserve the candidate on mismatch; do not destroy by a name whose
    # relationship to the selected source is now uncertain.
    candidate = dict(command=prefix, dataset=target, guid=props['guid'], origin=props['origin'])
    be_check_source_identity(source, 'during creation')
    be_check_candidate_identity(candidate)
    command('/sbin/zfs', 'set', 'readonly=off', target)
    return candidate


def be_check_candidate_identity(candidate):
    # Consistency check in an exclusive builder, not a name-to-object lock.
    # On replacement leave state for diagnosis rather than mutating by name.
    actual = zfs_properties(candidate['dataset'])
    if actual['guid'] != candidate['guid'] or actual['origin'] != candidate['origin']:
        raise ValueError('candidate identity changed: ' + candidate['dataset'])


def be_check_target(root, source, name):
    rows = mount_inventory()
    matching = [row for row in rows if row[1] == root]
    target = source['root'] + '/' + name
    if len(matching) != 1 or matching[0][0] != target or matching[0][2] != 'zfs' or 'rw' not in matching[0][3]:
        raise ValueError('candidate is not the expected writable ZFS clone')
    # Package scripts run in a chroot and can address any descendant. A shared
    # mount unrelated to package payloads is still unsafe during installation.
    if any(root in row[1].parents for row in rows):
        raise ValueError('candidate contains a nested mount before installation')
    root_dev = root.stat().st_dev
    for relative in source['private_paths']:
        current = root
        for part in Path(relative).parts:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_dev != root_dev:
                raise ValueError('candidate package/software state is not private to the clone: ' + str(current))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--pkg-public-key', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--generated', type=Path, required=True,
                        help='explicit generated-file provenance and metadata manifest')
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--root', type=Path)
    target.add_argument('--bootenv')
    parser.add_argument('--kernel', default='GENERIC')
    parser.add_argument('--clone-from', help='source BE or BE@snapshot; defaults to active BE')
    parser.add_argument('--be-root', help='explicit ZFS boot-environment parent dataset')
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--capsign', default='/usr/sbin/capsign')
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    if not repository.is_dir() or not (repository / 'publication.json').is_file():
        raise ValueError('repository is not a completed combined publication')
    if any(p.is_symlink() for p in repository.rglob('*')):
        raise ValueError('published generation must not contain symlinks')
    pub = regular(args.pkg_public_key)
    codepub = regular(args.public_key)
    regular(args.capsign)
    generated_source = regular(args.generated)
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', args.kernel):
        raise ValueError('invalid kernel configuration name')
    if args.bootenv and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', args.bootenv):
        raise ValueError('invalid boot environment name')
    if (args.clone_from or args.be_root) and not args.bootenv:
        raise ValueError('--clone-from/--be-root require --bootenv')
    if args.clone_from and any(ord(c) < 32 for c in args.clone_from):
        raise ValueError('invalid source snapshot')
    root = new_root(args.root) if args.root else None
    print('repository=' + str(repository))
    print('target=' + (str(root) if root else 'new inactive boot environment ' + args.bootenv))
    if args.plan:
        if root is not None:
            print('require a root-owned mode-0700 destination parent before fetching or extraction')
        print('snapshot publication and explicit public keys in private run directory')
        print('verify signed pkg catalogue and archive downloads; select base, kernel and matching hardware')
        print('inventory authenticated package payloads and reject ownership/path conflicts before creating destination')
        print('derive private traversal directories from package/generated objects; reject shared candidate mounts before installation')
        print('create destination; install using target chroot and isolated pkg database')
        print('verify all signed system bundles with capsign')
        print('unmount temporary devfs; reconcile complete candidate against verified packages and explicit generated inputs')
        print('require zero unexplained differences; retain report; unmount boot environment')
        if args.bootenv:
            print('clone source=' + (args.clone_from or 'current boot environment'))
        print('scope: trusted-builder preparation; live BIP update/activation is not implemented')
        print('no boot environment activation or reboot')
        return
    if os.geteuid() != 0:
        raise PermissionError('deployment requires a root shell for chroot, ownership and boot-environment mounts')
    if root is not None:
        private_builder_parent(root)
    # Freeze the publication and explicit trust inputs once, before validation.
    # Both inventory and installation consume this private builder snapshot;
    # changing the source publication later cannot select different payloads.
    # The release builder is trusted. This is not a root-resistant live updater.
    scratch = Path(tempfile.mkdtemp(prefix='deploy-', dir=RUN_ROOT)).resolve(strict=True)
    shutil.copyfile(generated_source, scratch / 'generated.json')
    generation = load_generation_check()
    generated, generated_hash = generation.read_json(scratch / 'generated.json')
    repository_source = repository
    shutil.copytree(repository, scratch / 'repository', symlinks=True)
    repository = scratch / 'repository'
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in repository.rglob('*')):
        raise ValueError('unsupported entry in copied publication')
    hw = load_hardware()
    for source_key, name in ((pub, 'repository.pub'), (codepub, 'code.pub')):
        hw.copy_public_key(source_key, scratch / name)
    pub, codepub = scratch / 'repository.pub', scratch / 'code.pub'
    # Verification and downloads happen before any boot environment creation.
    info = hw.verify(repository)
    pkg = regular('/usr/local/sbin/pkg-static')
    abi = info['abi']
    host_abi = command(pkg, 'config', 'ABI', capture=True).stdout.strip()
    if abi.split(':')[-1] != host_abi.split(':')[-1]:
        raise ValueError('deployment requires a target-native host; use installer media for a foreign architecture')
    osversion = info.get('osversion')
    if not str(osversion).isdigit():
        raise ValueError('repository lacks target OS version')
    # Retain the work directory, including on failed unmount. An automatic
    # recursive temporary-directory cleanup must never walk a mounted BE.
    repos = scratch / 'repos'
    repos.mkdir()
    (repos / 'build.conf').write_text(repository_definition(repository, pub))
    for name in ('db', 'cache'):
        (scratch / name).mkdir()
    pkgcmd = [pkg, '-C', '/dev/null', '-R', repos, '-o', 'ABI=' + abi,
              '-o', 'OSVERSION=' + str(osversion), '-o', 'PKG_ENABLE_PLUGINS=no',
              '-o', 'REPO_AUTOUPDATE=no', '-o', 'PKG_DBDIR=' + str(scratch / 'db'),
              '-o', 'PKG_CACHEDIR=' + str(scratch / 'cache')]
    clean_result(command(*pkgcmd, 'update', '-f', '-r', 'bsd_build', capture=True))
    names = clean_result(command(*pkgcmd, 'rquery', '-U', '-r', 'bsd_build', '%n', capture=True)).splitlines()
    selected = select_packages(names, args.kernel)
    fetched = scratch / 'fetched'
    clean_result(command(*pkgcmd, 'fetch', '-y', '-d', '-o', fetched, '-r',
                         'bsd_build', *selected, capture=True))
    archives = sorted((fetched / 'All').glob('*.pkg'))
    if not archives or any(p.is_symlink() or not p.is_file() for p in archives):
        raise ValueError('invalid fetched package archive set')
    # Use the exact pkg-verified downloaded archives, never the live pkg DB or
    # a maintained application list. This is provenance/inventory, not BIP
    # filesystem reconciliation or permission to add writable exceptions.
    payload_inventory = load_package_inventory().inventory_packages(archives)
    install_names = require_package_closure(payload_inventory, selected)
    payload_inventory['authentication'] = {
        'method': 'pkg-fetch-from-verified-catalogue',
        'repository': str(repository_source), 'snapshot': str(repository),
        'abi': abi, 'osversion': osversion,
        'public_key_sha256': hw.sha256(pub),
    }
    (scratch / 'package-inventory.json').write_text(
        json.dumps(payload_inventory, indent=2, sort_keys=True) + '\n')
    # Reject malformed or ambiguous construction inputs before target creation.
    # Inventory comes from the authenticated fetch, never caller-supplied JSON.
    expected = generation.expected_objects(payload_inventory, generated)
    private_paths = deployment_private_paths(expected)
    source = be_source(args.clone_from, args.be_root,
                       private_paths=private_paths) if args.bootenv else None
    be_prefix = ['bectl', '-r', source['root']] if source else None
    candidate = None
    mount_attempted = False
    devmounted = False
    dev_identity = None
    created = False
    try:
        if args.bootenv:
            root = scratch / 'root'
            # Existing names cause bectl to fail; never destroy or reuse one.
            # Record creation intent so a failure retains a useful diagnostic.
            # bectl refuses an existing target; no destroy or activation occurs.
            created = True
            candidate = be_create(args.bootenv, source)
            be_prefix = candidate['command']
            be_check_candidate_identity(candidate)
            mount_attempted = True
            command(*be_prefix, 'mount', args.bootenv, root)
            be_check_candidate_identity(candidate)
            be_check_target(root, source, args.bootenv)
        else:
            root.mkdir(mode=0o700)
            created = True
            # Bootstrap only from pkg-verified archives. No target code or
            # package scripts run during extraction. pkg then reinstalls
            # and registers these files inside the complete target chroot.
            for archive in archives:
                command('tar', '-xpf', archive, '-C', root, '--exclude', '+*')
        for directory in DEPLOYMENT_WORK_DIRECTORIES:
            path = root / directory
            if path.is_symlink() or (path.exists() and not path.is_dir()):
                raise ValueError('unsafe target directory: ' + directory)
            path.mkdir(exist_ok=True)
        command('mount', '-t', 'devfs', 'devfs', root / 'dev')
        devmounted = True
        dev_identity = devfs_identity(root / 'dev')
        # Inputs reside directly below the private root, outside shared
        # /var or /tmp datasets. No private signing key is copied.
        inputs = Path(tempfile.mkdtemp(prefix='.bsd-build-', dir=root))
        inside = Path('/') / inputs.name
        shutil.copy2(pkg, inputs / 'pkg-static')
        shutil.copy2(pub, inputs / 'repository.pub')
        (inputs / 'repos').mkdir()
        shutil.copytree(repository, inputs / 'repository', symlinks=False)
        (inputs / 'repos/build.conf').write_text(repository_definition(inside / 'repository', inside / 'repository.pub'))
        targetpkg = ['chroot', root, inside / 'pkg-static', '-C', '/dev/null',
                     '-R', inside / 'repos', '-o', 'ABI=' + abi,
                     '-o', 'OSVERSION=' + str(osversion), '-o', 'PKG_ENABLE_PLUGINS=no',
                     '-o', 'REPO_AUTOUPDATE=no', '-o', 'PKG_DBDIR=/var/db/pkg',
                     '-o', 'PKG_CACHEDIR=' + str(inside / 'cache')]
        clean_result(command(*targetpkg, 'update', '-f', '-r', 'bsd_build', capture=True))
        # Re-query the imported catalogue rather than trusting update's status.
        installed_names = clean_result(command(*targetpkg, 'rquery', '-U', '-r', 'bsd_build', '%n', capture=True)).splitlines()
        if sorted(installed_names) != sorted(names):
            raise ValueError('repository catalogue changed during deployment')
        command(*targetpkg, 'install', '-U', '-f', '-y', '-r', 'bsd_build', *install_names)
        command(*targetpkg, 'check', '-s', '-a')
        environment = dict(os.environ, CAPSIGN=args.capsign)
        subprocess.run(['sh', str(Path(__file__).resolve().with_name('verify-stage.sh')),
                        '-r', str(root), '-p', str(codepub)], env=environment, check=True)
        shutil.rmtree(inputs)
        if candidate is not None:
            be_check_candidate_identity(candidate)
        unmount_devfs(root / 'dev', dev_identity)
        devmounted = False
        if not args.bootenv:
            root.chmod(0o755)
        # Check only after transient installation inputs and devfs are removed,
        # while an inactive BE is still mounted. No scan generates exceptions.
        if candidate is not None:
            be_check_candidate_identity(candidate)
        result = generation.reconcile(root, payload_inventory, generated)
        if candidate is not None:
            be_check_candidate_identity(candidate)
            result['deployment_target'] = dict(kind='boot-environment',
                **{field: candidate[field] for field in ('dataset', 'guid', 'origin')})
        else:
            result['deployment_target'] = dict(kind='directory', path=str(root))
        result['input_sha256'] = {
            'inventory': hw.sha256(scratch / 'package-inventory.json'),
            'generated': generated_hash,
        }
        result['package_authentication'] = payload_inventory['authentication']
        (scratch / 'reconciliation.json').write_text(
            json.dumps(result, indent=2, sort_keys=True) + '\n')
        if result['result'] != 'PASS':
            raise ValueError('filesystem reconciliation failed: ' +
                             str(scratch / 'reconciliation.json'))
    except BaseException:
        if created:
            print('Deployment incomplete; retained destination for diagnosis: ' + (args.bootenv or str(root)), file=sys.stderr)
        raise
    finally:
        if devmounted:
            # Do not touch a replacement BE before checking the outer unmount.
            if candidate is not None:
                be_check_candidate_identity(candidate)
            unmount_devfs(root / 'dev', dev_identity)
        if mount_attempted:
            be_check_candidate_identity(candidate)
            command(*be_prefix, 'unmount', args.bootenv)
    print('DEPLOYMENT_VERIFIED scope=packages-bundles-and-filesystem target=' +
          (args.bootenv or str(root)) + ' reconciliation=' + str(scratch / 'reconciliation.json'))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, PermissionError, OSError, subprocess.CalledProcessError) as error:
        print('build-bsd deploy: ' + str(error), file=sys.stderr)
        sys.exit(1)
