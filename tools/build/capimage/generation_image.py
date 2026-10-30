#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Materialize and read back a UFS2 generation image in a trusted builder.

Inputs/receipts are unsigned. This does not authorize signing, boot or activation.
Execution requires root for a private read-only memory-disk mount.
"""
import argparse
import hashlib
import importlib.util
import logging
import os
from pathlib import Path
import re
import subprocess

spec = importlib.util.spec_from_file_location('construction', Path(__file__).with_name('construction.py'))
construction = importlib.util.module_from_spec(spec); spec.loader.exec_module(construction)

spec = importlib.util.spec_from_file_location('verity_artifacts', Path(__file__).with_name('verity_artifacts.py'))
verity = importlib.util.module_from_spec(spec); spec.loader.exec_module(verity)


def file_hash(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def boot_archive(root, observed, destination):
    """Export all /boot objects as a byte transport plus complete observations.

    This is not an installable tree: reconstruction must apply and reconcile the
    observations, including flags and hardlinks, before signing boot media.
    """
    from decimal import Decimal
    import tarfile

    root, destination = Path(root).resolve(strict=True), Path(destination)
    entries = {name: item for name, item in observed.items()
               if name == '/boot' or name.startswith('/boot/')}
    if entries.get('/boot', {}).get('type') != 'directory':
        raise ValueError('boot archive requires a complete boot directory')
    if destination.resolve().is_relative_to(root):
        raise ValueError('boot archive output must be outside the generation')
    if construction.generation.scan(root) != observed:
        raise ValueError('generation changed before boot archive creation')
    with destination.open('xb') as stream:
        os.chmod(destination, 0o600)
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name, item in sorted(entries.items()):
                header = tarfile.TarInfo(name.lstrip('/'))
                header.uid, header.gid, header.mode = item['uid'], item['gid'], item['mode']
                header.mtime = item['mtime']
                header.pax_headers['mtime'] = str(Decimal(item['mtime']) +
                    Decimal(item['mtime_nsec']) / Decimal(1000000000))
                if item['type'] == 'directory':
                    header.type = tarfile.DIRTYPE
                    archive.addfile(header)
                elif item['type'] == 'symlink':
                    header.type, header.linkname = tarfile.SYMTYPE, item['target']
                    archive.addfile(header)
                elif item['type'] == 'file':
                    # Store each alias's bytes. Hardlink identity is retained in
                    # the bound observation, including aliases outside /boot.
                    header.size = item['size']
                    fd = os.open(root / name.lstrip('/'), os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(fd, 'rb') as payload:
                        archive.addfile(header, payload)
                else:
                    raise ValueError('unsupported boot object: ' + name)
    if construction.generation.scan(root) != observed:
        raise ValueError('generation changed during boot archive creation')
    # Verify the serialized transport without extracting paths or following links.
    with tarfile.open(destination, mode='r:') as archive:
        members = archive.getmembers()
        if [m.name for m in members] != [n.lstrip('/') for n in sorted(entries)]:
            raise ValueError('boot archive namespace differs from observation')
        for member in members:
            item = entries['/' + member.name]
            if (member.uid, member.gid, member.mode) != (item['uid'], item['gid'], item['mode']):
                raise ValueError('boot archive metadata differs from observation')
            stamp = Decimal(member.pax_headers['mtime']) * 1000000000
            if stamp != item['mtime'] * 1000000000 + item['mtime_nsec']:
                raise ValueError('boot archive timestamp differs from observation')
            if item['type'] == 'file':
                if not member.isfile() or member.size != item['size']:
                    raise ValueError('boot archive file type/size differs from observation')
                with archive.extractfile(member) as payload:
                    if hashlib.file_digest(payload, 'sha256').hexdigest() != item['sha256']:
                        raise ValueError('boot archive bytes differ from observation')
            elif item['type'] == 'symlink':
                if not member.issym() or member.linkname != item['target']:
                    raise ValueError('boot archive link differs from observation')
            elif not member.isdir():
                raise ValueError('boot archive directory differs from observation')
    return {'format': 1, 'scope': 'generation-boot-transport', 'result': 'PASS',
            'archive_sha256': file_hash(destination), 'archive_bytes': destination.stat().st_size,
            'source_observation_sha256': construction.digest(observed),
            'entries': entries, 'metadata_reconstruction_required': True,
            'generation_authenticated': False, 'activation_authorized': False}


def prepare(root, inventory_record, generated, receipt):
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or root.resolve() == Path('/'):
        raise ValueError('requires an alternate nonsymlink generation directory')
    root = root.resolve(strict=True)
    inventory = construction.inventory_from_archives(inventory_record)
    if (receipt.get('scope') != 'trusted-builder-construction' or receipt.get('result') != 'PASS' or
            receipt.get('inventory_sha256') != construction.digest(inventory) or
            receipt.get('generated_sha256') != construction.digest(generated)):
        raise ValueError('complete construction receipt does not bind selected inputs')
    observed = construction.require_match(root, inventory, generated)
    if receipt.get('filesystem_sha256') != construction.digest(observed):
        raise ValueError('construction receipt does not bind final filesystem')
    return root, observed


def partitions(inventory, observed, policy):
    """Derive image observations from explicit, validated storage boundaries.

    Empty attachment slots are format objects owned by root; seed roots retain
    the original directory metadata. This transformation is recorded explicitly.
    """
    import copy
    layout = construction.generation.storage_layout(inventory, observed, policy)
    base = {name: copy.deepcopy(observed[name]) for name in layout['immutable_objects']}
    images = []
    for boundary in layout['boundaries']:
        path = boundary['path']
        def rebase(name):
            return '/' if name == path else name[len(path):]
        seed = {}
        sources = {}
        for name, value in boundary['seed_objects'].items():
            item = copy.deepcopy(value)
            if 'hardlinks' in item:
                item['hardlinks'] = [rebase(alias) for alias in item['hardlinks']]
            seed[rebase(name)] = item
            sources[rebase(name)] = name
        original = boundary['seed_objects'][path]
        base[path] = dict(type='directory', uid=0, gid=0, mode=0o755,
                          flags_set=0, mtime=original['mtime'], mtime_nsec=original['mtime_nsec'])
        images.append(dict(boundary=path, content=boundary['content'],
                           observed=seed, sources=sources))
    images.insert(0, dict(boundary=None, content='immutable', observed=base,
                         sources={name: name for name in base}))
    return layout, images


def image_manifest(root, projection):
    """Use a complete mtree input, never -F's overlay of an unfiltered tree."""
    import ctypes as C
    lib = C.CDLL(None)
    lib.fflagstostr.argtypes, lib.fflagstostr.restype = [C.c_ulong], C.c_void_p
    lib.strtofflags.argtypes = [C.POINTER(C.c_char_p), C.POINTER(C.c_ulong), C.POINTER(C.c_ulong)]
    lib.strtofflags.restype = C.c_int
    lib.free.argtypes = [C.c_void_p]
    def flags_text(flags):
        if flags == 0:
            return 'none'
        ptr = lib.fflagstostr(flags)
        if not ptr:
            raise ValueError('cannot encode image flags')
        try:
            value = C.string_at(ptr)
        finally:
            lib.free(ptr)
        buffer = C.create_string_buffer(value); cursor = C.cast(buffer, C.c_char_p)
        setflags, clearflags = C.c_ulong(), C.c_ulong()
        if lib.strtofflags(C.byref(cursor), C.byref(setflags), C.byref(clearflags)) or setflags.value != flags or clearflags.value:
            raise ValueError('unsupported image flags')
        return value.decode('ascii')
    def escape(value):
        safe = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_.-'
        return ''.join(chr(b) if b in safe else '\\%03o' % b for b in value.encode('utf-8'))
    lines = ['#mtree 2.0']
    for name, item in sorted(projection['observed'].items()):
        kind = {'directory': 'dir', 'file': 'file', 'symlink': 'link'}[item['type']]
        fields = [escape('.' if name == '/' else '.' + name), 'type=' + kind,
                  'uid=' + str(item['uid']), 'gid=' + str(item['gid']),
                  'mode=%04o' % item['mode'], 'flags=' + flags_text(item['flags_set']),
                  'time=%d.%09d' % (item['mtime'], item['mtime_nsec'])]
        if kind == 'file':
            fields.append('contents=' + escape(str(root / projection['sources'][name].lstrip('/'))))
        elif kind == 'link':
            if len(item.get('hardlinks', [])) > 1:
                raise ValueError('makefs image does not yet support hardlinked symlinks')
            fields.append('link=' + escape(item['target']))
        lines.append(' '.join(fields))
    return '\n'.join(lines) + '\n'


def validate_layout_version(policy):
    if isinstance(policy, dict) and policy.get('format') == 3:
        raise ValueError('BIP format-3 images have been retired')


def validate_verity_layout(projections, input_bindings):
    """Check the mountroot ABI against reconciled inventory, never invent files.

    These two slots belong to kernel root staging, not writable-state attachment.
    The descriptor still authenticates image bytes; this is layout validation only.
    """
    if (input_bindings or {}).get('verity_policy') is None:
        return
    base = projections[0]
    if base['boundary'] is not None or base['content'] != 'immutable':
        raise ValueError('verity layout requires an immutable base')
    observed = base['observed']
    for path in ('/.mount', '/dev'):
        item = observed.get(path, {})
        if (item.get('type') != 'directory' or item.get('uid') != 0 or
                item.get('mode', 0) & 0o022):
            raise ValueError('verity staging requires a root-owned non-writable directory: ' + path)
        if any(name.startswith(path + '/') for name in observed):
            raise ValueError('verity staging directory must be empty: ' + path)
        if any(entry['boundary'] == path or
               (entry['boundary'] or '').startswith(path + '/')
               for entry in projections[1:]):
            raise ValueError('verity staging slot cannot be a writable-state boundary: ' + path)


def verify_layout(work, observed, inventory, policy, input_bindings=None, *, root=None):
    """Verify retained artifacts against caller-selected construction inputs.

    This checks transport consistency, not publisher trust or a new filesystem
    readback. The caller must independently authenticate its selected inputs.
    """
    validate_layout_version(policy)
    work = Path(work)
    if work.is_symlink() or not work.is_dir():
        raise ValueError('layout output must be a physical directory')
    work = work.resolve(strict=True)
    layout, projections = partitions(inventory, observed, policy)
    validate_verity_layout(projections, input_bindings)
    def regular(path):
        if path.is_symlink() or not path.is_file():
            raise ValueError('layout artifact must be a regular nonsymlink file: ' + str(path))
        return path
    def record(path):
        return construction.generation.read_json(regular(path))[0]
    report = record(work / 'receipt.json')
    if report.get('storage_binding') is not None:
        raise ValueError('retired BIP storage binding in image receipt')
    bindings = dict(input_bindings or {})
    # Selected observation is stable during this synchronous verification.
    # Reuse its digest only within this call; retained files are still rehashed.
    observation_digest = construction.digest(observed)
    if (report.get('scope') != 'trusted-builder-storage-images' or report.get('format') != 1 or
            report.get('result') != 'PASS' or report.get('layout') != layout or
            report.get('source_observation_sha256') != observation_digest or
            report.get('policy_sha256') != construction.digest(policy) or
            report.get('input_bindings') != bindings or
            any(report.get(key) is not False for key in ('generation_authenticated',
                'activation_authorized', 'seeds_installed', 'attachments_constructed'))):
        raise ValueError('layout receipt does not bind selected construction inputs and scope')
    entries = report.get('images')
    if not isinstance(entries, list) or len(entries) != len(projections):
        raise ValueError('layout image set is incomplete')
    verified = []
    for index, (entry, projection) in enumerate(zip(entries, projections)):
        # Derive artifact paths; never follow directory names supplied by a receipt.
        directory = 'base' if index == 0 else 'seed-' + str(index)
        folder = work / directory
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError('layout image directory must be physical')
        if (entry.get('directory') != directory or entry.get('boundary') != projection['boundary'] or
                entry.get('content') != projection['content'] or
                entry.get('observations') != projection['observed']):
            raise ValueError('layout image projection differs from selected inputs')
        receipt = record(folder / 'receipt.json')
        expected = construction.digest(projection['observed'])
        if (entry.get('receipt') != receipt or receipt.get('format') != 1 or
                receipt.get('scope') != 'trusted-builder-partition-image' or
                receipt.get('partition_content') != projection['content'] or
                'partition_boundary' not in receipt or receipt['partition_boundary'] != projection['boundary'] or
                receipt.get('result') != 'PASS' or receipt.get('input_bindings') != bindings or
                receipt.get('source_observation_sha256') != observation_digest or
                receipt.get('expected_observation_sha256') != expected or
                receipt.get('readback_observation_sha256') != expected or
                any(receipt.get(key) is not False for key in ('inputs_authenticated',
                    'generation_authenticated', 'activation_authorized'))):
            raise ValueError('partition receipt does not bind image projection and readback')
        artifact = regular(folder / 'system.ufs')
        manifest = regular(folder / 'filesystem.mtree')
        digest = file_hash(artifact)
        if (receipt.get('image_sha256') != digest or
                receipt.get('image_bytes') != artifact.stat().st_size or
                receipt.get('manifest_sha256') != file_hash(manifest)):
            raise ValueError('retained partition artifact differs from receipt')
        selected_verity = bindings.get('verity_policy') if index == 0 else None
        if selected_verity is not None:
            verity.verify(folder, receipt.get('verity'), selected_verity,
                          digest, artifact.stat().st_size)
        elif 'verity' in receipt:
            raise ValueError('unexpected verity artifact without selected policy')
        if 'boot_archive' in receipt:
            validate_boot_projection(observed, projection)
            spec = importlib.util.spec_from_file_location('generation_boot', Path(__file__).with_name('generation_boot.py'))
            boot = importlib.util.module_from_spec(spec); spec.loader.exec_module(boot)
            boot.verify(artifact, regular(folder / 'boot.tar'), folder / 'receipt.json')
        verified.append(dict(directory=directory, image_sha256=digest,
                             observation_sha256=expected))
    return dict(format=1, scope='retained-storage-image-consistency', result='PASS',
                receipt_sha256=file_hash(work / 'receipt.json'), images=verified,
                generation_authenticated=False, activation_authorized=False,
                filesystem_readback_repeated=False)


def validate_boot_projection(observed, projection):
    def boot_objects(items):
        return {name: item for name, item in items.items()
                if name == '/boot' or name.startswith('/boot/')}
    if (projection['content'] != 'immutable' or projection['boundary'] is not None or
            not boot_objects(observed) or
            boot_objects(projection['observed']) != boot_objects(observed)):
        raise ValueError('boot transport requires unchanged immutable boot objects')


def materialize_layout(root, observed, inventory, policy, tools, work, input_bindings=None, export_boot=False):
    validate_layout_version(policy)
    root, work = Path(root).resolve(strict=True), Path(work)
    if work.exists() or work.is_symlink() or work.resolve().is_relative_to(root):
        raise ValueError('layout output must be new and outside the generation')
    layout, images = partitions(inventory, observed, policy)
    validate_verity_layout(images, input_bindings)
    if os.geteuid() != 0:
        raise PermissionError('image read-back requires root in a trusted builder; use a disposable VM')
    logging.getLogger(__name__).info('Checking complete source before layout construction')
    if construction.generation.scan(root) != observed:
        raise ValueError('generation changed before layout image creation')
    work.mkdir(mode=0o700)
    report = dict(format=1, scope='trusted-builder-storage-images', result='RUNNING',
                  source_observation_sha256=construction.digest(observed),
                  policy_sha256=construction.digest(policy), layout=layout,
                  input_bindings=dict(input_bindings or {}), images=[],
                  generation_authenticated=False, activation_authorized=False,
                  seeds_installed=False, attachments_constructed=False)
    construction.write_record(work / 'construction.json', report)
    try:
        for index, projection in enumerate(images):
            logging.getLogger(__name__).info('Constructing and reading back image %d of %d', index + 1, len(images))
            directory = 'base' if index == 0 else 'seed-' + str(index)
            receipt = _materialize(root, observed, tools, work / directory,
                                  projection=projection, input_bindings=input_bindings,
                                  export_boot=export_boot and index == 0,
                                  verity_policy=(input_bindings or {}).get('verity_policy') if index == 0 else None)
            report['images'].append(dict(directory=directory, boundary=projection['boundary'],
                content=projection['content'], observations=projection['observed'], receipt=receipt))
        logging.getLogger(__name__).info('Checking complete source after all image readbacks')
        if construction.generation.scan(root) != observed:
            raise ValueError('generation changed during layout image creation')
        for entry in report['images']:
            folder = work / entry['directory']
            construction.write_record(folder / 'construction.json', entry['receipt'])
            construction.write_record(folder / 'receipt.json', entry['receipt'])
        report['result'] = 'PASS'
        construction.write_record(work / 'receipt.json', report)
        checked = verify_layout(work, observed, inventory, policy, input_bindings, root=root)
        construction.write_record(work / 'verification.json', checked)
        construction.write_record(work / 'construction.json', report)
        return report
    except BaseException as error:
        (work / 'receipt.json').unlink(missing_ok=True)
        # A partition receipt is not independently publishable when the complete
        # selected layout failed. Derive paths from the construction plan, not
        # from receipt contents, and retain image bytes only for diagnosis.
        for index in range(len(images)):
            directory = 'base' if index == 0 else 'seed-' + str(index)
            (work / directory / 'receipt.json').unlink(missing_ok=True)
        (work / 'verification.json').unlink(missing_ok=True)
        report.update(result='FAIL', error=str(error))
        construction.write_record(work / 'construction.json', report)
        raise


def materialize(root, observed, tools, work, timeout=600, input_bindings=None, export_boot=False, projection=None):
    """Standalone image construction with whole-source consistency checks."""
    if os.geteuid() != 0:
        raise PermissionError('image read-back requires root in a trusted builder; use a disposable VM')
    root = Path(root).resolve(strict=True)
    if construction.generation.scan(root) != observed:
        raise ValueError('generation changed before image creation')
    report = _materialize(root, observed, tools, work, timeout=timeout,
        input_bindings=input_bindings, export_boot=export_boot, projection=projection)
    try:
        if construction.generation.scan(root) != observed:
            raise ValueError('generation changed during image creation')
        construction.write_record(Path(work) / 'construction.json', report)
        construction.write_record(Path(work) / 'receipt.json', report)
        return report
    except BaseException as error:
        (Path(work) / 'receipt.json').unlink(missing_ok=True)
        report.update(result='FAIL', error=str(error))
        construction.write_record(Path(work) / 'construction.json', report)
        raise


def _materialize(root, observed, tools, work, timeout=600, input_bindings=None, export_boot=False, projection=None, verity_policy=None):
    """Build and independently read back one image within a checked operation.

    materialize and materialize_layout own the before/after whole-source checks.
    This internal worker always compares the mounted image to its projection.
    """
    if os.geteuid() != 0:
        raise PermissionError('image read-back requires root in a trusted builder; use a disposable VM')
    root = Path(root).resolve(strict=True)
    work = Path(work)
    if work.exists() or work.is_symlink() or work.resolve().is_relative_to(root):
        raise ValueError('image output must be new and outside the generation')
    work = work.resolve()
    if set(tools) != {'makefs', 'mdconfig', 'mount', 'umount'}:
        raise ValueError('all four explicit image tools required')
    programs = {}
    for name, path in tools.items():
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise ValueError('image tools must be regular nonsymlink files')
        path = path.resolve(strict=True)
        if path.is_relative_to(root):
            raise ValueError('image tool cannot come from the candidate')
        programs[name] = path
    hashes = {str(p): file_hash(p) for p in programs.values()}
    if projection is not None and export_boot:
        validate_boot_projection(observed, projection)
    if verity_policy is not None:
        verity_policy = verity.policy(verity_policy)
        if projection is None or projection['content'] != 'immutable' or projection['boundary'] is not None:
            raise ValueError('verity output requires the selected immutable base projection')
    expected = observed if projection is None else projection['observed']
    work.mkdir(mode=0o700)
    image = work / 'system.ufs'
    mountpoint = work / 'mounted'; mountpoint.mkdir(mode=0o700)
    report = dict(format=1, scope='trusted-builder-filesystem-image', result='RUNNING',
                  inputs_authenticated=False, generation_authenticated=False, activation_authorized=False,
                  source_observation_sha256=construction.digest(observed), tools_sha256=hashes,
                  input_bindings=dict(input_bindings or {}))
    construction.write_record(work / 'construction.json', report)
    device = None
    mounted = False

    def run(name, *args):
        result = subprocess.run([str(programs[name]), *map(str, args)],
            env=construction.ENVIRONMENT, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=timeout, close_fds=True)
        with (work / 'commands.log').open('a') as log:
            log.write(result.stdout + result.stderr)
        result.check_returncode()
        return result.stdout.strip()

    try:
        source = root
        if projection is not None:
            source = work / 'filesystem.mtree'
            source.write_text(image_manifest(root, projection))
            report['scope'] = 'trusted-builder-partition-image'
            report['partition_content'] = projection['content']
            report['partition_boundary'] = projection['boundary']
            report['manifest_sha256'] = file_hash(source)
            report['expected_observation_sha256'] = construction.digest(expected)
        geometry = verity.makefs_options(verity_policy)
        run('makefs', '-t', 'ffs', '-o', 'version=2', *geometry, image, source)
        allocated = run('mdconfig', '-a', '-t', 'vnode', '-o', 'readonly', '-f', image)
        if not re.fullmatch(r'md[0-9]+', allocated):
            raise ValueError('unexpected memory-disk allocation response')
        device = allocated
        run('mount', '-t', 'ufs', '-o', 'ro', '/dev/' + device, mountpoint)
        mounted = True
        if not os.statvfs(mountpoint).f_flag & os.ST_RDONLY:
            raise ValueError('image read-back mount is writable')
        actual = construction.generation.scan(mountpoint)
        if actual != expected:
            raise ValueError('image read-back differs from complete generation observation')
        run('umount', mountpoint); mounted = False
        run('mdconfig', '-d', '-u', device[2:]); device = None
        for name, expected in hashes.items():
            if file_hash(Path(name)) != expected:
                raise ValueError('image tool changed during construction')
        if export_boot:
            boot = boot_archive(root, observed, work / 'boot.tar')
            construction.write_record(work / 'boot.json', boot)
            report['boot_archive'] = boot
        report.update(result='PASS', image_sha256=file_hash(image),
                      image_bytes=image.stat().st_size, readback_observation_sha256=construction.digest(actual))
        if verity_policy is not None:
            report['verity'] = verity.build(work, verity_policy,
                report['image_sha256'], report['image_bytes'])
            verity.verify(work, report['verity'], verity_policy,
                report['image_sha256'], report['image_bytes'])
        # The caller publishes receipts only after its final whole-source check.
        return report
    except BaseException as error:
        (work / 'receipt.json').unlink(missing_ok=True)
        report.update(result='FAIL', error=str(error))
        construction.write_record(work / 'construction.json', report)
        raise
    finally:
        if mounted:
            run('umount', mountpoint)
        if device is not None:
            run('mdconfig', '-d', '-u', device[2:])


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'inventory', 'generated', 'construction-receipt', 'output',
                 'makefs', 'mdconfig', 'mount', 'umount'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--storage-layout-policy', type=Path)
    parser.add_argument('--verity-policy', type=Path)
    parser.add_argument('--boot-archive', action='store_true',
                        help='export the complete verified /boot namespace and observations')
    args = parser.parse_args()
    if args.verity_policy and not args.storage_layout_policy:
        parser.error('verity output requires an explicit storage layout')
    read = construction.generation.read_json
    policy_input = read(args.storage_layout_policy) if args.storage_layout_policy else None
    if policy_input is not None:
        validate_layout_version(policy_input[0])
    inventory, inventory_file_hash = read(args.inventory)
    generated, generated_file_hash = read(args.generated)
    receipt, receipt_file_hash = read(args.construction_receipt)
    root, observed = prepare(args.root, inventory, generated, receipt)
    tools = {name: getattr(args, name) for name in ('makefs', 'mdconfig', 'mount', 'umount')}
    bindings = {
        'inventory_file_sha256': inventory_file_hash,
        'generated_file_sha256': generated_file_hash,
        'construction_receipt_file_sha256': receipt_file_hash,
        'verified_inventory_sha256': receipt['inventory_sha256'],
        'verified_generated_sha256': receipt['generated_sha256']}
    if args.verity_policy:
        selected_verity, verity_hash = read(args.verity_policy)
        bindings['verity_policy'] = verity.policy(selected_verity)
        bindings['verity_policy_file_sha256'] = verity_hash
    if args.storage_layout_policy:
        policy, policy_hash = policy_input
        bindings['storage_layout_policy_file_sha256'] = policy_hash
        verified_inventory = construction.inventory_from_archives(inventory)
        materialize_layout(root, observed, verified_inventory, policy, tools, args.output, bindings, export_boot=args.boot_archive)
    else:
        materialize(root, observed, tools, args.output, export_boot=args.boot_archive, input_bindings=bindings)


if __name__ == '__main__':
    main()
