#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Assemble explicit native iconv artifacts for the maintained disposable VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import re
import subprocess
import stat
import tarfile
import runtime_profile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(name):
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(p in ('', '.', '..') for p in path.parts):
        raise ValueError('normalized relative path required: ' + name)
    if str(path) != name:
        raise ValueError('noncanonical path: ' + name)
    return path


def put(source, destination, mode):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise ValueError('duplicate fixture destination: ' + str(destination))
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def unpack(archive, root):
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        for member in members:
            name = member.name.removeprefix('./').rstrip('/')
            if not name or name == '.':
                continue
            path = root / relative(name)
            if any(parent.is_symlink() for parent in path.parents if parent != root):
                raise ValueError('archive traverses symlink: ' + name)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(member.mode)
            elif member.isfile():
                if path.exists() or path.is_symlink():
                    raise ValueError('archive destination collision: ' + name)
                path.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(member) as source, path.open('xb') as target:
                    shutil.copyfileobj(source, target)
                path.chmod(member.mode)
            elif member.issym():
                target = PurePosixPath(member.linkname)
                if target.is_absolute():
                    raise ValueError('absolute fixture symlink: ' + name)
                resolved = (path.parent / member.linkname).resolve()
                if not resolved.is_relative_to(root):
                    raise ValueError('escaping fixture symlink: ' + name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(member.linkname)
            else:
                raise ValueError('unsupported archive object: ' + name)


def copy_boot(source, destination):
    source = source.resolve(strict=True)
    exclude = shutil.ignore_patterns('kernel*', 'modules*', 'dtb', 'firmware', 'zfs',
                                     'loader.conf', 'loader.conf.local', 'loader.conf.d',
                                     'nextboot.conf', 'entropy')
    # These are host-specific root entries; defaults/loader.conf is required.
    shutil.copytree(source, destination,
                    ignore=lambda directory, names: exclude(directory, names)
                    if Path(directory) == source else [])


def inventory(root):
    records = {}
    for path in sorted(root.rglob('*')):
        name = str(path.relative_to(root))
        info = path.lstat()
        if path.is_symlink():
            if not path.resolve(strict=True).is_relative_to(root):
                raise ValueError('fixture symlink escapes root: ' + name)
            records[name] = {'type': 'symlink', 'target': os.readlink(path)}
        elif path.is_file():
            records[name] = {'type': 'file', 'sha256': digest(path), 'size': info.st_size,
                             'mode': format(stat.S_IMODE(info.st_mode), '04o')}
        elif path.is_dir():
            records[name] = {'type': 'dir', 'mode': format(stat.S_IMODE(info.st_mode), '04o')}
        else:
            raise ValueError('unexpected fixture object: ' + name)
    return records


def native_elf_closure(root, readelf):
    """Require the declared inner runtime to resolve without host loader state."""
    records = {}
    for source in sorted(root.rglob('*')):
        if source.is_relative_to(root/'usr/lib/debug') or not source.is_file() or source.is_symlink():
            continue
        with source.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
        dynamic = subprocess.check_output([readelf, '-d', str(source)], text=True)
        if re.search(r'\((?:RPATH|RUNPATH)\)', dynamic):
            raise ValueError('native fixture runtime must not depend on embedded library search paths: '+str(source))
        dependencies = re.findall(r'\(NEEDED\).*?\[([^]]+)\]', dynamic)
        for needed in dependencies:
            if '/' in needed or not any((root/d/needed).is_file() for d in ['lib','usr/lib']):
                raise ValueError('unresolved declared native dependency: '+str(source)+': '+needed)
        headers = subprocess.check_output([readelf, '-l', str(source)], text=True)
        for interpreter in re.findall(r'Requesting program interpreter: ([^\]]+)', headers):
            if '..' in PurePosixPath(interpreter).parts or not (root/interpreter.lstrip('/')).is_file():
                raise ValueError('missing declared native interpreter: '+interpreter)
        records[str(source.relative_to(root))] = dependencies
    return records


def kernel_modules(entries, kernel):
    """Bind explicit execution-kernel bootstrap modules to its selected build."""
    if not isinstance(entries, dict):
        raise ValueError('explicit kernel module map required')
    kernel = kernel.resolve(strict=True)
    kernel_hash = digest(kernel)
    result = {}
    for name, entry in entries.items():
        if (not re.fullmatch(r'[A-Za-z0-9_+.-]+\.ko', name) or
                not isinstance(entry, dict) or set(entry) != {'path', 'sha256', 'kernel_sha256'}):
            raise ValueError('explicit module basename/path/hash/kernel binding required')
        source = Path(entry['path']).resolve(strict=True)
        if not source.is_file() or not source.is_relative_to(kernel.parent / 'modules'):
            raise ValueError('bootstrap module must come from selected kernel build modules')
        if entry['kernel_sha256'] != kernel_hash or entry['sha256'] != digest(source):
            raise ValueError('bootstrap module or selected kernel hash mismatch')
        result[name] = dict(entry, path=str(source), scope='execution kernel bootstrap; not native Bazel module qualification')
    return result


def validate_checker_inputs(value):
    if not isinstance(value, dict):
        raise ValueError('checker_inputs must map normalized relative names to explicit files')
    paths = []
    for name, source in value.items():
        if not isinstance(name, str) or any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise ValueError('checker input name must be a printable relative string')
        path = relative(name)
        if any(path == p or path in p.parents or p in path.parents for p in paths):
            raise ValueError('checker input path collision')
        paths.append(path)
        if not isinstance(source, str) or not Path(source).is_absolute() or not Path(source).is_file():
            raise ValueError('checker input requires an existing absolute source file')
    return dict(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    qualification = args.qualification.resolve(strict=True)
    output = args.output.resolve()
    if not output.is_relative_to('/usr/obj') or output.exists():
        parser.error('a new output directory under /usr/obj is required')
    receipt_path = qualification / 'receipt.json'
    receipt = json.loads(receipt_path.read_text())
    if receipt['status'] != 'passed':
        raise ValueError('completed native qualification required')
    manifest_path = qualification / receipt['artifacts']['manifest']
    if digest(manifest_path) != receipt['artifacts']['sha256']:
        raise ValueError('native artifact manifest mismatch')
    manifest = json.loads(manifest_path.read_text())
    plan = json.loads(args.plan.read_text())
    required = {'format', 'archives', 'files', 'kernel', 'boot_directory', 'guest_driver', 'checker', 'daemon_fixtures', 'readelf'}
    if not required <= set(plan) or set(plan) - required - {'kernel_modules', 'checker_profile', 'checker_inputs', 'guest_driver_destination'} or type(plan['format']) is not int or plan['format'] != 1:
        raise ValueError('versioned explicit fixture plan required')
    profile = runtime_profile.validate(plan.get('checker_profile', {'timeout_scale': 1}))
    driver_destination = relative(plan.get('guest_driver_destination', 'tests/iconv_vm_driver'))
    checker_inputs = validate_checker_inputs(plan.get('checker_inputs', {}))
    selected = {}
    for target in manifest['targets']:
        label = target['target']['label']
        if label in selected:
            raise ValueError('ambiguous target configuration: ' + label)
        selected[label] = target['outputs']

    bindings = {}
    def artifact(label, suffix=None):
        outputs = [entry for entry in selected[label] if suffix is None or entry['name'].endswith(suffix)]
        if len(outputs) != 1:
            raise ValueError('one selected artifact required: ' + label)
        entry = outputs[0]
        source = qualification / 'artifacts' / relative(entry['file'])
        if not source.resolve(strict=True).is_relative_to(qualification / 'artifacts') or digest(source) != entry['sha256']:
            raise ValueError('native artifact content mismatch: ' + label)
        bindings[label + (suffix or '')] = {'path': str(source), 'sha256': entry['sha256']}
        return source

    # Validate selected artifacts before creating a partial fixture.
    for label in plan['archives']:
        artifact(label, '/install_archive.tar')
    for entry in plan['files']:
        if set(entry) != {'target', 'destination', 'mode'}:
            raise ValueError('explicit target/destination/mode required')
        relative(entry['destination'])
        artifact(entry['target'])
    driver = artifact(plan['guest_driver'])
    sdk = Path(receipt['sdk_repository']).resolve(strict=True) / 'toolchain'
    bootstrap_inputs = [sdk / 'bin/extra_python', sdk / 'execution-runtime/libexec/ld-elf.so.1',
                        Path(plan['kernel']), Path(plan['checker']), Path(plan['readelf']),
                        Path(__file__).with_name('runtime_profile.py')]
    bootstrap_inputs.extend(Path(source) for source in checker_inputs.values())
    for source in bootstrap_inputs:
        if not source.is_file():
            raise ValueError('missing explicit bootstrap input: ' + str(source))
    for name, source in plan['daemon_fixtures'].items():
        relative(name)
        bootstrap_inputs.append(Path(source))
    modules = kernel_modules(plan.get('kernel_modules', {}), Path(plan['kernel']))
    bootstrap_inputs.extend(Path(entry['path']) for entry in modules.values())
    before = {str(path): digest(path) for path in bootstrap_inputs}
    output.mkdir(mode=0o700, parents=True)
    extra = output / 'extra-root'
    fixture = extra / 'fixture'
    fixture.mkdir(parents=True)
    for label in plan['archives']:
        unpack(artifact(label, '/install_archive.tar'), fixture)
    for entry in plan['files']:
        put(artifact(entry['target']), fixture / relative(entry['destination']), int(entry['mode'], 8))
    put(sdk / 'execution-runtime/libexec/ld-elf.so.1', fixture / 'libexec/ld-elf.so.1', 0o555)
    (fixture / 'dev').mkdir(exist_ok=True)
    (fixture / 'tmp').mkdir(exist_ok=True)
    (fixture / 'tmp').chmod(0o1777)
    for name, entry in modules.items():
        put(Path(entry['path']), fixture / 'boot/kernel' / name, 0o555)
    native_dependencies = native_elf_closure(fixture, plan['readelf'])
    files = {str(path.relative_to(fixture)): digest(path) for path in fixture.rglob('*') if path.is_file()}
    runtime = extra / 'runtime'
    runtime.mkdir()
    (runtime / 'checker-profile.json').write_text(json.dumps(profile, sort_keys=True) + '\n')
    (runtime / 'checker-profile.json').chmod(0o444)
    put(Path(__file__).with_name('runtime_profile.py'), runtime / 'runtime_profile.py', 0o444)
    for name, source in checker_inputs.items():
        put(Path(source), runtime / 'checker-inputs' / relative(name), 0o444)
    (runtime / 'fixture-manifest.json').write_text(json.dumps({'format': 1, 'files': files}, indent=2) + '\n')
    # The bootstrap interpreter runtime is separate from the native test root.
    shutil.copytree(sdk / 'execution-runtime', extra, dirs_exist_ok=True)
    # Physical SDK filenames may differ from DT_SONAME (e.g. libintl.so.8.4.6).
    # Resolve aliases only from declared SDK objects, never from host ldconfig.
    aliases = runtime / 'python-libs'
    aliases.mkdir()
    sonames = {}
    for source in sorted((sdk / 'execution-runtime').rglob('*')):
        if not source.is_file() or source.open('rb').read(4) != b'\x7fELF':
            continue
        text = subprocess.check_output([plan['readelf'], '-d', str(source)], text=True)
        match = re.search(r'\(SONAME\).*?\[([^]]+)\]', text)
        if not match:
            continue
        name = match.group(1)
        if '/' in name or name in ('.', '..'):
            raise ValueError('unsupported SDK SONAME: ' + name)
        if name in sonames:
            if sonames[name]['sha256'] != digest(source):
                raise ValueError('conflicting SDK runtime SONAME: ' + name)
            continue
        installed = extra / source.relative_to(sdk / 'execution-runtime')
        (aliases / name).symlink_to(os.path.relpath(installed, aliases))
        sonames[name] = {'source': str(source), 'sha256': digest(source)}
    bootstrap_elf_inputs = [sdk / 'bin/extra_python'] + [p for p in (sdk / 'python-home').rglob('*')
        if p.is_file() and p.open('rb').read(4) == b'\x7fELF'] + [Path(v['source']) for v in sonames.values()]
    for source in bootstrap_elf_inputs:
        text = subprocess.check_output([plan['readelf'], '-d', str(source)], text=True)
        for needed in re.findall(r'\(NEEDED\).*?\[([^]]+)\]', text):
            if needed not in sonames:
                raise ValueError('unresolved declared bootstrap dependency: ' + str(source) + ': ' + needed)
    shutil.copytree(sdk / 'python-home', runtime / 'python-home')
    put(sdk / 'bin/extra_python', runtime / 'python', 0o555)
    put(Path(plan['checker']), runtime / Path(plan['checker']).name, 0o444)
    chroot = next(entry for entry in plan['files'] if entry['destination'] == 'usr/sbin/chroot')
    put(artifact(chroot['target']), extra / 'usr/sbin/chroot', 0o555)
    # Stage only boot inputs; the VM harness independently verifies the kernel.
    boot_root = output / 'boot-root'
    copy_boot(Path(plan['boot_directory']), boot_root / 'boot')
    put(Path(plan['kernel']), boot_root / 'boot/kernel/kernel', 0o555)
    fixture_objtop = output / 'fixture-objtop'
    put(driver, fixture_objtop / driver_destination, 0o555)
    for name, source in plan['daemon_fixtures'].items():
        put(Path(source), fixture_objtop / relative(name), 0o555)
    after = {str(path): digest(Path(path)) for path in before}
    if before != after:
        raise ValueError('bootstrap input changed during preparation')
    records = inventory(extra)
    report = {'format': 1, 'scope': 'explicit native fixture plus separately identified SDK Python/loader bootstrap',
              'qualification_receipt': {'path': str(receipt_path), 'sha256': digest(receipt_path)},
              'plan': {'path': str(args.plan.resolve()), 'sha256': digest(args.plan)},
              'implementation_sha256': digest(Path(__file__)), 'guest_driver_destination': str(driver_destination), 'checker_profile': profile,
              'checker_profile_scope': 'explicit checker deadline input; wrapper and VM limits are separate', 'artifact_bindings': bindings,
              'bootstrap_inputs': before, 'kernel_modules': modules, 'native_elf_dependencies': native_dependencies, 'extra_root': str(extra), 'fixture_objtop': str(fixture_objtop),
              'boot_root': str(boot_root), 'boot_files': inventory(boot_root),
              'sdk_repository': str(sdk.parent), 'bootstrap_sonames': sonames, 'files': records, 'payload_bytes': sum(r.get('size', 0) for r in records.values()),
              'runtime_qualified': False, 'host_installed': False}
    (output / 'fixture.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'fixture': str(output / 'fixture.json'), 'payload_bytes': report['payload_bytes'], 'runtime_qualified': False}))


if __name__ == '__main__':
    main()
