#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Build a release-specific hardware repository; never consume upstream kmods.

The build root must be a disposable, native-architecture 5BSD build jail with
pkg, the release source/build trees and a pinned ports tree. No host installation
or module loading is performed. See docs/book/src/develop/packaging.md.
"""
import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, text=True, **kwargs)


def manifest(path):
    return json.loads(run('tar', '-xOf', path, '+MANIFEST', capture_output=True).stdout)


def sha256(path):
    with open(path, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def kernel_hash(package):
    with tempfile.TemporaryDirectory() as tmp:
        entries = run('tar', '-tf', package, capture_output=True).stdout.splitlines()
        member = next((n for n in entries if n.lstrip('./') == 'boot/kernel/kernel'), None)
        if member is None:
            raise ValueError('kernel package has no kernel')
        run('tar', '-xf', package, '-C', tmp, member)
        return sha256(Path(tmp) / 'boot/kernel/kernel')


def closure(packages, seeds):
    selected = {}
    pending = list(seeds)
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        if name not in packages:
            raise ValueError('missing hardware dependency: ' + name)
        selected[name] = packages[name]
        pending.extend(packages[name][1].get('deps', {}))
    return selected


def create(pkg, output, meta, payload=None):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / 'root'
        root.mkdir()
        if meta['name'].startswith('5BSD-hardware-abi-'):
            identity = root / 'usr/share/5bsd/hardware-abi'
            identity.parent.mkdir(parents=True)
            identity.write_text(meta['annotations']['5BSD_kernel_sha256'] + '\n')
            meta['files'] = {'/usr/share/5bsd/hardware-abi': {
                'sum': sha256(identity), 'uname': 'root', 'gname': 'wheel',
                'perm': '0644'}}
        if payload:
            run('tar', '-xf', payload, '-C', root, '--exclude', '+*')
        m = Path(tmp) / 'manifest.json'
        m.write_text(json.dumps(meta))
        run(pkg, 'create', '-r', root, '-M', m, '-o', output)
    return output / (meta['name'] + '-' + meta['version'] + '.pkg')


def inventory(directory):
    result = {}
    for p in sorted(directory.glob('*.pkg')):
        m = manifest(p)
        if m['name'] in result:
            raise ValueError('duplicate package: ' + m['name'])
        result[m['name']] = (p, m)
    return result


def package_kind(meta):
    files = list(meta.get('files', {}))
    if any(re.search(r'\.ko(?:\.(?:gz|xz|zst))?$', f) for f in files):
        return 'module'
    if not files:
        return 'meta'
    # Only data-only firmware packages can be independent of the kernel.
    # Other support packages remain conservative, including executable helpers.
    data_paths = ('/boot/firmware/', '/usr/share/firmware/', '/usr/local/share/')
    if ('firmware' in meta['name'] and not meta.get('scripts') and
            not meta.get('deps') and all(f.startswith(data_paths) for f in files)):
        return 'firmware'
    return 'support'


def hardware_version(meta, epoch):
    if package_kind(meta) == 'firmware':
        return meta['version']
    version, _, old_epoch = meta['version'].partition(',')
    return version + ',' + str(max(epoch, int(old_epoch or '0') + 1))


def raw_gpu_firmware(pkg, output, package, meta):
    """Remove executable wrappers from locally built GPU firmware packages.

    Preserve the exact blob between the wrapper's binary start/end symbols.
    FreeBSD's firmware loader accepts this data under /boot/firmware using the
    same registered name. The extension broker must never execute a firmware
    wrapper merely to read device data.
    """
    if (not meta['name'].startswith('gpu-firmware-') or
            not meta.get('origin', '').startswith('graphics/gpu-firmware-') or
            package_kind(meta) != 'module'):
        return package, meta
    if meta.get('deps'):
        raise ValueError('GPU firmware wrapper has dependencies: ' + meta['name'])
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / 'root'
        root.mkdir()
        run('tar', '-xf', package, '-C', root, '--exclude', '+*')
        converted = dict(meta)
        converted['files'] = {}
        converted.pop('scripts', None)
        converted.pop('directories', None)
        converted.pop('flatsize', None)
        for name, attrs in meta['files'].items():
            if name.startswith('/usr/local/share/licenses/'):
                converted['files'][name] = attrs
                continue
            if not re.fullmatch(r'/boot/modules/[a-zA-Z0-9_]+\.ko', name):
                raise ValueError('unexpected GPU firmware payload: ' + name)
            module = root / name.lstrip('/')
            stem = module.stem
            symbols = run('nm', '-P', '-S', module, capture_output=True).stdout
            found = {}
            for line in symbols.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] in (
                        '_binary_' + stem + '_start', '_binary_' + stem + '_end'):
                    if parts[1] not in ('r', 'R') or parts[0] in found:
                        raise ValueError('invalid firmware symbols: ' + name)
                    found[parts[0]] = int(parts[2], 16)
            if len(found) != 2:
                raise ValueError('missing firmware symbols: ' + name)
            section = Path(tmp) / 'rodata'
            run('objcopy', '-O', 'binary', '-j', '.rodata', module, section)
            data = section.read_bytes()
            start, end = (found['_binary_' + stem + '_' + suffix]
                          for suffix in ('start', 'end'))
            if not 0 <= start < end <= len(data):
                raise ValueError('invalid firmware bounds: ' + name)
            target = root / 'boot/firmware' / stem
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data[start:end])
            converted['files']['/boot/firmware/' + stem] = {
                'sum': sha256(target), 'uname': 'root', 'gname': 'wheel',
                'perm': '0444'}
            module.unlink()
        if package_kind(converted) != 'firmware':
            raise ValueError('GPU conversion did not produce data-only firmware')
        m = Path(tmp) / 'manifest.json'
        m.write_text(json.dumps(converted))
        run(pkg, 'create', '-r', root, '-M', m, '-o', output)
        archive = output / (converted['name'] + '-' + converted['version'] + '.pkg')
        return archive, manifest(archive)


def seal(args):
    with tempfile.TemporaryDirectory() as tmp:
        return seal_with_firmware(args, Path(tmp))


def seal_with_firmware(args, firmware_output):
    """Called only after a clean source build, never on fetched module packages."""
    if args.epoch <= 0:
        raise ValueError('release epoch must be positive')
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('output must be empty: ' + str(out))
    out.mkdir(parents=True, exist_ok=True)
    km = manifest(args.kernel_package)
    if not re.fullmatch(r'5BSD-kernel-[a-z0-9]+', km['name']):
        raise ValueError('expected a 5BSD kernel package')
    digest = kernel_hash(args.kernel_package)
    token = '5BSD-hardware-abi-' + digest
    tokenmeta = dict(name=token, version='1', origin='5bsd-hardware/abi',
                     comment='Hardware ABI for ' + km['name'],
                     desc='Exact release kernel identity for hardware packages.',
                     maintainer='root@localhost', www='https://github.com/5BSD/5BSD',
                     prefix='/', abi=km['abi'], arch=km.get('arch', km['abi']),
                     annotations={'5BSD_kernel_sha256': digest})
    tokenfile = create(args.pkg, out, tokenmeta)
    dep = {token: {'origin': '5bsd-hardware/abi', 'version': '1'}}
    inputs = inventory(args.packages)
    selected = closure(inputs, args.seeds)
    selected = {name: raw_gpu_firmware(args.pkg, firmware_output, p, m)
                for name, (p, m) in selected.items()}
    records = {}
    for name, (p, original) in selected.items():
        m = dict(original)
        has_modules = package_kind(original) == 'module'
        if (has_modules and m['abi'] != km['abi']) or not fnmatch.fnmatchcase(km['abi'], m['abi']):
            raise ValueError('wrong architecture: ' + name)
        m['abi'], m['arch'] = km['abi'], km.get('arch', km['abi'])
        m['name'] = '5BSD-hw-' + name
        m['origin'] = '5bsd-hardware/' + name
        kind = package_kind(original)
        m['version'] = hardware_version(original, args.epoch)
        # Raw firmware is data, so it has no exact-kernel dependency. Kernel
        # modules, metapackages and support helpers remain release-coordinated.
        m['deps'] = {} if kind == 'firmware' else dict(dep)
        for d in original.get('deps', {}):
            # fwget selects firmware for detected GPUs separately. Keep the
            # complete collection on the ISO without installing every GPU's
            # firmware through the upstream driver metaport.
            if name == 'drm-kmod' and d == 'gpu-firmware-kmod':
                continue
            dm = selected[d][1]
            m['deps']['5BSD-hw-' + d] = {
                'origin': '5bsd-hardware/' + d,
                'version': hardware_version(dm, args.epoch)}
        m.setdefault('annotations', {}).update({
            '5BSD_hardware_original': name, '5BSD_hardware_kind': kind})
        if kind != 'firmware':
            m['annotations']['5BSD_kernel_sha256'] = digest
        else:
            m['annotations'].pop('5BSD_kernel_sha256', None)
        # An upstream package cannot silently replace our namespaced package.
        m.pop('conflicts', None)
        built = create(args.pkg, out, m, p)
        records[name] = {'package': m['name'], 'file': built.name,
                         'sha256': sha256(built), 'kind': m['annotations']['5BSD_hardware_kind']}
    km['vital'] = True
    km.setdefault('deps', {}).update(dep)
    km.setdefault('annotations', {})['5BSD_kernel_sha256'] = digest
    kernel = create(args.pkg, out, km, args.kernel_package)
    run(args.pkg, 'repo', out)
    (out / 'hardware.json').write_text(json.dumps({
        'format': 1, 'kernel_sha256': digest, 'kernel_package': kernel.name,
        'osversion': int(km.get('annotations', {}).get('FreeBSD_version', 0)),
        'kernel_package_sha256': sha256(kernel), 'abi': km['abi'],
        'epoch': args.epoch, 'token_sha256': sha256(tokenfile), 'packages': records}, indent=2) + '\n')


def build(args):
    root = args.root.resolve()
    if root == Path('/'):
        raise ValueError('a disposable build root is required')
    for value in (args.source, args.kernel_build, args.ports):
        if not re.fullmatch(r'/[a-zA-Z0-9_./+-]+', value) or '..' in Path(value).parts:
            raise ValueError('build paths must be absolute inside the build root')
    src = root / args.source.lstrip('/')
    obj = root / args.kernel_build.lstrip('/')
    if sha256(obj / 'kernel') != kernel_hash(args.kernel_package):
        raise ValueError('kernel build directory does not match the release kernel package')
    version = re.search(r'^#define\s+__FreeBSD_version\s+(\d+)',
                        (src / 'sys/sys/param.h').read_text(), re.M).group(1)
    packages = root / 'var/tmp/5bsd-hardware-packages'
    if packages.exists():
        raise ValueError('use a fresh build root; package staging already exists')
    # Refuse installed ports so package-recursive cannot reuse an upstream
    # hardware dependency. A freshly bootstrapped pkg is the only exception.
    installed = run('chroot', root, 'pkg', 'query', '%n', capture_output=True).stdout.splitlines()
    if any(not (n == 'pkg' or n.startswith('5BSD-')) for n in installed):
        raise ValueError('build root contains ports; start with clean 5BSD world and pkg')
    packages.mkdir(parents=True)
    # Ports builds sanitize the environment. Put these in the jail make.conf
    # so every recursive dependency build receives the same kernel settings.
    with (root / 'etc/make.conf').open('a') as conf:
        conf.write('\n# 5BSD release hardware build\nSRC_BASE=' + args.source +
                   '\nOSVERSION=' + version + '\nMAKE_ENV+= KERNBUILDDIR=' +
                   args.kernel_build + '\n')
    seeds = []
    for line in args.port_list.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        if not re.fullmatch(r'[a-z0-9+_.-]+/[a-zA-Z0-9+_.-]+(@[a-zA-Z0-9+_.-]+)?', line):
            raise ValueError('invalid port origin: ' + line)
        origin, _, flavor = line.partition('@')
        options = ['BATCH=yes', 'SRC_BASE=' + args.source, 'OSVERSION=' + version,
                   'PACKAGES=/var/tmp/5bsd-hardware-packages']
        if flavor:
            options.append('FLAVOR=' + flavor)
        command = ['chroot', root, 'env', 'KERNBUILDDIR=' + args.kernel_build,
                   'SYSDIR=' + args.source + '/sys', 'make', '-C', args.ports + '/' + origin]
        name = run(*command, *options, '-V', 'PKGBASE', capture_output=True).stdout.strip()
        if not name:
            raise ValueError('port has no PKGBASE: ' + origin)
        # clean-depends removes any old build products in a reused ports tree.
        run(*command, *options, 'clean', 'clean-depends')
        run(*command, *options, 'package-recursive')
        seeds.append(name)
    args.packages = packages / 'All'
    args.seeds = seeds
    # Fail if a fwget-selected package is missing from the release closure.
    available = closure(inventory(args.packages), seeds)
    for f in (src / 'usr.sbin/fwget').rglob('*'):
        if not f.is_file() or f.suffix in ('.8', '.md'):
            continue
        for group in re.findall(r'addpkg\s+"([^"]+)"', f.read_text(errors='replace')):
            for name in group.split():
                if '$' not in name and name not in available:
                    raise ValueError('fwget package missing from hardware profile: ' + name)
    seal(args)


def verify(directory, kernel=None):
    info = json.loads((directory / 'hardware.json').read_text())
    if info['format'] != 1:
        raise ValueError('unsupported hardware repository format')
    if kernel and kernel_hash(kernel) != info['kernel_sha256']:
        raise ValueError('hardware repository was built for a different kernel')
    for record in list(info['packages'].values()) + [{
            'file': info['kernel_package'], 'sha256': info['kernel_package_sha256']}]:
        name = record['file']
        if Path(name).name != name or sha256(directory / name) != record['sha256']:
            raise ValueError('hardware package checksum mismatch: ' + name)
    # Verify the ABI token too; pkg repo metadata authenticates archives when
    # the published repository is signed using the normal release signing key.
    token = directory / ('5BSD-hardware-abi-' + info['kernel_sha256'] + '-1.pkg')
    if sha256(token) != info['token_sha256']:
        raise ValueError('hardware identity checksum mismatch')
    tm = manifest(token)
    if tm.get('annotations', {}).get('5BSD_kernel_sha256') != info['kernel_sha256']:
        raise ValueError('invalid hardware ABI token')
    return info


def stage(args):
    info = verify(args.repository, args.kernel_package)
    if args.base_repository:
        verify(args.repository, args.base_repository / info['kernel_package'])
        base = args.base_repository.resolve()
        # Replace the same-version kernel with one depending on the ABI token.
        for name in (info['kernel_package'],
                     '5BSD-hardware-abi-' + info['kernel_sha256'] + '-1.pkg'):
            shutil.copy2(args.repository / name, base / name)
        run(args.pkg, 'repo', base)
    if args.media:
        if sha256(args.media / 'boot/kernel/kernel') != info['kernel_sha256']:
            raise ValueError('live media kernel does not match the hardware repository')
        dest = args.media / 'usr/5bsd-packages/hardware'
        shutil.copytree(args.repository, dest, dirs_exist_ok=True)
        # Install firmware on the live media too: Wi-Fi is needed before the
        # target exists. Do not install the kernel package into this root.
        repos = args.media / 'etc/pkg'
        repos.mkdir(parents=True, exist_ok=True)
        (repos / '5BSD-hardware.conf').write_text(
            '5BSD-hardware: { url: "file:///usr/5bsd-packages/hardware", enabled: yes }\n')
        with (args.media / 'METALOG').open('a') as metalog:
            metalog.write('./etc/pkg/5BSD-hardware.conf type=file uname=root gname=wheel mode=0644\n')
        live = [r['package'] for n, r in info['packages'].items()
                if n.startswith(('wifi-firmware-', 'gpu-firmware-')) or
                n in ('iwmbt-firmware', 'rtlbt-firmware')]
        if live:
            # --rootdir redirects payloads only. Explicitly isolate the package
            # database, cache and repository configuration from the build host.
            with tempfile.TemporaryDirectory() as config:
                Path(config, 'hardware.conf').write_text(
                    '5BSD-hardware: { url: "file://' + str(args.repository.resolve()) +
                    '", enabled: yes }\n')
                target_options = ['-o', 'ABI=' + info['abi']]
                if info.get('osversion'):
                    target_options += ['-o', 'OSVERSION=' + str(info['osversion'])]
                run(args.pkg, '-r', args.media, *target_options,
                    '-o', 'INSTALL_AS_USER=yes', '-o', 'METALOG=METALOG',
                    '-o', 'PKG_DBDIR=' + str(args.media / 'var/db/pkg'),
                    '-o', 'PKG_CACHEDIR=' + str(args.media / 'var/cache/pkg'),
                    '-o', 'REPOS_DIR=' + config,
                    'install', '-y', '-r', '5BSD-hardware', *live)

        # INSTALL_AS_USER suppresses pkg scripts, including kldxref. Build the
        # module index explicitly so the live kernel can locate firmware names.
        modules = args.media / 'boot/modules'
        if modules.exists() and any(modules.glob('*.ko')):
            run('kldxref', modules)
            hints = modules / 'linker.hints'
            if not hints.is_file():
                raise ValueError('live hardware modules have no linker.hints')
            with (args.media / 'METALOG').open('a') as metalog:
                metalog.write('./boot/modules/linker.hints type=file uname=root gname=wheel mode=0644\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    b = sub.add_parser('build')
    b.add_argument('--root', type=Path, required=True)
    b.add_argument('--source', default='/usr/src')
    b.add_argument('--kernel-build', required=True)
    b.add_argument('--ports', default='/usr/ports')
    b.add_argument('--port-list', type=Path, required=True)
    b.add_argument('--kernel-package', type=Path, required=True)
    b.add_argument('--output', type=Path, required=True)
    b.add_argument('--epoch', type=int, required=True)
    s = sub.add_parser('stage')
    s.add_argument('--repository', type=Path, required=True)
    s.add_argument('--kernel-package', type=Path)
    s.add_argument('--base-repository', type=Path)
    s.add_argument('--media', type=Path)
    for parser in (b, s):
        parser.add_argument('--pkg', default='/usr/local/sbin/pkg-static')
    args = p.parse_args()
    try:
        if args.action == 'build':
            build(args)
        else:
            stage(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as e:
        p.exit(1, str(e) + '\n')


if __name__ == '__main__':
    main()
