"""Create disposable automated qualification media from the fresh release tree.

This copies release staging and adds only installer automation. Public media
must be retained separately; this ISO creates test accounts and is not public.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shlex

FIXTURES = Path(__file__).resolve().parent / 'installer-fixtures'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-root', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--qualified-vm', required=True, type=Path)
    args = parser.parse_args()
    if not __debug__:
        parser.error('do not disable evidence assertions with Python -O')
    source = args.source.resolve(strict=True)
    release = args.release_root.resolve(strict=True)
    work = args.build.resolve(strict=True)
    assert (work / 'phase').read_text().strip() == 'CLEAN_WORLD_KERNEL_BUILT'
    assert (work / 'stage-phase').read_text().strip() == 'CLEAN_KERNEL_VM_PASS'
    assert subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD']).decode().strip() == (work / 'source-head').read_text().strip(), 'source revision mismatch'
    assert subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain']) == b'', 'source changed after clean build'

    assert (release / 'METALOG').is_file()
    fresh = args.root.resolve(strict=True)
    expected = digest(fresh / 'boot/kernel/kernel')
    assert digest(release / 'boot/kernel/kernel') == expected, 'release kernel differs from clean world'
    vm = args.qualified_vm.resolve(strict=True)
    result = json.loads((vm / 'software-result.json').read_text())
    build = json.loads((vm / 'build.json').read_text())
    assert result['result'] == 'PASS' and not result['forced']
    assert build['kernel_sha256'] == expected
    assert build['stage'].startswith('fresh clean world/kernel installation')
    output = args.out.resolve()
    output.mkdir(exist_ok=False)
    root = output / 'media'
    subprocess.run(['cp', '-a', str(release), str(root)], check=True)
    records = {}
    for line in (root / 'METALOG').read_text().splitlines():
        if line and not line.startswith('#'):
            records[line.split()[0]] = line

    def put(name, data, mode=0o644):
        path = root / name
        if path.exists() or path.is_symlink():
            path.unlink()
        path.write_bytes(data)
        path.chmod(mode)
        records['./' + name] = f'./{name} type=file uid=0 gid=0 mode={mode:04o}'

    # Bind actual installed executables to the qualified clean installation,
    # rather than accepting a matching kernel with stale userland packages.
    identity_paths = [
        'boot/kernel/kernel', 'sbin/capsule', 'usr/libexec/switchboard',
        'usr/lib/libservice.so.1', 'usr/lib/libchannel.so.1',
        'usr/lib/libcapbundle.so.1', 'libexec/ld-elf.so.1',
        'usr/bin/login', 'usr/bin/su', 'usr/sbin/sshd',
        'usr/libexec/sshd-session', 'usr/libexec/sshd-auth',
        'Capabilities/System/SwitchBoardControl.cap/Units/switchboardctl.unit/bin/switchboardctl',
        'Capabilities/System/CapsuleControl.cap/Units/capsulectl.unit/bin/capsulectl',
    ]
    # Check every shipped chapter, including renamed chapters and redirects.
    # The older file list installed anointments.md but omitted attributes.md.
    book = source / 'docs/book/src'
    for chapter in sorted(book.rglob('*.md')):
        name = 'usr/share/doc/5bsd/' + chapter.relative_to(book).as_posix()
        assert digest(fresh / name) == digest(chapter), 'staged book differs from source: ' + name
        identity_paths.append(name)
    installed_identity = {name: digest(fresh / name) for name in identity_paths}
    config = (FIXTURES / 'bsdinstall-software.conf').read_text()
    marker = "printf '%s\\n' SOFTWARE_BSDINSTALL_SETUP_PASS"
    assert marker in config
    checks = ''.join('[ "$(sha256 -q ' + shlex.quote('/' + name) +
                     ')" = ' + shlex.quote(value) + ' ]\n'
                     for name, value in installed_identity.items())
    config = config.replace(marker, checks + marker)
    put('etc/installerconfig', config.encode())
    put('etc/rc.local', (FIXTURES / 'software-installer-rc.local').read_bytes(), 0o555)
    put('etc/ttys', b'ttyu0 \"/usr/libexec/getty 3wire\" vt100 on secure\n')
    loader = (root / 'boot/loader.conf').read_text()
    loader = '\n'.join(line for line in loader.splitlines()
                       if not line.startswith(('console=', 'autoboot_delay=', 'vfs.root.mountfrom=')))
    loader += '\nconsole="comconsole"\nautoboot_delay="1"\n'
    loader += 'vfs.root.mountfrom="cd9660:/dev/iso9660/5BSD_SOFTWARE_TEST"\n'
    put('boot/loader.conf', loader.encode())
    (root / 'METALOG').write_text('#mtree 2.0\n' + '\n'.join(records.values()) + '\n')
    iso = output / 'software-installer-test.iso'
    with (output / 'mkiso.log').open('w') as log:
        subprocess.run(['sh', str(source / 'release/amd64/mkisoimages.sh'),
                        '-b', '5BSD_SOFTWARE_TEST', str(iso), './METALOG'],
                       cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    manifest = {'scope': 'private installer automation media, not a public release',
                'iso': str(iso), 'iso_sha256': digest(iso),
                'release_root': str(release), 'clean_build': str(work), 'source_commit': (work / 'source-head').read_text().strip(),
                'vm_result_sha256': digest(vm / 'software-result.json'),
                'kernel_sha256': expected, 'vm_evidence': str(vm),
                'installed_file_sha256': installed_identity,
                'fixtures': {name: digest(FIXTURES / name) for name in
                             ('bsdinstall-software.conf', 'software-installer-rc.local')}}
    (output / 'media.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest))


if __name__ == '__main__':
    main()
