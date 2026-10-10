"""Export only test additions from a qualified fresh VM for BSDInstall testing.

Production programs, authentication files and kernel/modules are never copied.
The DTrace fixture is a copy of the installed program and is checked separately
against the installed image before its command link is changed in the test VM.
"""
import argparse
import hashlib
import json
import io
from pathlib import Path
import tarfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error('do not disable evidence assertions with Python -O')
    vm = args.vm.resolve(strict=True)
    result = json.loads((vm / 'software-result.json').read_text())
    build = json.loads((vm / 'build.json').read_text())
    assert result['result'] == 'PASS' and not result['forced'] and result['exit'] == 0
    assert build['stage'].startswith('fresh clean world/kernel installation')
    assert digest(vm / 'software-serial.log') == result['serial_sha256']
    assert digest(vm / 'build.json') == result['build_manifest_sha256']
    root = vm / 'root'
    replacements = json.loads((vm / 'replacement-files.json').read_text())
    names = []
    for name, record in replacements.items():
        path = Path(name)
        assert not path.is_absolute() and '..' not in path.parts
        allowed = (name.startswith(('Capabilities/System/Fixture-',
                                   'root/managed-fixtures/',
                                   'root/retired-package-fixtures/',
                                   'root/software-tests/')) or
                   (name.startswith('root/software-') and name.endswith('-guest.sh')) or
                   name == 'usr/bin/authority-session-check')
        if not allowed:
            continue
        assert digest(root / name) == record['sha256'], name
        names.append(name)
    names.append('usr/bin/policy-askpass')
    required = ['root/software-application-guest.sh', 'root/software-unix-guest.sh',
                'root/software-be-guest.sh', 'root/software-user-agent-guest.sh',
                'root/software-retired-package-guest.sh']
    assert all(name in names for name in required)
    output = args.out.resolve()
    output.mkdir(exist_ok=False)
    files = {}
    adaptations = {}
    archive = output / 'fixtures.tar'
    with tarfile.open(archive, 'w') as tar:
        for name in sorted(names):
            path = root / name
            assert path.is_file() and not path.is_symlink(), name
            item = tar.gettarinfo(str(path), arcname=name)
            item.uid = item.gid = 0
            item.uname = item.gname = 'root'
            item.mode = 0o555 if '/bin/' in name or name.endswith('.sh') or name.startswith('root/software-tests/') or name.endswith('pkg-static') else 0o644
            data = path.read_bytes()
            if name == 'root/software-reload-guest.sh':
                original = data
                # The installer fixture gives /tmp its own dataset. Keep
                # hard links and renames local regardless of /root layout.
                data = data.replace(b'/tmp/registered-control-image',
                                    b'/Capabilities/.registered-control-image')
                data = data.replace(b'/root/retired-reload-control.cap',
                                    b'/Capabilities/.retired-reload-control.cap')
                assert data != original
                adaptations[name] = {
                    'source_sha256': hashlib.sha256(original).hexdigest(),
                    'reason': 'keep hard-link and bundle rename on the capabilities filesystem; preserve vnode identity',
                }
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
            files[name] = hashlib.sha256(data).hexdigest()
    manifest = {
        'scope': 'private fixture additions only; not installed-system test evidence',
        'qualified_vm': str(vm),
        'vm_result_sha256': digest(vm / 'software-result.json'),
        'kernel_sha256': build['kernel_sha256'],
        'archive_sha256': digest(archive),
        'files': files,
        'installed_layout_adaptations': adaptations,
        'dtrace_sha256': digest(root / 'Capabilities/System/Fixture-dtrace.cap/Units/dtrace.unit/bin/dtrace'),
    }
    (output / 'fixtures.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(output)


if __name__ == '__main__':
    main()
