#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check ports license directory declarations and real pkg manifest metadata.

This does not build the selected ports or authenticate a release.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def run(command):
    return subprocess.check_output(list(map(str, command)), text=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ports', type=Path, required=True)
    p.add_argument('--pkg', type=Path, required=True)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--osversion', type=int, required=True)
    p.add_argument('--origin', action='append', required=True)
    p.add_argument('--prefix', action='append', required=True)
    a = p.parse_args()
    ports, pkg = a.ports.resolve(strict=True), a.pkg.resolve(strict=True)
    a.work.mkdir(parents=False, exist_ok=False)
    report = {'scope': 'ports license declaration and pkg metadata', 'result': 'RUNNING',
              'ports_built': False, 'cases': [], 'files_sha256': {}}
    sources = [ports / 'Mk/bsd.licenses.mk', ports / 'Mk/bsd.port.mk', pkg]
    try:
        abi = run([pkg, '-C', '/dev/null', 'config', 'ABI']).strip()
        for origin in a.origin:
            relative, separator, flavor = origin.partition('@')
            directory = (ports / relative).resolve(strict=True)
            if not directory.is_relative_to(ports) or not (directory / 'Makefile').is_file():
                raise ValueError('invalid port origin')
            sources.append(directory / 'Makefile')
            for prefix in a.prefix:
                if not prefix.startswith('/') or '..' in Path(prefix).parts:
                    raise ValueError('absolute prefix required')
                command = ['make', '-C', str(directory), 'OSVERSION=' + str(a.osversion),
                           'PREFIX=' + prefix, 'BATCH=yes']
                if separator:
                    command.append('FLAVOR=' + flavor)
                packages = run(command + ['-V', '${_PKGS}']).split()
                primary = run(command + ['-V', '${PKGBASE}']).strip()
                for name in packages:
                    suffix = '' if name == primary else run(command + ['-V', '${_SP.' + name + '}']).strip()
                    if name != primary and not suffix:
                        raise ValueError('subpackage suffix missing')
                    expected = run(command + ['-V', '${_LICENSE_DIR.' + name + '}']).strip()
                    dirs = run(command + ['-V', '${PLIST_DIRS' + suffix + '}']).split()
                    parents = [str(Path(expected).parent), expected]
                    if not expected or not set(parents) <= set(dirs):
                        raise ValueError('license directory not declared: ' + name + ': ' + expected)
                    disabled = run(command + ['NO_LICENSES_INSTALL=yes', '-V', '${PLIST_DIRS' + suffix + '}']).split()
                    if set(parents) & set(disabled):
                        raise ValueError('disabled license install still declares directory')
                    case = a.work / str(len(report['cases'])); case.mkdir()
                    root, meta, output = (case / n for n in ('root', 'meta', 'packages'))
                    for target in (root, meta, output): target.mkdir()
                    license_dir = root / expected.lstrip('/')
                    license_dir.mkdir(parents=True); license_dir.chmod(0o755)
                    (license_dir / 'LICENSE').write_text('directory metadata fixture\n')
                    manifest = dict(name='license-directory-fixture', version='1',
                        origin='tests/license-directory', abi=abi, prefix=prefix,
                        comment='test', desc='test', maintainer='test@example.invalid',
                        www='https://example.invalid')
                    (meta / '+MANIFEST').write_text(json.dumps(manifest))
                    plist = case / 'plist'
                    plist.write_text(expected + '/LICENSE\n' +
                                     ''.join('@dir ' + name + '\n' for name in parents))
                    run([pkg, '-C', '/dev/null', 'create', '-r', root, '-m', meta,
                         '-p', plist, '-o', output])
                    archive = output / 'license-directory-fixture-1.pkg'
                    actual = json.loads(run(['tar', '-xOf', archive, '+MANIFEST']))
                    metadata = {name: actual.get('directories', {}).get(name) for name in parents}
                    if any(value != {'uname': 'root', 'gname': 'wheel', 'perm': '0755'}
                           for value in metadata.values()):
                        raise ValueError('packaged directory metadata differs: ' + repr(metadata))
                    report['cases'].append(dict(origin=origin, package=name, prefix=prefix,
                        directory=expected, metadata=metadata, command=command,
                        archive_sha256=hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()))
        if not report['cases']: raise ValueError('no package cases selected')
        report['result'] = 'PASS'
    except BaseException as error:
        report.update(result='FAIL', error=str(error))
        raise
    finally:
        report['files_sha256'] = {str(f): hashlib.file_digest(f.open('rb'), 'sha256').hexdigest()
                                  for f in sources}
        (a.work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: ' + str(len(report['cases'])) + ' license directory cases')


if __name__ == '__main__':
    main()
