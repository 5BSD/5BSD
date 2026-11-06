#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Carry BSD installation flags through real unprivileged pkg creation."""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import shutil
from pathlib import Path
import tarfile
import tempfile


def run(driver, pkg, tar, abi_file, osversion_header, output):
    spec = importlib.util.spec_from_file_location('pkg_create', driver)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output.mkdir(parents=True, exist_ok=False)
    results = []
    with tempfile.TemporaryDirectory(prefix='pkg-flags-', dir=output) as temporary:
        root = Path(temporary)
        for case, file_flags, directory_flags, mismatch in [
            ('ordinary', '', '', False),
            ('system-immutable', 'schg', '', False),
            ('user-immutable', 'uchg', '', False),
            ('immutable-directory', '', 'uchg', False),
            ('file-mismatch', 'schg', '', True),
            ('directory-mismatch', '', 'uchg', True),
        ]:
            work = root / case
            work.mkdir()
            archive = work / 'stage.tar'
            payload = b'BSD file flags must survive package construction\n'
            records = []
            with tarfile.open(archive, 'w', format=tarfile.PAX_FORMAT) as stream:
                for name in ['.', 'opt', 'opt/example']:
                    member = tarfile.TarInfo(name)
                    member.type = tarfile.DIRTYPE
                    member.uname, member.gname, member.mode = 'root', 'wheel', 0o755
                    if name == 'opt/example' and directory_flags:
                        member.pax_headers['SCHILY.fflags'] = directory_flags
                    stream.addfile(member)
                    if name != '.':
                        records.append(dict(type='dir', destination='/' + name, owner='root',
                            group='wheel', mode='0755', tags=['package=p'],
                            flags=directory_flags if name == 'opt/example' else ''))
                member = tarfile.TarInfo('opt/example/data')
                member.uname, member.gname, member.mode, member.size = 'root', 'wheel', 0o444, len(payload)
                if file_flags:
                    member.pax_headers['SCHILY.fflags'] = file_flags
                stream.addfile(member, io.BytesIO(payload))
            records.append(dict(type='file', destination='/opt/example/data', owner='root', group='wheel',
                mode='0444', tags=['package=p'], flags=file_flags))
            declared = copy.deepcopy(records)
            if mismatch:
                declared[-1 if file_flags else -2]['flags'] = ''
            policy = work / 'directories.json'
            policy.write_text(json.dumps(dict(format=1, directories=declared[:-1])))
            manifest = work / 'manifest.ucl'
            manifest.write_text(json.dumps(dict(name='Test-flags', version='1', origin='test/flags', prefix='/',
                comment='BSD flag preservation', desc='BSD flag preservation', maintainer='test@example.invalid',
                www='https://example.invalid', licenselogic='single', licenses=['BSD2CLAUSE'])))
            package = work / 'packages/Test-flags-1.pkg'
            package.parent.mkdir()
            request = dict(osversion_header=str(osversion_header), archive=str(archive), packages={'p': declared},
                suffix_tags=[], directory_metadata=str(policy), manifests={'p': str(manifest)},
                abi_file=str(abi_file), pkg=str(pkg), tar=str(tar), format='tar', threads=1, epoch=0,
                outputs={'p': str(package)}, index=str(package.parent / 'index.json'))
            try:
                module.create(request)
            except ValueError as error:
                assert mismatch and str(error) == 'archive file flags differ from package layout', (case, str(error))
                assert not package.exists(), case
                results.append(dict(case=case, rejected=str(error)))
                continue
            assert not mismatch, case
            with tarfile.open(package) as stream:
                members = {'/' + m.name.lstrip('./').rstrip('/'): m for m in stream.getmembers()}
                assert stream.extractfile(members['/opt/example/data']).read() == payload
                for path, flags in [('/opt/example/data', file_flags), ('/opt/example', directory_flags)]:
                    actual = members[path].pax_headers.get('SCHILY.fflags', '')
                    assert actual == flags, (case, path, flags, actual)
                metadata = json.load(stream.extractfile(members['/+MANIFEST']))
                assert set(metadata['files']) == {'/opt/example/data'}
            # Preserve the actual packages and input policy for independent inspection.
            (work / 'layout.json').write_text(json.dumps(dict(packages={'p': declared}, suffix_tags=[])))
            shutil.copytree(work, output / case)
            results.append(dict(case=case, flags=file_flags, directory_flags=directory_flags,
                package_sha256=hashlib.sha256(package.read_bytes()).hexdigest()))
    (output / 'receipt.json').write_text(json.dumps(dict(status='passed', driver=str(driver),
        driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest(), results=results), indent=2) + '\n')
    print('Real pkg file/directory flag preservation and mismatch rejection passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('driver', 'pkg', 'tar', 'abi-file', 'osversion-header', 'output'):
        parser.add_argument('--' + key, required=True, type=Path)
    args = parser.parse_args()
    run(args.driver, args.pkg, args.tar, args.abi_file, args.osversion_header, args.output)


if __name__ == '__main__':
    main()
