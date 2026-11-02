#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise explicit and empty directory ownership using real pkg/tar tools."""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile


def run(driver, pkg, tar, abi_file, osversion_header, output):
    spec = importlib.util.spec_from_file_location('pkg_create', driver)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output.mkdir(parents=True, exist_ok=False)
    results = []
    with tempfile.TemporaryDirectory(prefix='pkg-directories-', dir=output) as temporary:
        root = Path(temporary)
        archive = root / 'stage.tar'
        payload = b'declared package directory regression\n'
        directories = ['.', 'opt', 'opt/example', 'opt/example/empty']
        with tarfile.open(archive, 'w') as stream:
            for name in directories:
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE
                member.mode = 0o750 if name.endswith('/empty') else 0o755
                member.uname, member.gname = 'root', 'wheel'
                stream.addfile(member)
            member = tarfile.TarInfo('opt/example/data')
            member.mode, member.size = 0o444, len(payload)
            member.uname, member.gname = 'root', 'wheel'
            stream.addfile(member, io.BytesIO(payload))
        records = [dict(type='dir', destination='/' + name, owner='root', group='wheel',
                        mode='0750' if name.endswith('/empty') else '0755',
                        tags=['package=p'], flags='') for name in directories[2:]]
        records.append(dict(type='file', destination='/opt/example/data', owner='root',
                            group='wheel', mode='0444', tags=['package=p'], flags=''))
        policy = root / 'directories.json'
        manifest = root / 'manifest.json'
        manifest.write_text(json.dumps(dict(name='Test-p', version='1', origin='test/p',
            prefix='/', comment='Directory regression', desc='Directory regression',
            maintainer='test@example.invalid', www='https://example.invalid',
            licenselogic='single', licenses=['BSD2CLAUSE'])))
        base = dict(osversion_header=str(osversion_header), archive=str(archive),
                    packages={'p': records}, suffix_tags=[], directory_metadata=str(policy),
                    manifests={'p': str(manifest)}, abi_file=str(abi_file), pkg=str(pkg),
                    tar=str(tar), format='tar', threads=1, epoch=0)
        for case in ('explicit', 'file-only', 'layout-only-directories', 'wrong-owner', 'missing-directory', 'missing-payload'):
            request = copy.deepcopy(base)
            request['outputs'] = {'p': str(root / (case + '-outputs') / 'Test-p-1.pkg')}
            request['index'] = str(root / (case + '-index.json'))
            Path(request['outputs']['p']).parent.mkdir()
            declared_dirs = copy.deepcopy(records[:-1])
            expected_error = None
            if case == 'file-only':
                request['packages']['p'] = [records[-1]]
            elif case == 'layout-only-directories':
                declared_dirs.clear()
            elif case == 'wrong-owner':
                declared_dirs[0]['tags'] = ['package=q']
                expected_error = 'directory package ownership differs from layout'
            elif case == 'missing-directory':
                request['packages']['p'].append(dict(records[0], destination='/opt/not-in-archive'))
                expected_error = 'archive and package layout payload inventories differ'
            elif case == 'missing-payload':
                request['packages']['p'] = records[:-1]
                expected_error = 'archive and package layout payload inventories differ'
            policy.write_text(json.dumps(dict(format=1, directories=declared_dirs)))
            try:
                module.create(request)
            except ValueError as error:
                assert expected_error is not None and str(error) == expected_error, (case, str(error))
                results.append(dict(case=case, rejected=str(error)))
                continue
            assert expected_error is None, case
            package = Path(request['outputs']['p'])
            with tarfile.open(package) as stream:
                names = {m.name.lstrip('./'): m for m in stream.getmembers()}
                assert stream.extractfile(names['opt/example/data']).read() == payload
                metadata = json.load(stream.extractfile(names['+MANIFEST']))
                # Inspect pkg's persisted directory ownership, including empty directories.
                owned = metadata['directories']
                assert set(owned) == {'/opt', '/opt/example', '/opt/example/empty'}, owned
                assert owned['/opt/example/empty']['perm'] == '0750', owned
            results.append(dict(case=case, package_sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
                                directories=owned))
    (output / 'receipt.json').write_text(json.dumps(dict(status='passed', driver=str(driver),
        driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest(), results=results), indent=2) + '\n')
    print('Real pkg directory ownership, empty-directory mode and payload validation passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('driver', 'pkg', 'tar', 'abi-file', 'osversion-header', 'output'):
        parser.add_argument('--' + key, required=True, type=Path)
    args = parser.parse_args()
    run(args.driver, args.pkg, args.tar, args.abi_file, args.osversion_header, args.output)


if __name__ == '__main__':
    main()
