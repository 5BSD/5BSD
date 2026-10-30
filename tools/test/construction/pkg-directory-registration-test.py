#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Register real directory archives into a private DB; never install payloads."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('pkg', 'sqlite', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--abi', required=True)
    parser.add_argument('--osversion', type=int, required=True)
    args = parser.parse_args()
    work = args.work.absolute()
    if not work.is_relative_to('/usr/obj/usr/src') or args.osversion <= 0:
        parser.error('requires fresh work under /usr/obj/usr/src and positive OSVERSION')
    work.mkdir(mode=0o700)
    for name in ('repos', 'db', 'stage'):
        (work / name).mkdir()
    pkg, sqlite = args.pkg.resolve(strict=True), args.sqlite.resolve(strict=True)
    prefix = [str(pkg), '-C', '/dev/null', '-R', str(work / 'repos')]
    for setting in ['PKG_DBDIR=' + str(work / 'db'), 'PKG_CACHEDIR=' + str(work / 'cache'),
                    'ABI=' + args.abi, 'OSVERSION=' + str(args.osversion), 'INSTALL_AS_USER=yes',
                    'RUN_SCRIPTS=no', 'PKG_ENABLE_PLUGINS=no', 'PKG_TRIGGERS_ENABLE=no',
                    'SYSLOG=no', 'REPO_AUTOUPDATE=no']:
        prefix.extend(['-o', setting])
    env = {'PATH': '/bin:/usr/bin:/sbin:/usr/sbin', 'HOME': str(work), 'LC_ALL': 'C'}
    report = dict(result='RUNNING', scope='archive directory metadata and shared ownership registration',
                  pkg_sha256=hashlib.sha256(pkg.read_bytes()).hexdigest(), commands=[])

    def run(argv):
        command = list(map(str, argv))
        result = subprocess.run(command, cwd=work, env=env, capture_output=True,
                                text=True, timeout=60)
        report['commands'].append(dict(argv=command, exit=result.returncode,
                                       stdout=result.stdout, stderr=result.stderr))
        result.check_returncode()
        return result.stdout

    try:
        expected = []
        for name in ('directory-a', 'directory-b'):
            paths = ['/shared-directory', '/' + name]
            for path in paths:
                (work / 'stage' / path.lstrip('/')).mkdir(exist_ok=True)
            manifest = dict(name=name, origin='tests/' + name, version='1',
                comment='directory fixture', desc='directory fixture',
                maintainer='test@example.invalid', www='https://example.invalid',
                prefix='/', abi=args.abi)
            meta = work / (name + '.json'); meta.write_text(json.dumps(manifest))
            plist = work / (name + '.plist')
            plist.write_text(''.join('@dir(root,wheel,0750) ' + path + '\n' for path in paths))
            run(prefix + ['create', '-M', meta, '-p', plist, '-r', work / 'stage', '-o', work])
            archive = work / (name + '-1.pkg')
            raw = run(['/usr/bin/tar', '-xOf', archive, '+MANIFEST'])
            archived = json.loads(raw)
            if archived.get('files') or archived.get('scripts') or archived.get('lua_scripts'):
                raise ValueError('fixture must contain only directory payloads')
            archive_meta = work / (name + '-archive.json'); archive_meta.write_text(raw)
            run(prefix + ['register', '-t', '-M', archive_meta])
            expected.extend(dict(package=name, path=path, uname='root', gname='wheel',
                                 perm=0o750, fflags=0, removal=1) for path in paths)
        actual = json.loads(run([sqlite, '-readonly', '-json', work / 'db/local.sqlite',
            'SELECT p.name AS package,d.path,d.uname,d.gname,d.perm,d.fflags,pd.try AS removal '
            'FROM directories d JOIN pkg_directories pd ON pd.directory_id=d.id '
            'JOIN packages p ON p.id=pd.package_id ORDER BY p.name,d.path']))
        expected.sort(key=lambda row: (row['package'], row['path']))
        report.update(expected=expected, actual=actual)
        if actual != expected:
            raise AssertionError('registered directory metadata or ownership differs')
        report['result'] = 'PASS'
    except BaseException as error:
        report.update(result='FAIL', error=str(error))
        raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
