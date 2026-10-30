#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check config pathname round trips through real archives and registration.

No archive is installed. Registration uses a private database with hooks disabled.
This does not qualify configuration baseline construction or merge behavior.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pkg', type=Path, required=True)
    parser.add_argument('--sqlite', type=Path, required=True)
    parser.add_argument('--abi', required=True)
    parser.add_argument('--osversion', type=int, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.absolute()
    if not work.is_relative_to('/usr/obj/usr/src') or args.osversion <= 0:
        parser.error('new work directory under /usr/obj/usr/src and positive OSVERSION required')
    pkg, sqlite = args.pkg.resolve(strict=True), args.sqlite.resolve(strict=True)
    work.mkdir(mode=0o700)
    for name in ('repos', 'db', 'stage'):
        (work / name).mkdir()
    report = {'result': 'RUNNING', 'scope': 'config pathname archive and registration round trip',
              'pkg_sha256': hashlib.sha256(pkg.read_bytes()).hexdigest(), 'commands': []}
    env = {'PATH': '/bin:/usr/bin:/sbin:/usr/sbin', 'HOME': str(work), 'LC_ALL': 'C'}
    prefix = [str(pkg), '-C', '/dev/null', '-R', str(work / 'repos')]
    for setting in ['PKG_DBDIR=' + str(work / 'db'), 'PKG_CACHEDIR=' + str(work / 'cache'),
                    'ABI=' + args.abi, 'OSVERSION=' + str(args.osversion), 'INSTALL_AS_USER=yes',
                    'RUN_SCRIPTS=no', 'PKG_ENABLE_PLUGINS=no', 'PKG_TRIGGERS_ENABLE=no',
                    'SYSLOG=no', 'REPO_AUTOUPDATE=no']:
        prefix.extend(['-o', setting])

    def run(argv):
        r = subprocess.run(list(map(str, argv)), cwd=work, env=env,
                           capture_output=True, text=True, timeout=60)
        report['commands'].append({'argv': list(map(str, argv)), 'exit': r.returncode,
                                   'stdout': r.stdout, 'stderr': r.stderr})
        r.check_returncode()
        return r.stdout

    try:
        paths = ['/plain.conf', '/with space.conf', '/literal%20.conf', '/plus+.conf', '/caf\u00e9.conf']
        for path in paths:
            (work / 'stage' / path.lstrip('/')).write_text('original baseline\n')
        manifest = {'name': 'config-path-fixture', 'origin': 'tests/config-path-fixture',
                    'version': '1', 'comment': 'config path fixture', 'desc': 'config path fixture',
                    'maintainer': 'test@example.invalid', 'www': 'https://example.invalid',
                    'abi': args.abi, 'prefix': '/'}
        meta = work / 'manifest.json'; meta.write_text(json.dumps(manifest))
        plist = work / 'plist'; plist.write_text(''.join('@config ' + p + '\n' for p in paths))
        run(prefix + ['create', '-M', meta, '-p', plist, '-r', work / 'stage', '-o', work])
        archive = work / 'config-path-fixture-1.pkg'
        raw = run(['/usr/bin/tar', '-xOf', archive, '+MANIFEST'])
        archived = json.loads(raw)
        expected = sorted(['/plain.conf', '/with space.conf', '/literal%2520.conf',
                           '/plus+.conf', '/caf%c3%a9.conf'])
        assert sorted(archived['config']) == expected, 'archive config encoding mismatch'
        exported = json.loads(run(prefix + ['info', '-F', archive, '--raw', '--raw-format', 'json']))
        if isinstance(exported, list):
            assert len(exported) == 1
            exported = exported[0]
        assert sorted(exported['config']) == expected, 'archive read/export changed config paths'
        archived_meta = work / 'archive-manifest.json'; archived_meta.write_text(raw)
        run(prefix + ['register', '-t', '-M', archived_meta])
        actual = json.loads(run([sqlite, '-json', '-readonly', work / 'db/local.sqlite',
                                'SELECT path FROM config_files ORDER BY path']))
        assert [r['path'] for r in actual] == sorted(paths), 'registered config paths differ from archive payload'
        report.update(result='PASS', paths=paths,
                      archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
    except BaseException as error:
        report.update(result='FAIL', error=str(error))
        raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
