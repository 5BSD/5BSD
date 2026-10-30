#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Require Lua hook order to survive real package creation/private registration.

All hooks are disabled. Fixtures have no payload. The selected pkg is a trusted
builder input; only a new private package database is used, never the host DB.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pkg', type=Path, required=True)
    parser.add_argument('--abi', required=True)
    parser.add_argument('--osversion', type=int, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    if args.osversion <= 0:
        parser.error('osversion must be positive')
    pkg = args.pkg.resolve(strict=True); work = args.work.absolute()
    if not work.is_relative_to('/usr/obj/usr/src'):
        parser.error('qualification work must be under /usr/obj/usr/src')
    work.mkdir(mode=0o700)
    repos = work / 'repos'; repos.mkdir()
    db = work / 'db'; db.mkdir()
    env = {'PATH': '/bin:/usr/bin:/sbin:/usr/sbin', 'HOME': str(work), 'LC_ALL': 'C'}
    prefix = [str(pkg), '-C', '/dev/null', '-R', str(repos)]
    for setting in ['PKG_DBDIR=' + str(db), 'PKG_CACHEDIR=' + str(work / 'cache'),
                    'ABI=' + args.abi, 'OSVERSION=' + str(args.osversion), 'PKG_ENABLE_PLUGINS=no', 'RUN_SCRIPTS=no',
                    'PKG_TRIGGERS_ENABLE=no', 'SYSLOG=no', 'REPO_AUTOUPDATE=no',
                    'INSTALL_AS_USER=yes']:
        prefix.extend(['-o', setting])
    report = {'result': 'RUNNING', 'scope': 'Lua hook order persistence',
              'pkg_sha256': hashlib.sha256(pkg.read_bytes()).hexdigest(),
              'commands': [], 'cases': []}

    def run(argv):
        result = subprocess.run(argv, cwd=work, env=env, capture_output=True, text=True, timeout=60)
        report['commands'].append({'argv': argv, 'exit': result.returncode,
                                   'stdout': result.stdout, 'stderr': result.stderr})
        result.check_returncode()
        return result.stdout

    # Seed the dictionary in the opposite order to the second package's hooks.
    # The fixtures must retain A then B for the second package regardless of IDs.
    a = 'pkg.print_msg("LUA_ORDER_A")'
    b = 'pkg.print_msg("LUA_ORDER_B")'
    try:
        for name, hooks in [
            ('lua-order-seed', {'post-install': [b]}),
            ('lua-order-target', {'post-install': [a, b]}),
            ('lua-repeat-target', {'post-install': [a, b, a]}),
            ('lua-phase-target', {'pre-install': [a], 'post-install': [a]}),
        ]:
            manifest = {'name': name, 'origin': 'tests/' + name, 'version': '1',
                        'comment': 'Lua hook order fixture', 'desc': 'Lua hook order fixture',
                        'maintainer': 'test@example.invalid', 'www': 'https://example.invalid',
                        'abi': args.abi, 'prefix': '/', 'files': {},
                        'lua_scripts': hooks}
            path = work / (name + '.json'); path.write_text(json.dumps(manifest))
            run(prefix + ['create', '-M', str(path), '-o', str(work)])
            archive = work / (name + '-1.pkg')
            archived = json.loads(run(['/usr/bin/tar', '-xOf', str(archive), '+MANIFEST']))
            assert archived['lua_scripts'] == hooks, 'archive changed hook order'
            case = {'package': name, 'expected': hooks,
                    'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}
            report['cases'].append(case)
            try:
                run(prefix + ['add', str(archive)])
            except subprocess.CalledProcessError as error:
                case.update(result='FAIL', registration_exit=error.returncode)
                continue
            exported = json.loads(run(prefix + ['info', '--raw', '--raw-format', 'json', name]))
            assert len(exported) == 1
            actual = exported[0]['lua_scripts']
            case['actual'] = actual
            case['result'] = 'PASS' if actual == hooks else 'FAIL'
        assert all(c['result'] == 'PASS' for c in report['cases']), 'Lua hook persistence failures'
        report['result'] = 'PASS'
    except BaseException as error:
        report.update(result='FAIL', error=str(error)); raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
