#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Test dependency metadata updates with payload-free archives and private pkg DB."""
import argparse
import copy
import importlib.util
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
    parser.add_argument('--constructor', type=Path, help='explicit database_construction.py for preflight regression')
    parser.add_argument('--contract', type=Path, help='reviewed engine/schema contract for constructor preflight')
    args = parser.parse_args()
    if (args.constructor is None) != (args.contract is None):
        parser.error('constructor and contract must be supplied together')
    constructor = None
    if args.constructor is not None:
        spec = importlib.util.spec_from_file_location('database_constructor', args.constructor.resolve(strict=True))
        constructor = importlib.util.module_from_spec(spec); spec.loader.exec_module(constructor)
    work = args.work.absolute()
    if not work.is_relative_to('/usr/obj/usr/src') or args.osversion <= 0:
        parser.error('requires fresh work under /usr/obj/usr/src and positive OSVERSION')
    work.mkdir(mode=0o700)
    for name in ('repos', 'db'):
        (work / name).mkdir()
    pkg, sqlite = args.pkg.resolve(strict=True), args.sqlite.resolve(strict=True)
    prefix = [str(pkg), '-C', '/dev/null', '-R', str(work / 'repos')]
    for setting in ['PKG_DBDIR=' + str(work / 'db'), 'PKG_CACHEDIR=' + str(work / 'cache'),
                    'ABI=' + args.abi, 'OSVERSION=' + str(args.osversion), 'INSTALL_AS_USER=yes',
                    'RUN_SCRIPTS=no', 'PKG_ENABLE_PLUGINS=no', 'PKG_TRIGGERS_ENABLE=no',
                    'SYSLOG=no', 'REPO_AUTOUPDATE=no']:
        prefix.extend(['-o', setting])
    env = {'PATH': '/bin:/usr/bin:/sbin:/usr/sbin', 'HOME': str(work), 'LC_ALL': 'C'}
    report = {'result': 'RUNNING', 'scope': 'dependency metadata update and unrelated row isolation',
              'pkg_sha256': hashlib.sha256(pkg.read_bytes()).hexdigest(), 'commands': []}

    def run(argv):
        r = subprocess.run(list(map(str, argv)), cwd=work, env=env,
                           capture_output=True, text=True, timeout=60)
        report['commands'].append(dict(argv=list(map(str, argv)), exit=r.returncode,
                                       stdout=r.stdout, stderr=r.stderr))
        r.check_returncode()
        return r.stdout

    def rows(database=None):
        return json.loads(run([sqlite, '-readonly', '-json', database or work / 'db/local.sqlite',
            'SELECT p.name AS package,d.name,d.origin,d.version FROM deps d '
            'JOIN packages p ON p.id=d.package_id ORDER BY p.name,d.name']))

    try:
        for name, version in [('dependency-target', '1'), ('2', '7'),
                              ('dependency-consumer', '1'), ('dependency-target', '2')]:
            manifest = dict(name=name, origin='tests/' + name, version=version,
                comment='dependency update fixture', desc='dependency update fixture',
                maintainer='test@example.invalid', www='https://example.invalid',
                prefix='/', abi=args.abi, files={})
            if name == 'dependency-consumer':
                manifest['deps'] = {'dependency-target': {'origin': 'tests/dependency-target', 'version': '1'},
                                    '2': {'origin': 'tests/2', 'version': '7'}}
            meta = work / (name + '-' + version + '.json'); meta.write_text(json.dumps(manifest))
            run(prefix + ['create', '-M', meta, '-o', work])
            archive = work / (name + '-' + version + '.pkg')
            raw = json.loads(run(['/usr/bin/tar', '-xOf', archive, '+MANIFEST']))
            if raw.get('files') or raw.get('scripts') or raw.get('lua_scripts'):
                raise ValueError('fixture must contain no payload or hooks')
            run(prefix + ['add', '-f', archive])
            if name == 'dependency-consumer':
                report['before'] = rows()
        expected = [dict(package='dependency-consumer', name='2', origin='tests/2', version='7'),
                    dict(package='dependency-consumer', name='dependency-target', origin='tests/dependency-target', version='2')]
        report['expected'] = expected; report['actual'] = rows()
        if report['actual'] != expected:
            raise AssertionError('dependency update changed wrong rows or retained stale metadata')
        run(prefix + ['add', '-f', work / 'dependency-target-1.pkg'])
        rollback_expected = [dict(row) for row in expected]
        rollback_expected[1]['version'] = '1'
        report['rollback_expected'] = rollback_expected
        report['rollback_actual'] = rows()
        if report['rollback_actual'] != rollback_expected:
            raise AssertionError('dependency rollback changed wrong rows or retained stale metadata')
        # Fresh generation construction uses one local-only registration
        # transaction, not sequential add -f. Verify the actual selected version
        # separately from the consumer's recorded build dependency metadata.
        report['fresh_generations'] = []
        for version in ('1', '2'):
            database_dir = work / ('fresh-' + version)
            database_dir.mkdir()
            fresh = list(prefix)
            fresh[fresh.index('PKG_DBDIR=' + str(work / 'db'))] = 'PKG_DBDIR=' + str(database_dir)
            archives = [work / ('dependency-target-' + version + '.pkg'),
                        work / 'dependency-consumer-1.pkg', work / '2-7.pkg']
            if constructor is not None:
                inventory = constructor.construction.pkg.inventory_packages(archives)
                contract = constructor.payload.preflight.decode(args.contract.read_bytes())
                contract['packages'] = [dict(
                    **{key: package['manifest'][key] for key in ('name', 'origin', 'version', 'abi')},
                    automatic=0, locked=0, vital=int(package['manifest'].get('vital', False)))
                    for package in inventory['packages']]
                constructor.prepare(pkg, sqlite, inventory, contract, args.osversion)
                altered = copy.deepcopy(contract)
                target = next(row for row in altered['packages'] if row['name'] == 'dependency-target')
                target['version'] = 'unapproved'
                try:
                    constructor.prepare(pkg, sqlite, inventory, altered, args.osversion)
                except ValueError as error:
                    if 'archive identity differs from policy' not in str(error):
                        raise
                else:
                    raise AssertionError('constructor accepted an unapproved selected version')
                report.setdefault('constructor_preflight', []).append(dict(
                    selected_version=version, result='PASS', mismatched_contract_rejected=True))
            run(fresh + ['install', '--register-only', '--local-only', '--yes', *archives])
            database = database_dir / 'local.sqlite'
            installed = json.loads(run([sqlite, '-readonly', '-json', database,
                'SELECT name,version FROM packages ORDER BY name']))
            expected_installed = [dict(name='2', version='7'),
                dict(name='dependency-consumer', version='1'),
                dict(name='dependency-target', version=version)]
            actual_deps = rows(database)
            report['fresh_generations'].append(dict(selected_version=version,
                installed=installed, dependencies=actual_deps))
            if installed != expected_installed:
                raise AssertionError('fresh registration did not select requested archive versions')
            if actual_deps != rollback_expected:
                raise AssertionError('fresh registration changed consumer archive dependency metadata')
        report['result'] = 'PASS'
    except BaseException as error:
        report.update(result='FAIL', error=str(error))
        raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
