#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Demonstrate raw-manifest blind spots using private copies of a pkg database.

Evidence only: this is not a generation verifier. Source databases are never
mutated. The selected pkg and sqlite executables are trusted builder inputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('database', 'pkg', 'sqlite', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    source = args.database.resolve(strict=True)
    pkg = args.pkg.resolve(strict=True)
    sqlite = args.sqlite.resolve(strict=True)
    work = args.work.absolute()
    if not work.is_relative_to('/usr/obj/usr/src'):
        parser.error('qualification work must be under /usr/obj/usr/src')
    wal = Path(str(source) + '-wal')
    if wal.exists() and wal.stat().st_size:
        parser.error('requires a quiescent, checkpointed source database')
    original = sha(source)
    work.mkdir(mode=0o700)
    report = {'result': 'RUNNING', 'scope': 'raw-export-coverage-audit',
              'source': str(source), 'source_sha256': original,
              'executables': {str(p): sha(p) for p in (pkg, sqlite)}, 'cases': []}
    env = {'PATH': '/bin:/usr/bin:/sbin:/usr/sbin', 'HOME': str(work), 'LC_ALL': 'C'}

    def query(db, sql, write=False):
        argv = [str(sqlite), '-batch', '-json']
        if not write:
            argv.append('-readonly')
        result = subprocess.run(argv + [str(db), sql], env=env, text=True,
                                capture_output=True, check=True, timeout=60)
        if result.stderr:
            raise ValueError(result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else []

    def export(case):
        repos = case / 'repos'; repos.mkdir()
        argv = [str(pkg), '-C', '/dev/null', '-R', str(repos)]
        for value in ['PKG_DBDIR=' + str(case / 'db'), 'PKG_ENABLE_PLUGINS=no',
                      'RUN_SCRIPTS=no', 'PKG_TRIGGERS_ENABLE=no', 'SYSLOG=no',
                      'REPO_AUTOUPDATE=no', 'INSTALL_AS_USER=yes']:
            argv.extend(['-o', value])
        result = subprocess.run(argv + ['info', '-a', '--raw', '--raw-format', 'json'],
            env=env, text=True, capture_output=True, check=True, timeout=60)
        if result.stderr:
            raise ValueError(result.stderr)
        (case / 'export.json').write_text(result.stdout)
        rows = json.loads(result.stdout)
        names = [row['name'] for row in rows]
        if len(names) != len(set(names)) or not names:
            raise ValueError('invalid package export identities')
        return {row['name']: row for row in rows}

    try:
        mutations = [
            ('baseline', None),
            ('automatic', 'UPDATE packages SET automatic=1-automatic WHERE id=(SELECT min(id) FROM packages);'),
            ('locked', 'UPDATE packages SET locked=1-locked WHERE id=(SELECT min(id) FROM packages);'),
            ('unknown_schema', 'CREATE TABLE unexpected_policy (value TEXT); INSERT INTO unexpected_policy VALUES (\'unapproved\');'),
            ('orphan_file', "INSERT INTO files(path,sha256,package_id) VALUES('/unowned-audit-fixture','unapproved',(SELECT max(id)+1 FROM packages));"),
            ('null_owner', "INSERT INTO files(path,sha256,package_id) VALUES('/null-owner-audit-fixture','unapproved',NULL);"),
            ('null_lookup', 'INSERT INTO pkg_script(package_id,type,script_id) SELECT min(id),0,NULL FROM packages;'),
            ('unowned_script', "INSERT INTO script(script) VALUES('unowned audit fixture');"),
            ('missing_conflict', 'INSERT INTO pkg_conflicts(package_id,conflict_id) SELECT min(id),max(id)+1 FROM packages;'),
        ]
        baseline = baseline_state = baseline_schema = None
        for name, mutation in mutations:
            case = work / name; (case / 'db').mkdir(parents=True)
            db = case / 'db/local.sqlite'; shutil.copyfile(source, db)
            if query(db, 'PRAGMA user_version;') != [{'user_version': 42}]:
                raise ValueError('this audit requires pkg schema 42; inspect other versions explicitly')
            if mutation:
                changed = query(db, mutation + ' SELECT changes() AS changed;', write=True)
                if changed != [{'changed': 1}]:
                    raise ValueError('mutation did not change exactly one fixture row')
            physical = query(db, 'PRAGMA integrity_check;')
            references = query(db, 'PRAGMA foreign_key_check;')
            state = query(db, 'SELECT name,automatic,locked FROM packages ORDER BY name;')
            schema = query(db, "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name;")
            actual = export(case)
            if baseline is None:
                baseline, baseline_state, baseline_schema = actual, state, schema
            record = {'name': name, 'mutation': mutation, 'raw_export_matches_baseline': actual == baseline,
                      'integrity_check': physical, 'foreign_key_check': references,
                      'package_control_state': state, 'schema': schema}
            report['cases'].append(record)
            if physical != [{'integrity_check': 'ok'}]:
                raise ValueError('fixture corruption invalidates the comparison')
            if actual != baseline:
                raise ValueError('export behavior changed; review this pinned-engine audit')
            if name in ('automatic', 'locked') and state == baseline_state:
                raise ValueError('control-state mutation was not established')
            if name == 'unknown_schema' and schema == baseline_schema:
                raise ValueError('schema mutation was not established')
            if name != 'orphan_file' and references:
                raise ValueError('unexpected preexisting foreign-key violation')
            if name == 'orphan_file' and not references:
                raise ValueError('orphan mutation was not established')
        if sha(source) != original or (wal.exists() and wal.stat().st_size):
            raise ValueError('source changed during audit')
        report['result'] = 'PASS'
        report['conclusion'] = 'Raw exports and SQLite integrity_check alone cannot approve a package database.'
        report['generation_qualified'] = False
    except BaseException as error:
        report['result'] = 'FAIL'
        report['error'] = str(error)
        raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: ' + str(len(mutations) - 1) + ' database mutations are invisible to raw export; source unchanged')


if __name__ == '__main__':
    main()
