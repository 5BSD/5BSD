#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify Lua occurrence migration using private copies of a schema-42 database.

Does not run hooks or select the host database. Legacy order is the stored row
order, not proof of the original archive's order. New-generation verification must
use archive inputs separately.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('pkg', 'old-pkg', 'sqlite', 'database', 'fresh-database', 'work'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--abi', required=True)
    parser.add_argument('--osversion', type=int, required=True)
    args = parser.parse_args()
    pkg, old, sqlite, source = [p.resolve(strict=True) for p in (args.pkg, args.old_pkg, args.sqlite, args.database)]
    fresh = args.fresh_database.resolve(strict=True)
    work = args.work.absolute()
    if not work.is_relative_to('/usr/obj/usr/src') or args.osversion <= 0:
        parser.error('requires object-root work directory and positive OSVERSION')
    for suffix in ('-wal', '-journal'):
        p = Path(str(source) + suffix)
        if p.exists() and p.stat().st_size:
            parser.error('source database must be checkpointed')
    work.mkdir(mode=0o700); repos = work/'repos'; repos.mkdir()
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    env = {'PATH': '/bin:/usr/bin:/sbin:/usr/sbin', 'HOME': str(work), 'LC_ALL': 'C'}
    report = {'result': 'RUNNING', 'scope': 'Lua database migration and old-engine refusal',
              'source_sha256': before, 'commands': [], 'cases': [],
              'tools_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (pkg, old, sqlite)}}

    def sql(db, statement):
        r = subprocess.run([str(sqlite), '-batch', '-json', '-init', '/dev/null', str(db), statement],
            env=env, capture_output=True, text=True, check=True, timeout=60)
        return json.loads(r.stdout) if r.stdout.strip() else []

    def command(tool, db, argv):
        prefix = [str(tool), '-C', '/dev/null', '-R', str(repos)]
        for value in ['PKG_DBDIR='+str(db.parent), 'PKG_CACHEDIR='+str(work/'cache'),
                      'ABI='+args.abi, 'OSVERSION='+str(args.osversion), 'INSTALL_AS_USER=yes',
                      'PKG_ENABLE_PLUGINS=no', 'RUN_SCRIPTS=no', 'PKG_TRIGGERS_ENABLE=no',
                      'SYSLOG=no', 'REPO_AUTOUPDATE=no']:
            prefix.extend(['-o', value])
        r = subprocess.run(prefix+argv, cwd=work, env=env, capture_output=True, text=True, timeout=60)
        report['commands'].append({'argv': prefix+argv, 'exit': r.returncode,
                                  'stdout': r.stdout, 'stderr': r.stderr})
        return r

    def snapshot(db):
        schema = sql(db, "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
        rows = {r['name']: sql(db, 'SELECT * FROM "'+r['name'].replace('"','""')+'" ORDER BY rowid')
                for r in schema if r['type']=='table'}
        return {'version': sql(db, 'PRAGMA user_version'), 'schema': schema, 'rows': rows}

    try:
        assert sql(source, 'PRAGMA user_version') == [{'user_version':42}]
        legacy = sql(source, '''SELECT package_id,lua_script_id,type,
            row_number() OVER(PARTITION BY package_id,type ORDER BY rowid)-1 AS position
            FROM pkg_lua_script ORDER BY package_id,type,position''')
        assert legacy, 'fixture needs existing Lua hook rows'
        for name, mutation in [('valid', None), ('null-phase', 'NULL'), ('invalid-phase', '7'), ('fractional-phase', '1.5')]:
            root=work/name; root.mkdir(); db=root/'local.sqlite'; shutil.copyfile(source, db)
            if mutation:
                sql(db, 'UPDATE pkg_lua_script SET type='+mutation+' WHERE rowid=(SELECT min(rowid) FROM pkg_lua_script)')
            prior=snapshot(db)
            r=command(pkg, db, ['set', '-y', '-a', '-A', '0'])
            if mutation:
                assert r.returncode != 0, 'invalid legacy phase accepted'
                assert snapshot(db)==prior, 'failed migration did not roll back'
                report['cases'].append({'name':name, 'result':'PASS', 'migration_rejected':True, 'rollback_verified':True})
                continue
            r.check_returncode()
            assert sql(db, 'PRAGMA user_version') == [{'user_version':1000}]
            assert sql(db, "SELECT sql FROM sqlite_schema WHERE name='pkg_lua_script'") == sql(fresh, "SELECT sql FROM sqlite_schema WHERE name='pkg_lua_script'"), 'fresh/migrated Lua table definitions differ'
            actual=sql(db, 'SELECT package_id,lua_script_id,type,position FROM pkg_lua_script ORDER BY package_id,type,position')
            assert actual==legacy, 'legacy occurrences changed'
            assert sql(db, 'PRAGMA integrity_check') == [{'integrity_check':'ok'}]
            assert sql(db, 'PRAGMA foreign_key_check') == []
            stable=snapshot(db)
            command(pkg, db, ['set','-y','-a','-A','0']).check_returncode()
            assert snapshot(db)==stable, 'second open changed migrated data'
            r=command(old, db, ['set','-y','-a','-A','0'])
            assert r.returncode != 0 and 'incompatible' in r.stderr, 'old engine did not refuse incompatible write'
            assert snapshot(db)==stable, 'old engine modified new database'
            report['cases'].append({'name':name,'result':'PASS','occurrences':len(actual),
                                   'reopen_stable':True,'old_engine_write_refused':True})
        report['result']='PASS'
    except BaseException as error:
        report.update(result='FAIL',error=str(error));raise
    finally:
        assert hashlib.sha256(source.read_bytes()).hexdigest()==before
        (work/'result.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__ == '__main__':
    main()
