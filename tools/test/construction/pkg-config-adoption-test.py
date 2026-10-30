#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Test configuration adoption across package upgrades in private host paths.

Only synthetic archives whose exact payload paths are verified beneath a new
private work directory are installed. Hooks, plugins, triggers and repositories
are disabled. This is package-engine behavior, not BIP activation authorization.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('pkg','sqlite','baseline','local','work'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--abi',required=True)
    parser.add_argument('--osversion',type=int,required=True)
    args=parser.parse_args()
    work=args.work.absolute()
    if (work.resolve()!=work or not work.is_relative_to('/usr/obj/usr/src') or
            args.osversion<=0):
        parser.error('requires a new canonical work directory under /usr/obj/usr/src and positive OSVERSION')
    pkg,sqlite,baseline,local=[p.resolve(strict=True) for p in (args.pkg,args.sqlite,args.baseline,args.local)]
    baseline_bytes,local_bytes=baseline.read_bytes(),local.read_bytes()
    if not baseline_bytes or not local_bytes or baseline_bytes==local_bytes:
        parser.error('explicit nonempty distinct baseline and local inputs required')
    work.mkdir(mode=0o700)
    for name in ('repos','db','stage','live'):(work/name).mkdir()
    target=work/'live/site.conf'
    report=dict(result='RUNNING',scope='package configuration adoption upgrade/rollback in private paths',
        files_sha256={str(p):digest(p) for p in (pkg,sqlite,baseline,local)},commands=[],checks=[])
    env={'PATH':'/bin:/usr/bin:/sbin:/usr/sbin','HOME':str(work),'LC_ALL':'C'}
    prefix=[str(pkg),'-C','/dev/null','-R',str(work/'repos')]
    for setting in ['PKG_DBDIR='+str(work/'db'),'PKG_CACHEDIR='+str(work/'cache'),
        'ABI='+args.abi,'OSVERSION='+str(args.osversion),'INSTALL_AS_USER=yes',
        'RUN_SCRIPTS=no','PKG_ENABLE_PLUGINS=no','PKG_TRIGGERS_ENABLE=no',
        'SYSLOG=no','REPO_AUTOUPDATE=no','AUTOMERGE=yes']:
        prefix+=['-o',setting]

    def run(argv):
        argv=list(map(str,argv));r=subprocess.run(argv,env=env,cwd=work,capture_output=True,text=True,timeout=60)
        report['commands'].append(dict(argv=argv,exit=r.returncode,stdout=r.stdout,stderr=r.stderr))
        r.check_returncode();return r.stdout

    def check_local(name):
        if not target.is_file() or target.read_bytes()!=local_bytes:
            raise ValueError('local configuration missing or changed during '+name)
        report['checks'].append(name)

    try:
        archives={}
        for version in ('1','2'):
            manifest=dict(name='config-adoption-fixture',origin='tests/config-adoption-fixture',version=version,
                comment='private configuration adoption fixture',desc='private configuration adoption fixture',
                maintainer='test@example.invalid',www='https://example.invalid',abi=args.abi,prefix=str(target.parent))
            metadata=work/('manifest-'+version+'.json');metadata.write_text(json.dumps(manifest))
            plist=work/('plist-'+version)
            plist.write_text('@config site.conf\n' if version=='2' else '')
            if version=='2':
                staged=work/'stage'/str(target).lstrip('/');staged.parent.mkdir(parents=True)
                staged.write_bytes(baseline_bytes)
            run(prefix+['create','-M',metadata,'-p',plist,'-r',work/'stage','-o',work])
            archive=work/('config-adoption-fixture-'+version+'.pkg')
            raw=json.loads(run(['/usr/bin/tar','-xOf',archive,'+MANIFEST']))
            files=raw.get('files',{})
            if (set(files)!=(set() if version=='1' else {str(target)}) or
                    raw.get('scripts') or raw.get('lua_scripts') or raw.get('deps') or
                    raw.get('config',[])!=([] if version=='1' else [str(target)])):
                raise ValueError('archive has unexpected payload, hook, dependency or configuration')
            entries=run(['/usr/bin/tar','-tf',archive]).splitlines()
            allowed={'+MANIFEST','+COMPACT_MANIFEST'} | ({str(target),str(target).lstrip('/')} if version=='2' else set())
            if any(name not in allowed for name in entries):
                raise ValueError('archive contains undeclared member')
            archives[version]=archive
        run(prefix+['install','-y','-U',archives['1']])
        target.write_bytes(local_bytes)
        run(prefix+['install','-y','-U',archives['2']]);check_local('upgrade-adds-config-declaration')
        new=Path(str(target)+'.pkgnew')
        if not new.is_file() or new.read_bytes()!=baseline_bytes:
            raise ValueError('new baseline not retained separately for conflict review')
        rows=json.loads(run([sqlite,'-readonly','-json',work/'db/local.sqlite',
            'SELECT hex(CAST(content AS BLOB)) AS baseline FROM config_files']))
        if rows!=[dict(baseline=baseline_bytes.hex().upper())]:
            raise ValueError('database baseline differs from package bytes')
        report['checks'].append('package-baseline-and-local-bytes-independent')
        run(prefix+['install','-y','-U',archives['1']]);check_local('rollback-retains-local-config')
        run(prefix+['install','-y','-U',archives['2']]);check_local('reupgrade-retains-local-config')
        for name,expected in report['files_sha256'].items():
            if digest(Path(name))!=expected:raise ValueError('input changed during test')
        report['result']='PASS'
    except BaseException as error:
        report.update(result='FAIL',error=str(error));raise
    finally:
        (work/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('commands','files_sha256')},indent=2))


if __name__=='__main__':main()
