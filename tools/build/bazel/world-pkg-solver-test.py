# SPDX-License-Identifier: BSD-2-Clause
"""Catalogue and solve every declared world package without installing payloads."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    request = json.loads(args.request.read_text())
    runfiles = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
    def source(path):
        return (runfiles / path).resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(mode=0o700)
    work = args.work.resolve(); work.mkdir(mode=0o700)
    root, repo, repos = [work / name for name in ['root', 'fixture-repo', 'repositories']]
    for path in [root, repo, repos, root/'var/db/pkg', root/'var/cache/pkg']:
        path.mkdir(parents=True, exist_ok=True)
    config = work/'pkg.conf'; config.write_text('{}\n')
    catalogue = json.loads(source(request['catalogue']).read_text())
    index = json.loads(source(request['index']).read_text())
    expected = sorted(catalogue['prefix']+'-'+name for name in catalogue['packages'])
    expected_files = {name+'-'+catalogue['version']+'.pkg' for name in expected}
    indexed = {row['name']:row['sha256'] for row in index['packages']}
    assert index['format']==1 and set(indexed)==expected_files and len(indexed)==len(index['packages'])
    archives = {Path(path).name:source(path) for path in request['packages']}
    assert set(archives)==expected_files and len(archives)==len(request['packages'])
    for name, path in archives.items():
        assert digest(path)==indexed[name],name
        shutil.copyfile(path,repo/name)
        assert digest(repo/name)==indexed[name],name
    (repos/'fixture.conf').write_text(json.dumps(dict(fixture=dict(url=repo.as_uri(),enabled=True,signature_type='none')))+'\n')
    pkg=source(request['pkg'])
    environment={key:os.environ[key] for key in ['PATH','LD_LIBRARY_PATH'] if key in os.environ}
    environment.update(HOME=str(work),LC_ALL='C',INSTALL_AS_USER='1')
    report=dict(status='running',scope='Private unsigned fixture catalogue, complete world dependency/conflict solver dry-run; no installation, package scripts or publication',packages=len(expected),pkg_sha256=digest(pkg),commands=[])
    def save():
        (out/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(command,label):
        command=list(map(str,command));done=subprocess.run(command,capture_output=True,env=environment,timeout=240)
        for kind,data in [('stdout',done.stdout),('stderr',done.stderr)]:
            (out/(label+'.'+kind)).write_bytes(data)
        report['commands'].append(dict(argv=command,status=done.returncode,stdout_sha256=digest(out/(label+'.stdout')),stderr_sha256=digest(out/(label+'.stderr'))));save()
        assert done.returncode==0,(label,done.stderr.decode()[-1800:])
        return done.stdout.decode()
    try:
        # Exercise the maintained root-shell helper's exact configuration builder.
        spec=importlib.util.spec_from_file_location('private_pkg',source(request['helper']))
        helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        private=helper.pkg_command(pkg,root,config,repos)
        for key,path in [('PKG_DBDIR',root/'var/db/pkg'),('PKG_CACHEDIR',root/'var/cache/pkg')]:
            assert run(private+['config',key],'config-'+key).strip()==str(path),key
        common=[str(pkg),'-C',str(config),'-R',str(repos),'-o','PKG_DBDIR='+str(work/'catalogue-db'),'-o','PKG_CACHEDIR='+str(work/'catalogue-cache'),'-o','SYSLOG=no','-o','PKG_ENABLE_PLUGINS=no']
        abi=run(common+['-o','ABI_FILE='+str(source(request['abi_file'])),'config','ABI'],'abi').strip()
        assert abi and not any(c.isspace() for c in abi)
        versions=re.findall(r'^#define\s+__FreeBSD_version\s+(\d+)\s*$',source(request['osversion_header']).read_text(),re.M)
        assert len(versions)==1
        run(common+['repo','-l',str(repo)],'repo')
        private+=['-o','ABI='+abi,'-o','OSVERSION='+versions[0]]
        run(private+['update','-f','-r','fixture'],'update')
        actual=run(private+['rquery','-r','fixture','%n'],'catalogue').splitlines()
        assert sorted(actual)==expected,'catalogue differs from selected families'
        output=run(private+['install','-n','-y','-U','-r','fixture',*expected],'solve')
        # Require the entire plan rather than accepting a successful no-op.
        planned=re.findall(r'^\t([^\s:]+): '+re.escape(catalogue['version'])+r'$',output,re.M)
        assert sorted(planned)==expected,'solver plan omits/adds a selected package'
        assert '(0 conflicting)' in output,'integrity check did not report zero conflicts'
        assert not (root/'bin').exists() and not (root/'usr').exists(),'dry-run installed payload'
        assert not run(private+['query','-a','%n'],'installed-inventory').strip(),'dry-run registered packages'
        for name,path in archives.items():
            assert digest(path)==indexed[name] and digest(repo/name)==indexed[name],name
        report.update(status='passed',abi=abi,osversion=versions[0],planned_packages=len(planned),repository_packages=len(actual),installed_packages=0)
        save();print(json.dumps(report,indent=2))
    except Exception as error:
        report.update(status='failed',error=repr(error));save();raise


if __name__=='__main__':
    main()
