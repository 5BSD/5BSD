#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Prepare a signed, complete captured-package repository for disposable VM tests.

Never publishes a system repository, changes latest, or installs packages.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(SOURCE/'tools/build/bazel'))
from qualification_artifacts import resolve, resolve_many, digest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();plan=json.loads(args.plan.read_text())
    required={'format','qualification','packages_target','index_output','families_target',
              'families_output','package_output_prefix','pkg','private_key','public_key','wrong_public_key','abi','osversion'}
    if set(plan)!=required or type(plan['format']) is not int or plan['format']!=1:
        raise ValueError('exact format-1 signed qualification repository plan required')
    if not re.fullmatch(r'FreeBSD:[0-9]+:[A-Za-z0-9_]+',plan['abi']) or not re.fullmatch(r'[0-9]+',str(plan['osversion'])):
        raise ValueError('explicit target ABI and OS version required')
    os.environ['PATH']='/sbin:/bin:/usr/sbin:/usr/bin'
    os.environ['LC_ALL']='C'
    output=args.output.resolve()
    if output.exists() or not output.is_relative_to('/usr/obj/usr/src'):
        raise ValueError('fresh standard object-root qualification output required')
    tools={name:Path(plan[name]).resolve(strict=True) for name in ('pkg','private_key','public_key','wrong_public_key')}
    if any(not path.is_file() for path in tools.values()):raise ValueError('regular tools and key inputs required')
    if stat.S_IMODE(tools['private_key'].stat().st_mode)&0o077:
        raise ValueError('private signing key must not be accessible to group/other')
    spec=importlib.util.spec_from_file_location('hardware_packages',SOURCE/'release/scripts/hardware-packages.py')
    hardware=importlib.util.module_from_spec(spec);spec.loader.exec_module(hardware)
    q=Path(plan['qualification'])
    selected=resolve_many(q,[(plan['packages_target'],plan['index_output']),
                            (plan['families_target'],plan['families_output'])])
    index=json.loads(selected[0][0].read_text());family=json.loads(selected[1][0].read_text())
    expected={family['prefix']+'-'+name+'-'+family['version']+'.pkg' for name in family['packages']}
    if expected!={row['name'] for row in index['packages']} or len(expected)!=len(index['packages']):
        raise ValueError('complete distinct captured package set required')
    prefix=plan['package_output_prefix']
    if not prefix.endswith('/'):raise ValueError('explicit captured package output directory prefix required')
    packages=resolve_many(q,[(plan['packages_target'],prefix+row['name']) for row in index['packages']],exact=True)
    output.mkdir(mode=0o700)
    repository=output/'repository';repository.mkdir()
    control=output/'control';control.mkdir(mode=0o700)
    (control/'repositories').mkdir()
    report=dict(format=1,status='running',scope='Complete signed private qualification repository and actual catalogue/archive verification; not combined publication, installation or verified boot',
        plan_sha256=digest(args.plan),package_inputs=[binding for _,binding in packages],
        metadata_inputs=[binding for _,binding in selected],packages=len(packages),version=family['version'],abi=plan['abi'],osversion=str(plan['osversion']),
        host_tools={str(path):digest(path) for path in map(Path,('/usr/bin/tar','/usr/bin/openssl'))},
        tools={str(path):digest(path) for path in tools.values()},
        sources={str(path):digest(path) for path in (Path(__file__),SOURCE/'tools/build/bazel/qualification_artifacts.py',
            SOURCE/'release/scripts/hardware-packages.py',SOURCE/'tools/build/capimage/package_closure.py')},commands=[])
    def save():(output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(label,argv):
        result=subprocess.run(list(map(str,argv)),capture_output=True,env=dict(os.environ,INSTALL_AS_USER='yes',LC_ALL='C'),timeout=900)
        (control/(label+'.stdout')).write_bytes(result.stdout);(control/(label+'.stderr')).write_bytes(result.stderr)
        report['commands'].append(dict(label=label,argv=list(map(str,argv)),status=result.returncode,
            stdout_sha256=digest(control/(label+'.stdout')),stderr_sha256=digest(control/(label+'.stderr'))));save()
        if result.returncode:raise RuntimeError(label+' failed; see control logs')
        return result.stdout
    save()
    try:
        for row,(source,binding) in zip(index['packages'],packages):
            if row['sha256']!=binding['sha256']:raise ValueError('package index digest mismatch')
            shutil.copyfile(source,repository/row['name'])
            if digest(repository/row['name'])!=binding['sha256']:raise ValueError('copied package differs')
        hardware.copy_public_key(tools['public_key'],control/'repository.pub')
        hardware.copy_public_key(tools['wrong_public_key'],control/'wrong.pub')
        if digest(control/'repository.pub')==digest(control/'wrong.pub'):
            raise ValueError('negative verification requires a different public key')
        derived=run('signer-public',['/usr/bin/openssl','pkey','-in',tools['private_key'],'-pubout'])
        if derived!=(control/'repository.pub').read_bytes():raise ValueError('private/public signing key pair differs')
        common=[tools['pkg'],'-C','/dev/null','-R',control/'repositories','-o','PKG_DBDIR='+str(control/'db'),
            '-o','PKG_CACHEDIR='+str(control/'cache'),'-o','SYSLOG=no','-o','PKG_ENABLE_PLUGINS=no',
            '-o','ABI='+report['abi'],'-o','OSVERSION='+report['osversion']]
        run('repository',common+['repo','-l',repository,tools['private_key']])
        hardware.verify_catalogue_public_key(repository,control/'repository.pub',tools['pkg'],report['abi'],report['osversion'],verify_archives=True)
        try:
            hardware.verify_catalogue_public_key(repository,control/'wrong.pub',tools['pkg'],report['abi'],report['osversion'])
        except (ValueError,subprocess.CalledProcessError) as error:
            text=str(error)+'\n'+str(getattr(error,'stderr','') or '')
            if not re.search('signatur|verification|verif',text,re.I):
                raise RuntimeError('negative verification did not report a signature failure') from error
            report['wrong_key_rejection']=text
        else:raise ValueError('wrong repository key was accepted')
        report['repository_files']={path.name:digest(path) for path in sorted(repository.iterdir()) if path.is_file()}
        if len(report['repository_files'])!=len(list(repository.iterdir())):raise ValueError('unexpected repository object')
        if any(digest(Path(path))!=sha for path,sha in (report['tools']|report['host_tools']).items()):raise ValueError('tool/key input changed')
        if any(digest(Path(path))!=sha for path,sha in report['sources'].items()):raise ValueError('source input changed')
        report.update(status='passed',public_key_sha256=digest(control/'repository.pub'),wrong_public_key_sha256=digest(control/'wrong.pub'))
    except Exception as error:
        report.update(status='failed',error=repr(error));raise
    finally:save()
    print(output/'receipt.json')

if __name__=='__main__':main()
