#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Discover configured world directories through maintained Make print-dir.

This inventories recursion, not native action coverage or build dependencies.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import time
from libmd_environment import BuildEnvironment,digest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('src','objtop','profile','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--target-arch',choices=['amd64','aarch64','riscv64'],default='amd64')
    p.add_argument('--trust-anchor',type=Path,action='append',default=[])
    p.add_argument('--jobs',type=int,required=True)
    p.add_argument('--make',type=Path,default=Path('/usr/bin/make'))
    a=p.parse_args()
    if a.jobs<1:p.error('positive job count required')
    src,obj,profile,make=[v.resolve(strict=True) for v in (a.src,a.objtop,a.profile,a.make)]
    out=a.output.resolve()
    if not a.output.is_absolute() or a.output.is_symlink() or out.exists() or out==Path('/usr/obj') or not out.is_relative_to('/usr/obj') or any(v.is_relative_to(out) or (v.is_dir() and out.is_relative_to(v)) for v in (src,obj,profile,make)):
        p.error('fresh nonoverlapping output below /usr/obj required')
    anchors=[];bindings={str(Path(__file__).resolve()):digest(Path(__file__))}
    for value in a.trust_anchor:
        if not value.is_absolute() or any(c.isspace() or c=='$' for c in str(value)):
            p.error('absolute trust anchor paths without whitespace/Make expansion required')
        anchor=value.resolve(strict=True);data=anchor.read_bytes()
        if b'-----BEGIN CERTIFICATE-----' not in data or b'PRIVATE KEY' in data:
            p.error('public certificate PEM required for trust anchor')
        anchors.append(anchor);bindings[str(anchor)]=digest(anchor)
    if len(set(anchors))!=len(anchors):p.error('duplicate trust anchor')
    extra=['TRUST_ANCHORS='+' '.join(map(str,anchors))] if anchors else []
    env=BuildEnvironment(src,obj,profile,make,target_architecture=a.target_arch)
    keys=['SUBDIR','LOCAL_DIRS','LOCAL_LIB_DIRS','SUBDIR_OVERRIDE','_prereq_libs','_startup_libs','_prebuild_libs','_generic_libs']
    rows=env.query(['-f','Makefile.inc1',*[v for key in keys for v in ('-v',key)]],component=src,extra=extra).splitlines()
    if len(rows)!=len(keys):raise ValueError('ambiguous world metadata')
    inner=[str(make),'-C',str(src),'-f','Makefile.inc1',*env.fixed,*env.options,'SRCTOP='+str(src),'OBJTOP='+str(obj),*extra,'-j'+str(a.jobs),'.MAKE.JOB.PREFIX=','print-dir']
    cmd=[str(make),'-C',str(src),*env.fixed,*env.options,'buildenv','BUILDENV_SHELL='+shlex.join(inner)]
    out.mkdir();start=time.monotonic()
    with (out/'print-dir.stdout').open('w') as stdout,(out/'print-dir.stderr').open('w') as stderr:
        result=subprocess.run(['/usr/bin/time','-l',*cmd],env=env.env,stdout=stdout,stderr=stderr)
    text=(out/'print-dir.stdout').read_text().splitlines()
    if not text or text[0]!='Entering world for '+env.assignments['TARGET_ARCH']+':'+env.assignments['TARGET']:raise ValueError('unexpected buildenv prefix')
    directories=[];diagnostics=[]
    for line in text[1:]:
        candidate=Path(line)
        if line and not candidate.is_absolute() and '..' not in candidate.parts and (src/candidate/'Makefile').is_file():
            actual=(src/candidate).resolve()
            if not actual.is_relative_to(src):raise ValueError('discovered directory escapes source')
            directories.append(line)
        elif line:diagnostics.append(line)
    if result.returncode==0 and diagnostics:raise ValueError('successful traversal included unexplained output')
    for name in set(directories):bindings[str(src/name/'Makefile')]=digest(src/name/'Makefile')
    env.verify()
    for name,sha in bindings.items():
        if digest(Path(name))!=sha:raise ValueError('inventory input changed: '+name)
    record={'format':1,'target_architecture':a.target_arch,'status':'discovered' if result.returncode==0 else 'incomplete',
            'scope':'configured Make world recursion only; not native build coverage',
            'metadata':dict(zip(keys,rows)),'directories':sorted(set(directories)),
            'duplicate_visits':len(directories)-len(set(directories)),'diagnostics':diagnostics,
            'trust_anchors':[str(v) for v in anchors],'input_sha256':bindings,'environment':env.receipt(),
            'command':cmd,'exit_status':result.returncode,'elapsed_seconds':time.monotonic()-start,
            'limitations':['Subdirectory observations on a failed traversal are incomplete.',
                           'Directory inventory does not describe generated sources or compile/link actions.',
                           'Full recursive Make include closure and bootstrap phases are not authenticated by this inventory.']}
    (out/'inventory.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'status':record['status'],'directories_observed':len(record['directories']),'inventory':str(out/'inventory.json')}))
    raise SystemExit(result.returncode)


if __name__=='__main__':main()
