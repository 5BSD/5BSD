#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Create selected pkgbase archives from a verified native stage; never publish."""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess

from libmd_environment import BuildEnvironment, digest
import stage_verify
import archive_verify
import archive_headers
import component_labels


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'objtop', 'profile', 'workspace', 'directory-policy', 'output', 'pkg', 'flua'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--component-policy', type=Path, action='append', required=True)
    p.add_argument('--manifest-name', action='append', required=True)
    p.add_argument('--package-component', type=Path, required=True)
    p.add_argument('--abi-file', type=Path, required=True, help='stage-relative target ELF')
    p.add_argument('--jobs', type=int, required=True)
    p.add_argument('--make', type=Path, default=Path('/usr/bin/make'))
    p.add_argument('--awk', type=Path, default=Path('/usr/bin/awk'))
    a = p.parse_args()
    if a.jobs < 1:
        p.error('positive job count required')
    for name in ('package_component','abi_file'):
        value = getattr(a,name)
        if value.is_absolute() or '..' in value.parts:
            p.error(name+' must be relative without traversal')
    for name in ('src','objtop','profile','workspace','directory_policy','pkg','flua','make','awk'):
        value = getattr(a,name)
        if not value.is_absolute() or any(c in str(value) for c in ('\n','\r','$')):
            p.error('absolute paths without controls or Make expansion required')
        setattr(a,name,value.resolve(strict=True))
    policies = [v.resolve(strict=True) for v in a.component_policy]
    try:
        valid_manifests=all(re.fullmatch(r'[A-Za-z0-9_.+/-]+',component_labels.relative(n)) for n in a.manifest_name)
    except ValueError:
        valid_manifests=False
    if not valid_manifests:
        p.error('normalized relative manifest artifact paths required')
    out = a.output.resolve()
    protected = [a.src,a.objtop,a.workspace,a.directory_policy,*policies,a.pkg,a.flua]
    if (not a.output.is_absolute() or a.output.is_symlink() or out.exists() or
            out == Path('/usr/obj') or not out.is_relative_to('/usr/obj') or
            any(x==out or x.is_relative_to(out) or (x.is_dir() and out.is_relative_to(x)) for x in protected)):
        p.error('fresh nonoverlapping output below /usr/obj required')
    component=(a.src/a.package_component).resolve(strict=True)
    if not component.is_relative_to(a.src/'packages') or not (component/'Makefile').is_file():
        p.error('maintained source package component required')
    stage=a.workspace/'bazel-bin/native_stage.root'
    metalog=a.workspace/'bazel-bin/native_stage.METALOG'
    abi=(stage/a.abi_file).resolve(strict=True)
    if not abi.is_relative_to(stage.resolve()) or abi.read_bytes()[:4]!=b'\x7fELF':
        p.error('ABI input must be an ELF within the verified stage')
    parity=stage_verify.verify(a.workspace,a.directory_policy,component_plans=policies,manifest_names=a.manifest_name)
    env=BuildEnvironment(a.src,a.objtop,a.profile,a.make)
    version=env.query(['-f','Makefile.inc1','-v','PKG_VERSION'],component=a.src).strip()
    if not re.fullmatch(r'[A-Za-z0-9_.+,-]+',version):
        raise ValueError('invalid configured package version')
    inputs={str(x):digest(x) for x in [Path(__file__),a.pkg,a.flua,a.awk,a.directory_policy,*policies,metalog,abi,
        a.src/'tools/pkgbase/metalog_reader.lua',a.src/'release/scripts/mtree-to-plist.awk',
        Path(component_labels.__file__),Path(archive_verify.__file__),Path(archive_headers.__file__),archive_headers.LIBRARY.resolve(strict=True),Path(stage_verify.__file__),Path('/usr/bin/tar')]}
    inputs.update({str(x):digest(x) for x in component.rglob('*') if x.is_file()})
    out.mkdir();obj=out/'objects';obj.mkdir()
    extra=['REPODIR=/usr/obj/usr/src/repo','PKG_VERSION='+version,'WSTAGEDIR='+str(stage),
           'PKG_ABI_FILE='+str(abi),'FLUA='+str(a.flua),'PKG_CMD='+str(a.pkg)]
    # Bind package Make includes through the same explicit object/argument set.
    includes=env.query(['-v','.MAKE.MAKEFILES'],obj=obj,extra=extra,component=component)
    for name in shlex.split(includes):
        f=Path(name);f=(f if f.is_absolute() else component/f).resolve(strict=True)
        if f!=Path('/dev/null'):inputs[str(f)]=digest(f)
    commands=[]
    def run(argv,label,cwd=None):
        with (out/(label+'.stdout')).open('w') as stdout,(out/(label+'.stderr')).open('w') as stderr:
            result=subprocess.run(argv,cwd=cwd,stdout=stdout,stderr=stderr)
        commands.append({'argv':argv,'cwd':str(cwd) if cwd else None,'status':result.returncode})
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if result.returncode:raise RuntimeError(label+' failed; see '+str(out/(label+'.stderr')))
    keys=['_ALLPACKAGES','.OBJDIR','PKG_ABI','PKG_OSVERSION','PKG_NAME_PREFIX']
    rows=env.query([x for k in keys for x in ['-v',k]],obj=obj,component=component,extra=extra).splitlines()
    if len(rows)!=len(keys):raise ValueError('ambiguous package configuration')
    metadata=dict(zip(keys,rows));names=shlex.split(metadata['_ALLPACKAGES'])
    if not names or len(names)!=len(set(names)) or metadata['.OBJDIR']!=str(obj):
        raise ValueError('invalid package inventory or object directory')
    run([str(a.flua),str(a.src/'tools/pkgbase/metalog_reader.lua'),'-c',str(metalog)],'metalog')
    run([str(a.awk),'-v','complete_dirs=yes','-f',str(a.src/'release/scripts/mtree-to-plist.awk'),str(metalog)],'plists',obj)
    scaffolding=[]
    for plist in obj.glob('*.plist'):
        payload=[line for line in plist.read_text().splitlines() if line and not line.startswith('@dir')]
        if plist.stem not in names:
            if payload:raise ValueError('payload outside configured package inventory: '+plist.name)
            scaffolding.append(plist.name)
        elif not payload:raise ValueError('configured package has no payload: '+plist.name)
    for name in names:
        if not (obj/(name+'.plist')).is_file():raise ValueError('missing configured package plist: '+name)
    inner=['/usr/bin/env','MAKEOBJDIR='+str(obj),str(a.make),'-C',str(component),*env.fixed,*env.options,
           'SRCTOP='+str(a.src),'OBJTOP='+str(a.objtop),*extra,'-j'+str(a.jobs),'all']
    outer=[str(a.make),'-C',str(a.src),*env.fixed,*env.options,'buildenv','BUILDENV_SHELL='+shlex.join(inner)]
    run(['/usr/bin/time','-l',*outer],'packages')
    expected={metadata['PKG_NAME_PREFIX']+'-'+n+'-'+version+'.pkg' for n in names}
    archives=list(obj.glob('*.pkg'))
    if {x.name for x in archives}!=expected:raise ValueError('package archive coverage mismatch')
    stage_verify.verify(a.workspace,a.directory_policy,component_plans=policies,manifest_names=a.manifest_name)
    inspection=archive_verify.verify(archives,a.workspace,a.manifest_name,out/'archive-inspection',metadata['PKG_ABI'],version)
    env.verify()
    for name,sha in inputs.items():
        if digest(Path(name))!=sha:raise ValueError('package input changed: '+name)
    result={'status':'built','scope':'selected native stage packaged with maintained Make; not published or installed',
            'archive_inspection':{'receipt':str(out/'archive-inspection/receipt.json'),'status':inspection['status']},
            'stage_parity':parity,'metadata':metadata,'version':version,'input_sha256':inputs,
            'directory_only_plists_outside_selection':scaffolding,'environment':env.receipt(),
            'archives':[{'path':str(x),'sha256':digest(x)} for x in sorted(archives)],
            'limitations':['Execution tool runtime closure is not hermetic.','Archive installation and solver qualification are separate gates.']}
    (out/'receipt.json').write_text(json.dumps(result,indent=2)+'\n');print(out/'receipt.json')


if __name__=='__main__':main()
