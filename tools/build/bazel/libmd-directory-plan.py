#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Derive required libmd staging directories from source mtree and Make metadata."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess

import directory_metadata
import libmd_environment
from libmd_environment import BuildEnvironment, digest

CONFIG = ['NO_ROOT=yes', 'DB_FROM_SRC=yes', 'BUILD_PKGS=yes']


from directory_metadata import absolute, normalize, records


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['src','objtop','profile','output']:
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ['library-policy','test-policy','reference']:
        parser.add_argument('--'+name,type=Path)
    parser.add_argument('--component-policy',type=Path,action='append',default=[])
    parser.add_argument('--make',type=Path,default=Path('/usr/bin/make'))
    parser.add_argument('--mtree',type=Path,default=Path('/usr/sbin/mtree'))
    args=parser.parse_args()
    paths=[v for v in vars(args).values() if isinstance(v,Path)]+args.component_policy
    for value in paths:
        if not value.is_absolute() or any(ord(c)<32 or c=='$' for c in str(value)):
            parser.error('absolute paths without controls or Make expansion required')
    src,objtop,profile,make,mtree=[p.resolve(strict=True) for p in
        (args.src,args.objtop,args.profile,args.make,args.mtree)]
    if args.component_policy:
        if any((args.library_policy,args.test_policy,args.reference)):
            parser.error('component policies cannot be mixed with legacy library/test inputs')
        policy_files=[p.resolve(strict=True) for p in args.component_policy]
        payload_policies=[json.loads(p.read_text()) for p in policy_files]
        if any(p.get('status')!='reconciled' or not p.get('component') for p in payload_policies):
            raise ValueError('reconciled component policies required')
        components=[p['component'] for p in payload_policies]
        if len(set(components))!=len(components):raise ValueError('duplicate component')
        for component in components:
            if Path(component).is_absolute() or '..' in Path(component).parts or not (src/component).resolve().is_relative_to(src):
                raise ValueError('invalid policy component')
        references=[Path(p['reference']).resolve(strict=True) for p in payload_policies]
        policy_envs=[(p,'build_environment') for p in payload_policies]
        destinations=[d for p in payload_policies for d in p['payloads']]
    else:
        if not all((args.library_policy,args.test_policy,args.reference)):
            parser.error('legacy mode requires library-policy, test-policy and reference')
        policy_files=[args.library_policy.resolve(strict=True),args.test_policy.resolve(strict=True)]
        library,tests=[json.loads(p.read_text()) for p in policy_files]
        if library.get('status')!='reconciled' or tests.get('status')!='exported':
            raise ValueError('qualified input policy status required')
        policy_envs=[(library,'build_environment'),(tests,'environment')]
        references=[args.reference.resolve(strict=True)]
        destinations=list(library['payloads'])+[x['destination'] for x in tests['files']]
    if len(set(destinations))!=len(destinations):raise ValueError('overlapping payload destinations')
    output=args.output.resolve()
    if (output.exists() or args.output.is_symlink() or output==Path('/usr/obj') or
            not output.is_relative_to('/usr/obj') or output.is_relative_to(src) or src.is_relative_to(output) or
            objtop.is_relative_to(output) or output.is_relative_to(objtop/'tmp') or
            any(reference.is_relative_to(output) for reference in references)):
        parser.error('fresh private output below /usr/obj required')
    inputs={str(p):digest(p) for p in [Path(__file__).resolve(),Path(libmd_environment.__file__).resolve(),Path(directory_metadata.__file__).resolve(),
        mtree,*policy_files,*[p/n for p in references for n in ('METALOG','receipt.json')]]}
    for policy,key in policy_envs:
        e=policy[key]
        if e['objtop']!=str(objtop) or e['input_sha256'].get(str(profile))!=digest(profile):
            raise ValueError('payload policies differ from selected world/profile')
        for name,expected in policy['input_sha256'].items():
            if digest(Path(name))!=expected:raise ValueError('payload policy input changed: '+name)
            inputs[name]=expected
    for reference in references:
        receipt=json.loads((reference/'receipt.json').read_text())
        if (receipt.get('status')!='passed' or receipt.get('metalog_sha256')!=inputs[str(reference/'METALOG')] or
                receipt.get('environment',{}).get('objtop')!=str(objtop) or
                receipt.get('environment',{}).get('input_sha256',{}).get(str(profile))!=digest(profile)):
            raise ValueError('reference METALOG not bound by successful receipt')
    required={'/'}
    for destination in destinations:
        p=PurePosixPath(absolute(destination)).parent
        required.update(str(parent) for parent in [p,*p.parents])
    environments=[];closures=[];queries=[];commands=[];policy={};history={};declared_dirs={}
    def environment(component):
        e=BuildEnvironment(src,objtop,profile,make,component);environments.append(e);return e
    def query(e,names,extra=()):
        binding=CONFIG+list(extra)
        rows=e.query([v for n in names for v in ['-V',n]],extra=binding).splitlines()
        if len(rows)!=len(names):raise ValueError('ambiguous Make directory metadata')
        result=dict(zip(names,rows));queries.append({'component':str(e.component),'extra':list(extra),'values':result})
        return result
    def bind(e,extra=()):
        binding=CONFIG+list(extra);closures.append((e,binding,e.capture_closure(extra=binding)))
    def add(name,attrs,origin,phase,strict=False):
        name=absolute(name)
        if name not in required:return
        value=normalize(attrs)
        if strict and name in phase and phase[name]!=value:
            raise ValueError('conflicting coalesced DIRS policy: '+name)
        phase[name]=value
        history.setdefault(name,[]).append({'origin':origin,'policy':value})
        policy[name]=value
    etc=environment(src/'etc');bind(etc)
    meta=query(etc,['MTREES','MTREE_FILTER','DISTBASE','MK_INSTALL_AS_USER'])
    if shlex.split(meta['MTREE_FILTER'])!=['cat'] or meta['DISTBASE']:
        raise ValueError('unsupported mtree filter or distribution prefix')
    trees=shlex.split(meta['MTREES'])
    if len(trees)%2:raise ValueError('odd MTREES source/destination mapping')
    phase={}
    for filename,prefix in zip(trees[::2],trees[1::2]):
        source=(src/'etc'/filename).resolve(strict=True)
        if not source.is_relative_to(src):raise ValueError('mtree source escapes maintained tree')
        inputs[str(source)]=digest(source)
        command=[str(mtree),'-C','-K','all','-f',str(source)]
        done=subprocess.run(command,capture_output=True,text=True,check=True)
        commands.append({'argv':command,'status':done.returncode})
        for relative,attrs in records(done.stdout):
            name=absolute(prefix.rstrip('/')+('/'+relative[2:] if relative!='.' else '') or '/')
            if name in required and attrs.get('type')!='dir':raise ValueError('required ancestor is non-directory in mtree')
            if attrs.get('type')=='dir':add(name,attrs,str(source),phase)
    def component_dirs(e,extra=()):
        bind(e,extra);names=query(e,['DIRS'],extra)['DIRS'];phase=declared_dirs
        for name in sorted(set(shlex.split(names))):
            if not re.fullmatch('[A-Za-z_][A-Za-z0-9_.+-]*',name):raise ValueError('unsupported DIRS variable')
            values=query(e,[name]+[name+x for x in ['_MODE','_OWN','_GRP','_FLAGS','TAG_ARGS']],extra)
            if not values[name]:continue
            tag=shlex.split(values[name+'TAG_ARGS'])
            if len(tag)!=2 or tag[0]!='-T':raise ValueError('unsupported DIRS tags')
            add(values[name],{'type':'dir','mode':values[name+'_MODE'],'uname':values[name+'_OWN'],
                'gname':values[name+'_GRP'],'flags':values[name+'_FLAGS'],'tags':tag[1]},
                {'component':str(e.component),'extra':list(extra),'variable':name},phase,True)
    def debug_dirs(e,extra=()):
        values=query(e,['MK_DEBUG_FILES','DEBUGFILE','DEBUGFILEDIR','DEBUGDIR','DEBUGDIRMODE',
            'DEBUGDIROWN','DEBUGDIRGRP','DEBUGOWN','DEBUGGRP','TAG_ARGS'],extra)
        if values['MK_DEBUG_FILES']=='no' or not values['DEBUGFILE']:return
        if values['MK_DEBUG_FILES']!='yes':raise ValueError('unsupported debug policy')
        tag=shlex.split(values['TAG_ARGS'])
        if len(tag)!=2 or tag[0]!='-T':raise ValueError('unsupported debug tags')
        root=PurePosixPath(absolute(values['DEBUGDIR']));destination=PurePosixPath(absolute(values['DEBUGFILEDIR']))
        if not destination.is_relative_to(root) or destination==root:
            raise ValueError('nonstandard debug directory fallback lacks explicit mode policy')
        parents=[];current=destination
        while current!=root:parents.append(current);current=current.parent
        phase={}
        for directory in reversed(parents):
            add(str(directory),{'type':'dir','mode':values['DEBUGDIRMODE'],'uname':values['DEBUGDIROWN'],
                'gname':values['DEBUGDIRGRP'],'tags':tag[1]+',dbg'},
                {'component':str(e.component),'extra':list(extra),'policy':'bsd.debug.mk parent creation'},phase)
    if args.component_policy:
        for component in components:
            e=environment(src/component);component_dirs(e);debug_dirs(e)
    else:
        lib=environment(src/'lib/libmd');component_dirs(lib);debug_dirs(lib)
        test=environment(src/'lib/libmd/tests');component_dirs(test)
        progs=shlex.split(query(test,['PROGS'])['PROGS'])
        for program in progs:
            if not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',program):raise ValueError('invalid maintained PROG')
            extra=['PROG='+program];component_dirs(test,extra);debug_dirs(test,extra)
    if set(policy)!=required:raise ValueError('required directory missing maintained policy: '+str(sorted(required-set(policy))))
    actual={}
    # Each reference has its own distrib-dirs pass. Combine only ancestors
    # needed by that component so unrelated default directories cannot overwrite
    # another component's explicit directory policy.
    for index,reference in enumerate(references):
        needed=required
        if args.component_policy:
            needed={'/'}
            for destination in payload_policies[index]['payloads']:
                parent=PurePosixPath(destination).parent
                needed.update(str(p) for p in [parent,*parent.parents])
        for relative,attrs in records((reference/'METALOG').read_text()):
            name='/' if relative=='.' else '/'+relative[2:]
            if name in needed:
                if attrs.get('type')!='dir':raise ValueError('reference ancestor is not directory')
                actual[name]=normalize(attrs)
    if actual!=policy:
        raise ValueError('directory policy/reference mismatch: '+str({n:{'derived':policy.get(n),'reference':actual.get(n)} for n in required if policy.get(n)!=actual.get(n)}))
    for e in environments:e.verify()
    for e,binding,before in closures:
        if e.capture_closure(extra=binding)!=before:raise ValueError('Make directory closure changed')
    for name,expected in inputs.items():
        if digest(Path(name))!=expected:raise ValueError('directory input changed: '+name)
    output.mkdir(parents=True)
    result={'format':1,'status':'reconciled','directories':policy,'history':history,'input_sha256':inputs,
        'build_environment':[e.receipt() for e in environments],
        'make_closures':[{'component':str(e.component),'extra':binding,'sha256':before} for e,binding,before in closures],
        'queries':queries,'commands':commands,'reference':str(references[0]),'references':[str(p) for p in references],
        'scope':'required library/test payload ancestors derived from maintained mtree and Make metadata',
        'limitations':['Only plain mtree input filtering, named ownership and no file flags supported.',
            'Policy phase order follows maintained library then recursive tests installation; it is checked against actual Make stage.',
            'Directory payload staging/package creation is not executed here.']}
    (output/'inventory.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'directories':len(policy),'inventory':str(output/'inventory.json')}))

if __name__=='__main__':main()
