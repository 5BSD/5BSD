#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Export the complete libmd test file payload policy; directory policy is separate."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import shlex
from libmd_environment import BuildEnvironment, digest


def export(inventory, output):
    data = json.loads(inventory.read_text())
    if data.get('status') != 'exported':
        raise ValueError('completed test input inventory required')
    inputs = dict(data['implementation_sha256'])
    inputs.update(data['build_environment']['input_sha256'])
    for closure in data['program_make_include_closures'].values():
        inputs.update(closure)
    inputs[str(inventory)] = digest(inventory)
    inputs[str(Path(__file__).resolve())] = digest(Path(__file__))
    for path, expected in inputs.items():
        if digest(Path(path)) != expected:
            raise ValueError('input changed: ' + path)
    env = data['build_environment']
    src = Path(env['component']).parents[2]
    obj = Path(env['objtop'])
    e = BuildEnvironment(src, obj, Path(env['profile']), Path('/usr/bin/make'), src/'lib/libmd/tests')
    def query(keys, program=None):
        extra = ['NO_ROOT=yes', 'DB_FROM_SRC=yes', 'BUILD_PKGS=yes', 'DESTDIR=']
        if program:
            extra.append('PROG=' + program)
        rows = e.query([x for k in keys for x in ('-V', k)], extra=extra).splitlines()
        if len(rows) != len(keys):
            raise ValueError('ambiguous installation metadata')
        return dict(zip(keys, rows))
    base = query(['PROGS','SCRIPTS','FILESGROUPS','LINKS','SYMLINKS','KYUAFILE','TESTSUITE','_TESTS','TESTS_SUBDIRS','TAGS'])
    if base['LINKS'].strip() or base['SYMLINKS'].strip():
        raise ValueError('test links require explicit manifest support')
    if shlex.split(base['PROGS']) != [d['program'] for d in data['drivers']]:
        raise ValueError('driver inventory changed')
    entries, paths = [], set()
    def add(label, directory, name, owner, group, mode, tags):
        directory = PurePosixPath(directory)
        if not directory.is_absolute() or '..' in directory.parts or not re.fullmatch(r'[A-Za-z0-9_.+-]+', name):
            raise ValueError('unsafe installation destination')
        destination = str(directory/name)
        if destination in paths:
            raise ValueError('duplicate installation destination: ' + destination)
        if not re.fullmatch(r'[0-7]{3,4}', mode):
            raise ValueError('invalid installation mode')
        if not all(re.fullmatch(r'[A-Za-z0-9_.+-]+', value) for value in (owner, group)):
            raise ValueError('invalid ownership')
        taglist = shlex.split(tags)
        if len([t for t in taglist if t.startswith('package=')]) != 1:
            raise ValueError('exactly one package tag required')
        paths.add(destination)
        entries.append(dict(label=label, destination=destination, owner=owner, group=group, mode=format(int(mode,8),'04o'), tags=taglist))
    for d in data['drivers']:
        name = d['program']
        keys=['BINDIR','PROGNAME','BINOWN','BINGRP','BINMODE','TAGS','DEBUGFILEDIR','DEBUGFILE','DEBUGOWN','DEBUGGRP','DEBUGMODE','MK_DEBUG_FILES','_INSTALLFLAGS']
        v=query(keys,name)
        if v['_INSTALLFLAGS'].strip():
            raise ValueError('additional install flags require explicit support')
        add(':'+name+'_install',v['BINDIR'],v['PROGNAME'],v['BINOWN'],v['BINGRP'],v['BINMODE'],v['TAGS'])
        if v['MK_DEBUG_FILES']=='yes':
            add(':'+name+'_debug',v['DEBUGFILEDIR'],v['DEBUGFILE'],v['DEBUGOWN'],v['DEBUGGRP'],v['DEBUGMODE'],v['TAGS']+' dbg')
    if shlex.split(base['SCRIPTS']) != [t['target'] for t in data['harness']['targets']]:
        raise ValueError('script inventory changed')
    for name in shlex.split(base['SCRIPTS']):
        keys=[k+'_'+name for k in ('SCRIPTSDIR','SCRIPTSNAME','SCRIPTSOWN','SCRIPTSGRP','SCRIPTSMODE')]
        v=query(keys)
        add(':'+name,*(v[k] for k in keys),base['TAGS'])
    known = {Path(d['reference']).name:d['reference'] for d in data['drivers']}
    known['Kyuafile']=':test_kyuafile'
    seen=set()
    for group in shlex.split(base['FILESGROUPS']):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',group):
            raise ValueError('unsupported files group')
        v=query([group,group+'TAGS'])
        for name in shlex.split(v[group]):
            if name not in known or name in seen:
                raise ValueError('unmapped or duplicate package file: '+name)
            seen.add(name)
            keys=[group+k+'_'+name for k in ('PREFIX','NAME','OWN','GRP','MODE')]
            f=query(keys)
            add(known[name],*(f[k] for k in keys),v[group+'TAGS'])
    if seen != set(known):
        raise ValueError('reference/Kyuafile payload inventory differs')
    if base['KYUAFILE'].lower()!='auto' or base['TESTS_SUBDIRS'].strip():
        raise ValueError('explicit Kyuafile or recursive suites require support')
    tests=[]
    for name in shlex.split(base['_TESTS']):
        v=query(['TEST_INTERFACE.'+name,'_TEST_METADATA.'+name])
        if v['_TEST_METADATA.'+name].strip():
            raise ValueError('Kyua test metadata requires explicit support')
        interface=v['TEST_INTERFACE.'+name]
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',interface):
            raise ValueError('invalid test interface')
        tests.append({'name':name,'interface':interface})
    e.verify()
    for path, expected in inputs.items():
        if digest(Path(path))!=expected:
            raise ValueError('input changed during export: '+path)
    receipt={'status':'exported','scope':'libmd test file payload; directory metadata and library payload remain separate', 'files':entries,'kyua':{'suite':base['TESTSUITE'],'tests':tests},'input_sha256':inputs,'environment':e.receipt()}
    output.write_text(json.dumps(receipt,indent=2)+'\n')
    print('Exported',len(entries),'file records to',output)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists() or not a.output.resolve().is_relative_to('/usr/obj'):
        p.error('fresh output under /usr/obj required')
    export(a.inventory.resolve(strict=True),a.output)
