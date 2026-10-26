# SPDX-License-Identifier: BSD-2-Clause
"""Bind configuration queries to a maintained world build environment."""
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def profile_assignments(path):
    values = {}
    for line in path.read_text().splitlines():
        if not re.fullmatch(r'[A-Z][A-Z_0-9]*=[A-Za-z0-9_.+-]+', line):
            raise ValueError('unsupported recorded profile assignment: ' + line)
        key, value = line.split('=', 1)
        if key in values:
            raise ValueError('duplicate profile assignment: ' + key)
        values[key] = value
    if values.get('TARGET') != 'amd64' or values.get('TARGET_ARCH') != 'amd64':
        raise ValueError('only matching native amd64 world profile supported')
    return values


class BuildEnvironment:
    def __init__(self, src, objtop, profile, make, component=None):
        self.src, self.objtop = src.resolve(strict=True), objtop.resolve(strict=True)
        self.component = (component or (self.src / 'lib/libmd')).resolve(strict=True)
        self.make = make.resolve(strict=True)
        self.profile = profile.resolve(strict=True)
        if not self.objtop.is_relative_to('/usr/obj'):
            raise ValueError('objtop must use /usr/obj')
        recorded = self.objtop / '.src_opts'
        if digest(self.profile) != digest(recorded):
            raise ValueError('explicit profile differs from selected world .src_opts')
        self.assignments = profile_assignments(self.profile)
        self.env = {'PATH':'/bin:/usr/bin:/usr/local/bin', 'HOME':os.environ['HOME'],
                    'MAKEOBJDIRPREFIX':'/usr/obj', 'LC_ALL':'C'}
        self.fixed = ['SRCCONF=/dev/null', '__MAKE_CONF=/dev/null', 'SRC_ENV_CONF=/dev/null']
        self.options = [k+'='+v for k,v in self.assignments.items()]
        self.inputs = {str(p):digest(p) for p in [self.make,self.profile,recorded,
            self.src/'Makefile',self.src/'Makefile.inc1']}
        self.commands = []
        identity = self.query(['-V','OBJTOP','-V','MACHINE','-V','MACHINE_ARCH','-V','${CC}','-V','PATH'], component=self.src/'lib/libmd', bind_objtop=False)
        rows = identity.splitlines()
        if len(rows)!=5 or rows[:3] != [str(self.objtop),'amd64','amd64']:
            raise ValueError('buildenv identity differs from explicit objtop/architecture')
        self.cc = shlex.split(rows[3])
        if '--sysroot='+str(self.objtop/'tmp') not in self.cc:
            raise ValueError('buildenv compiler is not bound to selected staged sysroot')
        self.compiler = self.objtop/'tmp/usr/bin/clang'
        selected = shutil.which(self.cc[0], path=rows[4])
        if not selected or Path(selected).resolve(strict=True) != self.compiler.resolve(strict=True):
            raise ValueError('buildenv compiler executable differs from selected staged clang')
        self.compiler_selected = selected
        self.inputs[str(self.compiler)] = digest(self.compiler)
        target = subprocess.check_output([str(self.compiler),'-dumpmachine'],env=self.env,text=True).strip()
        if not re.fullmatch(r'x86_64-unknown-freebsd[0-9]+(?:\.[0-9]+)*',target):
            raise ValueError('staged compiler target does not match amd64 world')
        resource = Path(subprocess.check_output([str(self.compiler),'-print-resource-dir'],env=self.env,text=True).strip()).resolve(strict=True)
        if resource.parent != (self.objtop/'tmp/usr/lib/clang').resolve(strict=True):
            raise ValueError('staged compiler resource directory escapes selected world')
        self.target,self.resource = target,str(resource)
        self.closure = self.capture_closure()
        self.inputs.update(self.closure)

    def query(self, args, obj=None, extra=(), component=None, bind_objtop=True):
        # bmake -v expands in the nested make, avoiding recursive dollar expansion.
        args = ['-v' if x == '-V' else x[2:-1] if x.startswith('${') and x.endswith('}') else x for x in args]
        bindings = ['SRCTOP='+str(self.src),'OBJTOP='+str(self.objtop)] if bind_objtop else []
        inner = [str(self.make),'-C',str(component or self.component),*self.fixed,*self.options,*bindings,*extra,*args]
        if obj is not None:
            inner = ['/usr/bin/env','MAKEOBJDIR='+str(obj),*inner]
        outer = [str(self.make),'-C',str(self.src),*self.fixed,*self.options,
                 'buildenv','BUILDENV_SHELL='+shlex.join(inner)]
        done = subprocess.run(outer,env=self.env,capture_output=True,text=True)
        self.commands.append({'argv':outer,'status':done.returncode,'stderr':done.stderr})
        if done.returncode:
            raise ValueError('buildenv query failed: '+done.stderr+done.stdout)
        first,separator,output=done.stdout.partition('\n')
        if not separator or first!='Entering world for amd64:amd64':
            raise ValueError('ambiguous buildenv output')
        return output

    def capture_closure(self, obj=None, extra=()):
        values=self.query(['-V','${.MAKE.MAKEFILES}'], obj=obj, extra=extra).strip()
        paths=[]
        for value in shlex.split(values):
            p=Path(value)
            if not p.is_absolute():p=self.component/p
            p=p.resolve(strict=True)
            if p != Path('/dev/null'):
                paths.append(p)
        # The outer traversal defines buildenv; bind its includes independently.
        command=[str(self.make),'-C',str(self.src),*self.fixed,*self.options,'-V','${.MAKE.MAKEFILES}']
        for value in shlex.split(subprocess.check_output(command,env=self.env,text=True)):
            p=Path(value)
            if not p.is_absolute():p=self.src/p
            p=p.resolve(strict=True)
            if p!=Path('/dev/null'):paths.append(p)
        closure={str(p):digest(p) for p in sorted(set(paths))}
        return closure

    def verify(self):
        if self.capture_closure()!=self.closure:
            raise ValueError('Make include closure changed during export')
        for p,expected in self.inputs.items():
            if digest(Path(p))!=expected:
                raise ValueError('build input changed during export: '+p)

    def receipt(self):
        return {'component':str(self.component),'objtop':str(self.objtop),'profile':str(self.profile),
                'profile_assignments':self.assignments,'configuration':self.fixed,
                'compiler_command':self.cc,'compiler_selected':self.compiler_selected,'target':self.target,'compiler_resource':self.resource,
                'input_sha256':self.inputs,'make_include_closure':self.closure,'commands':self.commands}
