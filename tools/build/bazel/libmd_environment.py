# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Bind configuration queries to a maintained world build environment."""
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import threading


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def profile_assignments(path, target_architecture="amd64"):
    values = {}
    for line in path.read_text().splitlines():
        if not re.fullmatch(r'[A-Z][A-Z_0-9]*=[A-Za-z0-9_.+-]+', line):
            raise ValueError('unsupported recorded profile assignment: ' + line)
        key, value = line.split('=', 1)
        if key in values:
            raise ValueError('duplicate profile assignment: ' + key)
        values[key] = value
    pairs = {'amd64': ('amd64', 'amd64'), 'aarch64': ('arm64', 'aarch64'), 'riscv64': ('riscv', 'riscv64')}
    if target_architecture not in pairs or (values.get('TARGET'), values.get('TARGET_ARCH')) != pairs[target_architecture]:
        raise ValueError('recorded world profile differs from explicitly selected architecture')
    return values


def same_executable(path, expected):
    """Accept symlink and hardlink aliases of the selected compiler file."""
    try:
        return os.path.samefile(path, expected)
    except OSError:
        return False


def bind_inputs(bindings, incoming):
    """Reject an input that changes between world-environment queries."""
    for name, value in incoming.items():
        if name in bindings and bindings[name] != value:
            raise ValueError('world input changed during export: ' + name)
    bindings.update(incoming)


def world_compiler_identity(selected, staged, using_system, resource, metadata):
    """Accept a staged compiler or Make's explicitly selected system compiler."""
    selected, staged, resource = Path(selected), Path(staged), Path(resource)
    if not resource.is_dir() or not (resource / 'include').is_dir():
        raise ValueError('compiler resource directory must contain builtin headers')
    if same_executable(selected, staged):
        if resource.parent != (staged.parent.parent / 'lib/clang').resolve(strict=True):
            raise ValueError('staged compiler resource directory escapes selected world')
        return 'staged', staged
    if using_system != 'yes':
        raise ValueError('compiler outside staged world requires Make SYSTEM_COMPILER selection')
    selected = selected.resolve(strict=True)
    if not same_executable(selected, selected.parent / 'clang'):
        raise ValueError('selected system compiler must be the declared Clang executable')
    if (metadata.get('X_COMPILER_TYPE') != 'clang' or
            metadata.get('X_COMPILER_RESOURCE_DIR') != str(resource)):
        raise ValueError('system compiler differs from recorded world toolchain metadata')
    return 'system', selected.resolve(strict=True)


def system_compiler_version(macros, metadata):
    try:
        version = sum(int(macros[name]) * weight for name,weight in
                      [('__clang_major__',10000),('__clang_minor__',100),('__clang_patchlevel__',1)])
        freebsd = macros.get('__FreeBSD_cc_version', '0')
        if (str(version) != metadata.get('X_COMPILER_VERSION') or
                freebsd != metadata.get('X_COMPILER_FREEBSD_VERSION')):
            raise ValueError('system compiler version differs from recorded world')
    except (KeyError, TypeError) as error:
        raise ValueError('system compiler version macros are incomplete') from error
    return {'clang':version, 'freebsd':freebsd}


def compiler_metadata(path):
    """Read literal compiler identities emitted by toolchain-metadata.mk."""
    values = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r'(X_COMPILER_[A-Z_]+)=(.*)', line)
        if match:
            if match[1] in values:
                raise ValueError('duplicate recorded compiler identity')
            values[match[1]] = match[2]
    return values


class BuildEnvironment:
    def __init__(self, src, objtop, profile, make, component=None, target_architecture="amd64"):
        self.src, self.objtop = src.resolve(strict=True), objtop.resolve(strict=True)
        self.component = (component or (self.src / 'lib/libmd')).resolve(strict=True)
        self.make = make.resolve(strict=True)
        self.profile = profile.resolve(strict=True)
        if not self.objtop.is_relative_to('/usr/obj'):
            raise ValueError('objtop must use /usr/obj')
        recorded = self.objtop / '.src_opts'
        if digest(self.profile) != digest(recorded):
            raise ValueError('explicit profile differs from selected world .src_opts')
        self.assignments = profile_assignments(self.profile, target_architecture)
        self.env = {'PATH':'/bin:/usr/bin:/usr/local/bin', 'HOME':os.environ['HOME'],
                    'MAKEOBJDIRPREFIX':'/usr/obj', 'LC_ALL':'C'}
        self.fixed = ['SRCCONF=/dev/null', '__MAKE_CONF=/dev/null', 'SRC_ENV_CONF=/dev/null']
        self.options = [k+'='+v for k,v in self.assignments.items()]
        self.inputs = {str(p):digest(p) for p in [self.make,self.profile,recorded,
            self.src/'Makefile',self.src/'Makefile.inc1',Path(__file__).resolve()]}
        self.commands = []
        self._commands_lock = threading.Lock()
        identity = self.query(['-V','OBJTOP','-V','MACHINE','-V','MACHINE_ARCH','-V','${CC}','-V','PATH'], component=self.src/'lib/libmd', bind_objtop=False)
        rows = identity.splitlines()
        if len(rows)!=5 or rows[:3] != [str(self.objtop),self.assignments['TARGET'],self.assignments['TARGET_ARCH']]:
            raise ValueError('buildenv identity differs from explicit objtop/architecture')
        self.cc = shlex.split(rows[3])
        if '--sysroot='+str(self.objtop/'tmp') not in self.cc:
            raise ValueError('buildenv compiler is not bound to selected staged sysroot')
        staged = self.objtop/'tmp/usr/bin/clang'
        selected = shutil.which(self.cc[0], path=rows[4])
        if not selected:
            raise ValueError('world compiler command is not executable in its recorded PATH')
        selected = Path(selected)
        resource = Path(subprocess.check_output([str(selected),*self.cc[1:],'-print-resource-dir'],env=self.env,text=True).strip()).resolve(strict=True)
        using_system, metadata = 'no', {}
        if not same_executable(selected, staged):
            argv = [str(self.make), '-C', str(self.src), '-f', 'Makefile.inc1',
                    *self.fixed, *self.options, '-V', '${USING_SYSTEM_COMPILER}']
            done = subprocess.run(argv, env=self.env, capture_output=True, text=True)
            self.commands.append({'argv':argv, 'status':done.returncode, 'stderr':done.stderr})
            if done.returncode or done.stdout.strip() not in ('yes', 'no'):
                raise ValueError('unambiguous Make compiler selection required')
            using_system = done.stdout.strip()
            metadata_path = self.objtop/'toolchain-metadata.mk'
            self.inputs[str(metadata_path)] = digest(metadata_path)
            metadata = compiler_metadata(metadata_path)
        self.compiler_mode, self.compiler = world_compiler_identity(
            selected, staged, using_system, resource, metadata)
        self.compiler_selected = str(selected)
        self.inputs[str(self.compiler)] = digest(self.compiler)
        target = subprocess.check_output([str(self.compiler),*self.cc[1:],'-dumpmachine'],env=self.env,text=True).strip()
        expected = {'amd64': 'x86_64', 'aarch64': 'aarch64', 'riscv64': 'riscv64'}[self.assignments['TARGET_ARCH']]
        if not re.fullmatch(expected + r'-unknown-freebsd[0-9]+(?:\.[0-9]+)*',target):
            raise ValueError('compiler command target differs from selected world')
        if self.compiler_mode == 'system':
            output = subprocess.check_output([str(self.compiler),*self.cc[1:],'-dM','-E','-x','c','/dev/null'],env=self.env,text=True)
            macros = dict(re.findall(r'^#define (__clang_(?:major|minor|patchlevel)__|__FreeBSD_cc_version) ([0-9]+)$', output, re.M))
            self.system_compiler_version = system_compiler_version(macros, metadata)
        self.target,self.resource = target,str(resource)
        self.sdk_resource = self.objtop/'tmp/usr/lib/clang'/resource.name
        if not (self.sdk_resource/'include').is_dir():
            raise ValueError('selected world lacks matching SDK compiler resource headers')
        self.closure = self.capture_closure()
        bind_inputs(self.inputs, self.closure)

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
        with self._commands_lock:
            self.commands.append({'argv':outer,'status':done.returncode,'stderr':done.stderr})
        if done.returncode:
            raise ValueError('buildenv query failed: '+done.stderr+done.stdout)
        first,separator,output=done.stdout.partition('\n')
        if not separator or first!='Entering world for '+self.assignments['TARGET_ARCH']+':'+self.assignments['TARGET']:
            raise ValueError('ambiguous buildenv output: '+repr(done.stdout))
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
                'compiler_command':self.cc,'compiler_selected':self.compiler_selected,'compiler_executable':str(self.compiler),'compiler_mode':self.compiler_mode,
                'target':self.target,'compiler_resource':self.resource,
                'sdk_compiler_resource':str(self.sdk_resource),'system_compiler_version':getattr(self, 'system_compiler_version', None),
                'input_sha256':self.inputs,'make_include_closure':self.closure,'commands':self.commands}
