#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Build explicitly selected native amd64 execution tools with maintained Make."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked_path(value, existing=True):
    if not value.is_absolute() or any(ord(c)<32 or c=='$' for c in str(value)):
        raise ValueError('absolute paths without control characters or Make expansion required')
    return value.resolve(strict=existing)


def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate JSON key: '+key)
        result[key]=value
    return result


def relative(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_.+/-]+',value):
        raise ValueError('invalid component/binary path')
    path=PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or not path.parts or str(path)!=value:
        raise ValueError('component/binary must be normalized relative paths')
    return path


def selection(config,src):
    data=json.loads(config.read_text(),object_pairs_hook=unique_object)
    if set(data)!={'format','tools'} or type(data['format']) is not int or data['format']!=1 or not isinstance(data['tools'],dict) or not data['tools']:
        raise ValueError('format1 nonempty tools mapping required')
    result={}
    for name,entry in data['tools'].items():
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*',name) or not isinstance(entry,dict) or set(entry)!={'component','binary'}:
            raise ValueError('invalid tool mapping')
        component=(src/relative(entry['component'])).resolve(strict=True)
        binary=relative(entry['binary'])
        if component==src or not component.is_relative_to(src) or not (component/'Makefile').is_file():
            raise ValueError('tool component must be a maintained source directory')
        result[name]=(component,binary)
    return result


def output_path(value,src,objtop):
    output=checked_path(value,False)
    if value.is_symlink() or output.exists() or output==Path('/usr/obj') or not output.is_relative_to('/usr/obj') or output.is_relative_to(src) or src.is_relative_to(output) or output==objtop or objtop.is_relative_to(output) or output.is_relative_to(objtop/'tmp'):
        raise ValueError('output must be fresh below /usr/obj and separate from source and SDK')
    return output


def static_elf(binary,readelf):
    with binary.open('rb') as stream:
        header=stream.read(20)
        if header[:4]!=b'\x7fELF':raise ValueError('output is not ELF: '+str(binary))
        if len(header)!=20 or header[4:6]!=bytes((2,1)) or int.from_bytes(header[18:20],'little')!=62:
            raise ValueError('output is not native amd64 ELF64')
    command=[str(readelf),'-h','-l','-d',str(binary)]
    result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    if result.returncode:raise ValueError('readelf failed: '+result.stderr)
    if not re.search(r'Type:\s+(?:EXEC|DYN)\b',result.stdout) or re.search(r'\b(?:INTERP|NEEDED)\b',result.stdout):
        raise ValueError('output is not an ELF executable without PT_INTERP/DT_NEEDED')
    if not os.access(binary,os.X_OK):raise ValueError('output is not executable')
    return {'argv':command,'status':result.returncode,'stdout':result.stdout,'stderr':result.stderr}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('src','objtop','profile','output','tools'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--jobs',type=int,required=True)
    parser.add_argument('--make',type=Path,default=Path('/usr/bin/make'))
    parser.add_argument('--readelf',type=Path,default=Path('/usr/bin/readelf'))
    args=parser.parse_args()
    if args.jobs<1:parser.error('--jobs must be positive')
    src,objtop,profile,config,make,readelf=[checked_path(p) for p in (args.src,args.objtop,args.profile,args.tools,args.make,args.readelf)]
    output=output_path(args.output,src,objtop);tools=selection(config,src)
    environment_path=src/'tools/build/bazel/libmd_environment.py'
    environment_hash=sha(environment_path)
    spec=importlib.util.spec_from_file_location('maintained_environment',environment_path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    inputs={str(p):sha(p) for p in (Path(__file__).resolve(),config,readelf)}
    inputs[str(environment_path)]=environment_hash
    environments={name:module.BuildEnvironment(src,objtop,profile,make,component) for name,(component,binary) in tools.items()}
    source_hashes={str(p):sha(p) for component,_ in tools.values() for p in component.rglob('*') if p.is_file()}
    output.mkdir(parents=True,exist_ok=False)
    receipt={'format':1,'status':'running','scope':'maintained native-amd64 Make static execution-tool builds','jobs':args.jobs,'inputs':inputs,'source_hashes':source_hashes,'tools':{},'commands':[],
        'limitations':['Selected component source and Make include closures are checked; this is not a full hermetic source, SDK or execution-tool closure.','Uses an existing Make-built SDK and host build tools.','Static ELF inspection does not qualify execution on another kernel or guest.'],
        'host_installed':False,'guest_execution_qualified':False,'bazel_qualified':False}
    try:
        for name,(component,binary_name) in tools.items():
            environment=environments[name];private=output/name;private.mkdir();objects=private/'objects';objects.mkdir()
            component_objects=objects/str(component).lstrip('/');component_objects.mkdir(parents=True)
            static_options=['NO_SHARED=yes','WITHOUT_TESTS=yes']
            configured_closure=environment.capture_closure(obj=component_objects,extra=static_options)
            env=dict(environment.env);env.update(STATIC_OBJROOT=str(objects),MAKEOBJDIR='${STATIC_OBJROOT}${.CURDIR}')
            inner=[str(make),'-C',str(component),*environment.fixed,*environment.options,*static_options,'-j'+str(args.jobs),'all']
            command=[str(make),'-C',str(src),*environment.fixed,*environment.options,'buildenv','BUILDENV_SHELL='+shlex.join(inner)]
            log=private/'build.log'
            with log.open('w') as stream:result=subprocess.run(command,env=env,stdout=stream,stderr=subprocess.STDOUT)
            receipt['commands'].append({'argv':command,'environment_overrides':{'STATIC_OBJROOT':str(objects),'MAKEOBJDIR':env['MAKEOBJDIR']},'status':result.returncode,'log':str(log),'log_sha256':sha(log)})
            if result.returncode:raise RuntimeError('Make build failed: '+name)
            binary=(objects/str(component).lstrip('/')/binary_name).resolve(strict=True)
            if not binary.is_relative_to(objects):raise ValueError('binary escapes private objects')
            inspection=static_elf(binary,readelf)
            if environment.capture_closure(obj=component_objects,extra=static_options)!=configured_closure:
                raise ValueError('configured static Make include closure changed: '+name)
            environment.verify()
            receipt['tools'][name]={'component':str(component),'binary':str(binary),'sha256':sha(binary),'bytes':binary.stat().st_size,'static_elf':True,'static_options':static_options,'component_objects':str(component_objects),'configured_make_include_closure':configured_closure,'inspection':inspection,'environment':environment.receipt()}
            (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        if {str(p):sha(p) for component,_ in tools.values() for p in component.rglob('*') if p.is_file()}!=source_hashes:
            raise ValueError('selected component sources changed during build')
        for path,digest in inputs.items():
            if sha(Path(path))!=digest:raise ValueError('builder/configuration input changed: '+path)
        for environment in environments.values():environment.verify()
        for name,record in receipt['tools'].items():
            if environments[name].capture_closure(obj=Path(record['component_objects']),extra=record['static_options'])!=record['configured_make_include_closure']:
                raise ValueError('configured Make inputs changed before completion: '+name)
            if sha(Path(record['binary']))!=record['sha256']:raise ValueError('output changed during build')
        receipt.update(status='passed',inputs_rechecked=True)
    except Exception as error:
        receipt.update(status='failed',error=str(error));raise
    finally:
        (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(output/'receipt.json')

if __name__=='__main__':main()
