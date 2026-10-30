#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Stage explicit bootstrap ATF tools and emit native Bazel test targets."""
import hashlib, json, shutil, os, tempfile
from pathlib import Path

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def stage(workspace, inventory, config, src, environment):
    settings=json.loads(config.read_text())
    if (not isinstance(settings,dict) or set(settings)!={'format','receipt','libraries'}
            or type(settings['format']) is not int or settings['format']!=1
            or not isinstance(settings['receipt'],str)
            or not isinstance(settings['libraries'],list)
            or not all(isinstance(p,str) and Path(p).is_absolute() for p in settings['libraries'])
            or not Path(settings['receipt']).is_absolute()):
        raise ValueError('versioned explicit ATF runtime configuration required')
    receipt=Path(settings['receipt']).resolve(strict=True)
    libraries=[Path(p).resolve(strict=True) for p in settings['libraries']]
    sdk=(Path(environment['objtop'])/'tmp').resolve(strict=True)
    if not libraries or any(not p.is_relative_to(sdk) for p in libraries):
        raise ValueError('test libraries must come from the selected SDK')
    data=json.loads(inventory.read_text());runtime=json.loads(receipt.read_text())
    if runtime['status']!='passed' or data['status']!='exported':
        raise ValueError('verified tool build and test inventory required')
    if set(runtime['tools'])!={'atf-sh','atf-check','dirname','tr','diff'}:
        raise ValueError('explicit ATF tool closure required')
    if len(data['harness']['targets'])!=1:
        raise ValueError('one harness required for this component')
    inputs={str(receipt):sha(receipt),str(inventory):sha(inventory),str(config):sha(config),
        str(Path(__file__).resolve()):sha(Path(__file__)),
        str(Path(__file__).with_name('bsd_atf.bzl')):sha(Path(__file__).with_name('bsd_atf.bzl'))}
    for record in runtime['tools'].values():
        for key in ('objtop','target','profile_assignments'):
            if record['environment'][key]!=environment[key]:
                raise ValueError('ATF tool/target profile mismatch: '+key)
        inputs.update(record['configured_make_include_closure'])
        inputs.update(record['environment']['input_sha256'])
    inputs.update(data['implementation_sha256'])
    for closure in data['program_make_include_closures'].values():inputs.update(closure)
    inputs.update(runtime['inputs']);inputs.update(runtime['source_hashes'])
    for path,expected in inputs.items():
        if sha(Path(path))!=expected:raise ValueError('input changed: '+path)
    destination=workspace/'atf-runtime-inputs'
    if destination.is_symlink():
        raise ValueError('runtime staging directory cannot be a symlink')
    destination.mkdir(exist_ok=True)
    copies={}
    def copy(source,name):
        target=destination/name
        if target.is_symlink():
            raise ValueError('runtime output cannot be a symlink')
        fd,temporary=tempfile.mkstemp(prefix='.atf-copy-',dir=destination)
        os.close(fd)
        temporary=Path(temporary)
        try:
            shutil.copy2(source,temporary)
            if sha(temporary)!=inputs[str(source)]:
                raise ValueError('runtime input changed during copy: '+str(source))
            temporary.replace(target)
        finally:
            if temporary.exists():temporary.unlink()
        copies[str(target)]=inputs[str(source)]
    bins=['//toolchain:sh']
    for name,record in runtime['tools'].items():
        source=Path(record['binary'])
        if not record['static_elf'] or sha(source)!=record['sha256']:
            raise ValueError('static runtime tool changed: '+name)
        inputs[str(source)]=record['sha256']
        copy(source,name)
        bins.append('atf-runtime-inputs/'+name)
    for name,source in [('libatf-sh.subr',src/'contrib/atf/atf-sh/libatf-sh.subr'),('atf_runner.c',src/'tools/build/bazel/atf_runner.c')]:
        inputs[str(source)]=sha(source);copy(source,name)
    libs=[':md_runtime_install']
    reserved=set(runtime['tools'])|{'sh','libatf-sh.subr','atf_runner.c'}
    library_names=set()
    for source in libraries:
        source=source.resolve(strict=True)
        inputs[str(source)]=sha(source)
        if source.name in reserved or source.name in library_names:
            raise ValueError('runtime library name collision')
        library_names.add(source.name)
        copy(source,source.name);libs.append('atf-runtime-inputs/'+source.name)
    shutil.copyfile(Path(__file__).with_name('bsd_atf.bzl'),workspace/'bsd_atf.bzl')
    lines=['load(":bsd_atf.bzl", "bsd_atf_test")',
           'cc_binary(name="atf_test_runner", srcs=["atf-runtime-inputs/atf_runner.c"], linkstatic=True, features=["fully_static_link"])']
    harness=data['harness']['targets'][0]
    names=[]
    for driver,case in zip(data['drivers'],data['harness']['arguments'],strict=True):
        name='atf_'+case;names.append(':'+name)
        values={'name':name,'case_name':case,'body':':gen_'+harness['body_target'],
            'subr':'atf-runtime-inputs/libatf-sh.subr','data':[':'+driver['program']+'_install',driver['reference']],
            'runtime_bin':bins,'runtime_lib':libs,'runner':':atf_test_runner','size':'small'}
        lines.append('bsd_atf_test('+', '.join(k+'='+json.dumps(v) for k,v in values.items())+')')
    lines.append('test_suite(name="libmd_tests", tests='+json.dumps(names)+')')
    fragment='\n\n'.join(lines)+'\n'
    for path,expected in {**inputs,**copies}.items():
        if sha(Path(path))!=expected:raise ValueError('input changed before ATF graph publication: '+path)
    (workspace/'ATF.BUILD.fragment').write_text(fragment)
    (workspace/'atf-runtime-inputs.json').write_text(json.dumps({'inputs':inputs,'staged_inputs':copies,'scope':'explicit native ATF tools and libraries; host ELF interpreter and OS remain execution prerequisites'},indent=2)+'\n')
    return lines
