# SPDX-License-Identifier: BSD-2-Clause
"""Emit the maintained bzip2 sample cases as declared native Bazel tests."""
import json,shlex,shutil
import component_labels
import library_dependencies
from pathlib import Path
from libmd_environment import BuildEnvironment,digest

def emit(root,data,config_path,src):
    config=json.loads(config_path.read_text())
    if type(config.get('format')) is not int or config['format']!=1 or set(config)!={'format','suite','decoder-receipt','gzip-receipt','runtime-libraries'} or config['suite']!='bzip2':
        raise ValueError('explicit bzip2 test configuration format 1 required')
    records=[c for c in data['components'] if c['metadata']['PROG']=='bzip2']
    if len(records)!=1:raise ValueError('one selected bzip2 program required')
    record=records[0];envdata=data['build_environment']
    env=BuildEnvironment(src,Path(envdata['objtop']),Path(envdata['profile']),Path('/usr/bin/make'),src/record['component'])
    def query(names):
        lines=env.query([v for n in names for v in ('-v',n)]).splitlines()
        if len(lines)!=len(names):raise ValueError('ambiguous test metadata')
        return dict(zip(names,lines))
    base=query(['BZ2DIR','BZIP2_TEST_CASES']);cases=shlex.split(base['BZIP2_TEST_CASES'])
    if not cases or len(set(cases))!=len(cases) or any(Path(c).name!=c or c in ('.','..') for c in cases):raise ValueError('invalid maintained test cases')
    flags=query([k+c for c in cases for k in ('BZIP2_TEST_COMPRESS.','BZIP2_TEST_DECOMPRESS.')])
    fixture_dir=Path(base['BZ2DIR']).resolve(strict=True)
    if not fixture_dir.is_relative_to(src):raise ValueError('test fixtures outside source')
    inputs=dict(env.inputs);inputs.update(data['input_sha256'])
    inputs[str(config_path)]=digest(config_path)
    tools=root/'test-tools';tools.mkdir()
    for key,name in [('decoder-receipt','bintrans'),('gzip-receipt','gzip')]:
        receiptpath=Path(config[key]).resolve(strict=True);receipt=json.loads(receiptpath.read_text())
        if receipt['status']!='passed' or set(receipt['tools'])!={name}:raise ValueError('verified static fixture tool required')
        tool=receipt['tools'][name]
        if tool['static_elf'] is not True:raise ValueError('fixture tool must be static')
        for field in ('objtop','target','profile_assignments'):
            if tool['environment'][field]!=envdata[field]:raise ValueError('fixture tool environment differs')
        inputs.update(receipt['inputs']);inputs.update(receipt['source_hashes']);inputs.update(tool['environment']['input_sha256']);inputs.update(tool['configured_make_include_closure']);inputs[str(receiptpath)]=digest(receiptpath);inputs[tool['binary']]=tool['sha256']
        for p,h in inputs.items():
            if digest(Path(p))!=h:raise ValueError('test input changed: '+p)
        shutil.copyfile(tool['binary'],tools/name);(tools/name).chmod(0o755)
    runtime=[];sdk=(Path(envdata['objtop'])/'tmp').resolve(strict=True);libdir=root/'test-libraries';libdir.mkdir()
    for value in config['runtime-libraries']:
        p=Path(value).resolve(strict=True)
        if not p.is_relative_to(sdk):raise ValueError('test runtime outside selected SDK')
        target=libdir/p.name
        if target.exists():raise ValueError('duplicate runtime library name')
        inputs[str(p)]=digest(p);shutil.copyfile(p,target);runtime.append('test-libraries/'+p.name)
    if not runtime:raise ValueError('explicit runtime closure required')
    selected=shlex.split(record['metadata']['LIBADD'])
    if len(selected)!=1:raise ValueError('test adapter requires one declared library dependency')
    dependencies=library_dependencies.resolve_selections(record,data['components'])
    if len(dependencies)!=1:raise ValueError('one resolved bzip2 dependency required')
    runtime.append(component_labels.label(dependencies[0]['component'],dependencies[0]['library']+'_soname'))
    for name in ['byte_compare_runner.c','bsd_compare_test.bzl']:
        p=Path(__file__).with_name(name);inputs[str(p)]=digest(p);shutil.copyfile(p,root/name)
    inputs[str(Path(__file__))]=digest(Path(__file__))
    lines=['load(":bsd_compare_test.bzl", "bsd_compare_test", "bsd_filter_fixture")']
    def rule(kind,**values):lines.append(kind+'('+', '.join(k+'='+repr(v) for k,v in values.items())+')')
    rule('cc_binary',name='byte_compare_runner',srcs=['byte_compare_runner.c'],linkstatic=True,features=['fully_static_link'])
    for case in cases:
        for suffix in ('.ref.gz.uu','.bz2.uu'):
            p=fixture_dir/(case+suffix);inputs[str(p)]=digest(p);target=root/'test-fixtures'/p.name;target.parent.mkdir(exist_ok=True);shutil.copyfile(p,target)
        rule('bsd_filter_fixture',name=case+'_raw_gzip',src='test-fixtures/'+case+'.ref.gz.uu',output='fixtures/'+case+'.ref.gz',tool='test-tools/bintrans',arguments=['uudecode','-p'],redirect='//toolchain:stdout_redirect')
        rule('bsd_filter_fixture',name=case+'_raw',src=':'+case+'_raw_gzip',output='fixtures/'+case+'.ref',tool='test-tools/gzip',arguments=['-dc'],redirect='//toolchain:stdout_redirect')
        rule('bsd_filter_fixture',name=case+'_compressed',src='test-fixtures/'+case+'.bz2.uu',output='fixtures/'+case+'.bz2',tool='test-tools/bintrans',arguments=['uudecode','-p'],redirect='//toolchain:stdout_redirect')
        for direction,left,right,prefix in [('compress','raw','compressed','BZIP2_TEST_COMPRESS.'),('decompress','compressed','raw','BZIP2_TEST_DECOMPRESS.')]:
            arguments=shlex.split(flags[prefix+case])
            if not arguments:raise ValueError('missing maintained test arguments')
            rule('bsd_compare_test',name=case+'_'+direction,program=component_labels.label(record,'bzip2'),input=':'+case+'_'+left,expected=':'+case+'_'+right,arguments=arguments,runtime_lib=runtime,runner=':byte_compare_runner')
    env.verify()
    for p,h in inputs.items():
        if digest(Path(p))!=h:raise ValueError('test input changed during emission: '+p)
    (root/'bzip2-test-inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    (root/'native-test-inventory.json').write_text(json.dumps({'labels':['//:'+case+'_'+direction for case in cases for direction in ('compress','decompress')]},indent=2)+'\n')
    return lines
