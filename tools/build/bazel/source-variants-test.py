#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Build and inspect source membership in native regular, PIC and PIE archives.

Uses an explicit qualified workspace's toolchain/module inputs and build command.
This is a rule fixture, not evidence that a base component has been converted.
"""
import argparse,json,os,shutil,subprocess
from pathlib import Path
from libmd_environment import digest
from compile_context import compile_flags

p=argparse.ArgumentParser(description=__doc__)
for key in ('workspace','command-log','java-home','output'):
    p.add_argument('--'+key,type=Path,required=True)
p.add_argument('--nossp-context',type=Path,action='append',default=[])
a=p.parse_args();origin=a.workspace.resolve(strict=True);out=a.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj') or out==Path('/usr/obj') or origin.is_relative_to(out):
    raise ValueError('fresh nonoverlapping output below /usr/obj required')
commands=json.loads(a.command_log.read_text());argv=next(c['argv'] for c in commands if c['name']=='bazel-test')
if argv[-1]!='//...' or '--repository_disable_download' not in argv or '--ignore_all_rc_files' not in argv:
    raise ValueError('explicit offline native test command required')
out.mkdir();w=out/'workspace';w.mkdir()
shutil.copytree(origin/'toolchain',w/'toolchain',symlinks=True)
for name in ('MODULE.bazel','MODULE.bazel.lock'):shutil.copyfile(origin/name,w/name)
inputs={}
for name in ('native_cc.bzl','bsd_dtrace.bzl','bsd_fidl.bzl','source_identity.bzl'):
    src=Path(__file__).with_name(name);inputs[str(src)]=digest(src);shutil.copyfile(src,w/name)
(w/'common.c').write_text('int common(void) { return 1; }\n')
(w/'regular.c').write_text('#ifdef PIC\n#error regular source compiled with PIC\n#endif\nint selected(void) { return 2; }\n')
(w/'pic.c').write_text('#ifndef PIC\n#error PIC source compiled without PIC\n#endif\nint selected(void) { return 3; }\n')
(w/'pie.c').write_text('int selected(void) { return 4; }\n')
(w/'check.c').write_text('int common(void); int selected(void); int main(void) { return common()!=1 || selected()!=EXPECTED; }\n')
common=dict(srcs=['generated/common_alias.c','regular.c','pic.c','pie.c'],arflags=['-crsD'],archive_inputs='//toolchain:archive_inputs',variants=['regular','pic','pie'],variant_flags={'pic':['-fpic','-DPIC'],'pie':['-fpie','-DPIC']},source_variants={'generated/common_alias.c':['regular','pic','pie'],'regular.c':['regular'],'pic.c':['pic'],'pie.c':['pie']})
common['archive_member_order']={'regular':['regular.o','common_alias.o'],'pic':['pic.pic.o','common_alias.pic.o'],'pie':['pie.o','common_alias.o']}
def rule(kind,**attrs):return kind+'('+', '.join(k+'='+repr(v) for k,v in attrs.items())+')'
lines=['load(":native_cc.bzl", "bsd_library", "bsd_source_alias")','load("@rules_cc//cc:defs.bzl", "cc_import", "cc_test")',rule('bsd_source_alias',name='common_alias',source='common.c',output='generated/common_alias.c'),rule('bsd_library',name='membership',**common)]
for variant,value in (('regular',2),('pic',3),('pie',4)):
    label=':membership'
    if variant!='regular':
        lines.append(rule('filegroup',name=variant,srcs=[label],output_group=variant+'_archive'));label=':'+variant
    lines.append(rule('cc_import',name=variant+'_link',static_library=label))
    lines.append(rule('cc_test',name=variant+'_test',srcs=['check.c'],copts=['-DEXPECTED='+str(value)],deps=[':'+variant+'_link'],size='small'))
for name,mapping in [('missing',{'common.c':['regular']}),('unknown',dict(common['source_variants'],**{'pic.c':['other']})),('duplicate',dict(common['source_variants'],**{'pic.c':['pic','pic']})),('empty',dict(common['source_variants'],**{'pic.c':[]}))]:
    attrs=dict(common,source_variants=mapping,tags=['manual']);lines.append(rule('bsd_library',name='bad_'+name,**attrs))
for name,orders in [('missing',{'regular':['regular.o','common_alias.o']}),('duplicate',dict(common['archive_member_order'],regular=['regular.o','regular.o'])),('unaccounted',dict(common['archive_member_order'],regular=['regular.o','other.o']))]:
    attrs=dict(common,archive_member_order=orders,tags=['manual']);lines.append(rule('bsd_library',name='bad_order_'+name,**attrs))
nossp_contexts={}
if a.nossp_context:
    for path in a.nossp_context:
        receipt=json.loads(path.read_text())
        if receipt['status']!='passed' or len(receipt['cases'])!=1:raise ValueError('one verified context per language required')
        context=receipt['cases'][0]['context'];language=context['language']
        if language in nossp_contexts:raise ValueError('duplicate NOSSP language')
        nossp_contexts[language]=context;inputs[str(path.resolve())]=digest(path)
    if set(nossp_contexts)!={'c','c++','assembler-with-cpp'}:raise ValueError('C, C++ and assembly contexts required')
    guard='#if defined(__SSP__) || defined(__SSP_ALL__) || defined(__SSP_STRONG__)\n#error unexpected stack protection\n#endif\n'
    (w/'nossp_c.c').write_text(guard+'int nossp_c(void) { return 2; }\n')
    (w/'nossp_cxx.cc').write_text(guard+'extern "C" int nossp_cc(void) { return 3; }\n')
    (w/'nossp_asm.S').write_text(guard+'#ifndef __amd64__\n#error fixture requires native amd64\n#endif\n.text\n.globl nossp_asm\nnossp_asm:\n mov $4, %eax\n ret\n.section .note.GNU-stack,"",@progbits\n')
    (w/'nossp_check.c').write_text('int common(void); int nossp_c(void); int nossp_cc(void); int nossp_asm(void); int main(void) { return common()+nossp_c()+nossp_cc()+nossp_asm()!=10; }\n')
    selected={'common.c':['regular','nossp_pic'],'nossp_c.c':['nossp_pic'],'nossp_cxx.cc':['nossp_pic'],'nossp_asm.S':['nossp_pic']}
    flags={'common.c|regular':[]}
    for file,language in [('common.c','c'),('nossp_c.c','c'),('nossp_cxx.cc','c++'),('nossp_asm.S','assembler-with-cpp')]:
        flags[file+'|nossp_pic']=compile_flags(nossp_contexts[language],'nossp_pic')
    attrs=dict(srcs=list(selected),source_variants=selected,variants=['regular','nossp_pic'],arflags=['-crsD'],archive_inputs='//toolchain:archive_inputs')
    lines.append(rule('bsd_library',name='nossp',source_variant_flags=flags,**attrs))
    lines.append(rule('filegroup',name='nossp_archive',srcs=[':nossp'],output_group='nossp_pic_archive'))
    lines.append(rule('cc_import',name='nossp_link',static_library=':nossp_archive'))
    lines.append(rule('cc_test',name='nossp_test',srcs=['nossp_check.c'],deps=[':nossp_link'],size='small'))
    lines.append(rule('bsd_library',name='bad_nossp',tags=['manual'],**attrs))
(w/'BUILD.bazel').write_text('\n'.join(lines)+'\n')
argv=[('--output_user_root='+str(out/'bazel-root') if x.startswith('--output_user_root=') else x) for x in argv]
env=dict(os.environ,JAVA_HOME=str(a.java_home.resolve(strict=True)),BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1')
results=[]
def run(name,target):
    cmd=[('--build_event_json_file='+str(out/(name+'.events.json')) if x.startswith('--build_event_json_file=') else '--execution_log_json_file='+str(out/(name+'.execution.json')) if x.startswith(('--execution_log_json_file=', '--execution_log_compact_file=')) else x) for x in argv[:-1]]+[target]
    with (out/(name+'.stdout')).open('w') as stdout,(out/(name+'.stderr')).open('w') as stderr:
        r=subprocess.run(['/usr/bin/time','-l',*cmd],cwd=w,env=env,stdout=stdout,stderr=stderr)
    results.append(dict(name=name,argv=cmd,exit_code=r.returncode));return r.returncode
assert run('positive','//...')==0,'native fixture failed'
assert (w/'bazel-bin/generated/common_alias.c').read_bytes()==(w/'common.c').read_bytes()
archives={}
for variant,suffix in [('regular','.a'),('pic','.pic.a'),('pie','_pie.a')]:
    path=w/'bazel-bin'/('libmembership'+suffix)
    members=subprocess.check_output([str(w/'toolchain/bin/llvm-ar'),'t',str(path)],text=True).splitlines()
    ending='.pic.o' if variant=='pic' else '.o'
    assert members==[variant+ending,'common_alias'+ending],(variant,members)
    archives[variant]=dict(members=members,sha256=digest(path))
if nossp_contexts:
    path=w/'bazel-bin/libnossp_nossp_pic.a'
    members=subprocess.check_output([str(w/'toolchain/bin/llvm-ar'),'t',str(path)],text=True).splitlines()
    assert members==['common.pic.o','nossp_c.pic.o','nossp_cxx.pic.o','nossp_asm.pic.o'],members
    archives['nossp_pic']=dict(members=members,sha256=digest(path))
statuses={}
for line in (out/'positive.events.json').read_text().splitlines():
    event=json.loads(line)
    if 'testSummary' in event:statuses[event['id']['testSummary']['label']]=event['testSummary']['overallStatus']
expected_tests={'//:'+v+'_test':'PASSED' for v in ('regular','pic','pie')}
if nossp_contexts:expected_tests['//:nossp_test']='PASSED'
assert statuses==expected_tests,statuses
for name,message in [('missing','source variant inventory differs'),('unknown','source selects an unconfigured variant'),('duplicate','nonempty unique source variants required'),('empty','nonempty unique source variants required')]:
    assert run(name,'//:bad_'+name)!=0
    assert message in (out/(name+'.stderr')).read_text(),name
for name,message in [('missing','archive order inventory must cover'),('duplicate','duplicate archive member'),('unaccounted','archive members differ')]:
    assert run('order-'+name,'//:bad_order_'+name)!=0
    assert message in (out/('order-'+name+'.stderr')).read_text()
if nossp_contexts:
    assert run('nossp-missing-flags','//:bad_nossp')!=0
    assert 'NOSSP requires explicit effective source flags' in (out/'nossp-missing-flags.stderr').read_text()
for path,sha in inputs.items():assert digest(Path(path))==sha,'rule changed during qualification'
(out/'receipt.json').write_text(json.dumps(dict(status='passed',scope='source-variant rule fixture, not libc qualification',archives=archives,tests=statuses,commands=results,input_sha256=inputs),indent=2)+'\n')
print('PASS:',len(archives),'archive memberships and runtime consumers; invalid inventories rejected')
