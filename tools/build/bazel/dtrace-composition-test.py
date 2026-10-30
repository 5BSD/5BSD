#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify DTrace/static-only composition with an explicit SDK and Bazel inputs.

This builds bounded rule fixtures, not libc or active tracing qualification.
"""
import argparse,json,shutil,subprocess,os
from pathlib import Path
from libmd_environment import digest

p=argparse.ArgumentParser(description=__doc__)
for key in ('sdk','module-workspace','command-log','java-home','output'):
    p.add_argument('--'+key,type=Path,required=True)
p.add_argument('--object-path-mode', choices=('absolute','relative'), default='absolute')
a=p.parse_args()
root=a.output.resolve();sdk=a.sdk.resolve(strict=True)
modules=a.module_workspace.resolve(strict=True)
if root.exists() or not root.is_relative_to('/usr/obj') or root==Path('/usr/obj') or sdk.is_relative_to(root) or modules.is_relative_to(root):
    p.error('fresh nonoverlapping output below /usr/obj required')
receipt=json.loads((sdk/'toolchain-inputs.json').read_text())
for path,h in receipt['inputs'].items():
    if digest(Path(path))!=h:raise ValueError('SDK input changed: '+path)
for path,h in receipt['snapshot'].items():
    if digest(sdk/'workspace'/path)!=h:raise ValueError('SDK snapshot changed: '+path)
argv=next(x['argv'] for x in json.loads(a.command_log.read_text()) if x['name']=='bazel-test')
if argv[-1]!='//...' or '--repository_disable_download' not in argv or '--ignore_all_rc_files' not in argv:
    p.error('explicit offline native test command required')
root.mkdir();w=root/'workspace';w.mkdir()
shutil.copytree(sdk/'workspace/toolchain',w/'toolchain',symlinks=True)
inputs={}
for name in ('MODULE.bazel','MODULE.bazel.lock'):
    path=modules/name;inputs[str(path)]=digest(path);shutil.copyfile(path,w/name)
for name in ('native_cc.bzl','bsd_dtrace.bzl','bsd_fidl.bzl','source_identity.bzl','copy_then_exec.c'):
    path=Path(__file__).with_name(name);inputs[str(path)]=digest(path);shutil.copyfile(path,w/name)
for name in ('dtrace_composition.d','dtrace_composition_normal.c','dtrace_composition_static.c','dtrace_composition_main.c','static_only_main.c'):
    path=Path(__file__).with_name('tests')/name;inputs[str(path)]=digest(path);shutil.copyfile(path,w/name)
def rule(kind,**attrs):return kind+'('+', '.join(k+'='+repr(v) for k,v in attrs.items())+')'
lines=['load(":native_cc.bzl", "bsd_library", "bsd_static_source")','load(":bsd_dtrace.bzl", "bsd_dtrace_header")','load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_test")']
lines.append(rule('cc_binary',name='copy_runner',srcs=['copy_then_exec.c'],linkstatic=True,features=['fully_static_link']))
lines.append(rule('bsd_dtrace_header',name='provider',source='dtrace_composition.d',output='generated/dtrace_composition.h',flags=['-C','-x','nolibs'],static_anchor=True,object_path_mode=a.object_path_mode,dtrace='//toolchain:extra_dtrace',cpp='//toolchain:bin/cpp',linker='//toolchain:bin/ld.lld',objcopy='//toolchain:bin/llvm-objcopy',drti='//toolchain:sysroot/usr/lib/dtrace/drti.o',tool_inputs=['//toolchain:extra_dtrace_runtime','//toolchain:compile_inputs','//toolchain:link_inputs','//toolchain:objcopy_inputs']))
lines.append(rule('bsd_static_source',name='static_extra',source='dtrace_composition_static.c',output='generated/static_extra.c'))
order={'regular':['dtrace_composition.o','dtrace_composition_normal.o','static_extra.o'],'pic':['dtrace_composition.pico','dtrace_composition_normal.pic.o']}
lines.append(rule('bsd_library',name='composition',srcs=['dtrace_composition_normal.c'],arflags=['-crsD'],archive_inputs='//toolchain:archive_inputs',static_sources=[':static_extra'],dtrace_providers=[':provider'],dtrace_copy_runner=':copy_runner',variants=['regular','pic'],archive_member_order=order,dtrace_object_names={'regular':'dtrace_composition.o','pic':'dtrace_composition.pico'}))
lines.append(rule('filegroup',name='pic_archive',srcs=[':composition'],output_group='pic_archive'))
lines.append(rule('cc_import',name='pic_link',static_library=':pic_archive'))
lines.append(rule('cc_test',name='regular_test',srcs=['dtrace_composition_main.c'],deps=[':composition'],linkstatic=True,size='small'))
lines.append(rule('cc_test',name='pic_test',srcs=['dtrace_composition_main.c'],deps=[':pic_link'],copts=['-DPIC_CONSUMER'],linkstatic=True,size='small'))
lines.append(rule('bsd_library',name='only_static',srcs=[],arflags=['-crsD'],archive_inputs='//toolchain:archive_inputs',static_sources=[':static_extra'],variants=['regular'],archive_member_order={'regular':['static_extra.o']}))
lines.append(rule('cc_test',name='only_static_test',srcs=['static_only_main.c'],deps=[':only_static'],linkstatic=True,size='small'))
(w/'BUILD.bazel').write_text('\n'.join(lines)+'\n')
command=[('--output_user_root='+str(root/'bazel-root') if x.startswith('--output_user_root=') else '--build_event_json_file='+str(root/'events.json') if x.startswith('--build_event_json_file=') else '--execution_log_json_file='+str(root/'execution.json') if x.startswith(('--execution_log_json_file=', '--execution_log_compact_file=')) else x) for x in argv]
env=dict(os.environ,JAVA_HOME=str(a.java_home.resolve(strict=True)),BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1')
with (root/'stdout').open('w') as stdout,(root/'stderr').open('w') as stderr:r=subprocess.run(['/usr/bin/time','-l',*command],cwd=w,env=env,stdout=stdout,stderr=stderr)
(root/'command.json').write_text(json.dumps(dict(argv=command,exit_code=r.returncode),indent=2)+'\n');assert r.returncode==0,'native DTrace composition failed'
archives={}
for v,suffix in [('regular','.a'),('pic','.pic.a')]:
 p=w/'bazel-bin'/('libcomposition'+suffix);members=subprocess.check_output([str(w/'toolchain/bin/llvm-ar'),'t',str(p)],text=True).splitlines();assert members==order[v],(v,members);archives[v]=dict(members=members,sha256=digest(p))
s=(root/'execution.json').read_text();decoder=json.JSONDecoder();i=0;rewrite=[]
while i<len(s):
 while i<len(s) and s[i].isspace():i+=1
 if i==len(s):break
 row,i=decoder.raw_decode(s,i)
 if row.get('mnemonic')!='BSDDTraceObjects':continue
 assert row['exitCode']==0
 assert not any('static_extra' in x for x in row['commandArgs']),row['commandArgs']
 preserved=[]
 for entry in row['inputs']:
  if '/_objs/' in entry['path'] and entry['path'].endswith('.o'):
   assert digest(w/entry['path'])==entry['digest']['hash'];preserved.append(entry['path'])
 assert len(preserved)==1
 rewrite.append(dict(argv=row['commandArgs'],preserved_objects=preserved))
assert len(rewrite)==2
statuses={}
for line in (root/'events.json').read_text().splitlines():
 event=json.loads(line)
 if 'testSummary' in event:statuses[event['id']['testSummary']['label']]=event['testSummary']['overallStatus']
assert statuses=={'//:regular_test':'PASSED','//:pic_test':'PASSED','//:only_static_test':'PASSED'}
p=w/'bazel-bin/libonly_static.a'
assert subprocess.check_output([str(w/'toolchain/bin/llvm-ar'),'t',str(p)],text=True).splitlines()==['static_extra.o']
archives['only_static']=dict(members=['static_extra.o'],sha256=digest(p))
for n in ('regular_test','pic_test'):
 sections=subprocess.check_output(['/usr/bin/readelf','-SW',str(w/'bazel-bin'/n)],text=True);assert '.SUNW_dof' in sections,n
for p,h in inputs.items():assert digest(Path(p))==h,p
(root/'receipt.json').write_text(json.dumps(dict(status='passed',scope='native DTrace/static-only archive composition; linked disabled-probe consumers; no active tracing or libc qualification',archives=archives,tests=statuses,dtrace_rewrites=rewrite,input_sha256=inputs),indent=2)+'\n');print('PASS: DTrace excludes static-only objects; exact regular/PIC archive order; preserved compiler inputs; two linked DOF consumers and static-only consumer passed')
