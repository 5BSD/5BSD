#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify static-only runtime sources in an existing disposable native graph.

The explicit ABI source must exercise the configured runtime. This checks native
actions and archive membership, not complete component/linker-script coverage.
"""
import argparse,json,shutil,subprocess,os
from pathlib import Path
import static_sources,source_headers
from libmd_environment import digest
parser=argparse.ArgumentParser(description=__doc__)
for key in ('src','workspace','plan','build-command','java-home','abi-source','output'):
 parser.add_argument('--'+key,type=Path,required=True)
a=parser.parse_args();src=a.src.resolve(strict=True);workspace=a.workspace.resolve(strict=True);root=a.output.resolve();planpath=a.plan.resolve(strict=True)
if root.exists() or not root.is_relative_to('/usr/obj') or root==Path('/usr/obj') or workspace.is_relative_to(root):raise ValueError('fresh nonoverlapping result directory below /usr/obj required')
if not workspace.is_relative_to('/usr/obj'):raise ValueError('disposable workspace below /usr/obj required')
if 'bsd_static_source(name=' in (workspace/'BUILD.bazel').read_text():raise ValueError('workspace already contains static qualification targets')
plan=json.loads(planpath.read_text())
if len(plan['components'])!=1:raise ValueError('one configured component required')
component=plan['components'][0]
if not component['static_objects']:raise ValueError('configured static objects required')
root.mkdir()
for path,sha in plan['input_sha256'].items():
 if digest(Path(path))!=sha:raise ValueError('stale input: '+path)
lines=[];snapshot={}
def copy(path):
 relative=Path('sources')/path.relative_to(src);dest=workspace/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dest);snapshot[str(relative)]=digest(dest);return str(relative)
def rule(kind,**values):lines.append(kind+'('+', '.join(k+'='+repr(v) for k,v in values.items())+')')
labels,dirs=static_sources.emit(component,src,Path(plan['build_environment']['objtop']),copy,rule,{})
headers=sorted(set(copy(p) for d in dirs for p in source_headers.collect(d) if p.is_file()))
(workspace/'archive_anchor.c').write_text('int archive_anchor(void) { return 0; }\n')
rule('bsd_library',name='static_archive_qualification',srcs=['archive_anchor.c'],hdrs=headers,static_sources=labels,arflags=['-crsD'],archive_inputs='//toolchain:archive_inputs',variants=['regular','pic','pie'],variant_flags={'pic':['-fpic','-DPIC'],'pie':['-fpie','-DPIC']},copts=['-DQUALIFY_ORDINARY_SOURCE_ONLY=1'])
for variant in ('pic','pie'):rule('filegroup',name='static_archive_'+variant,srcs=[':static_archive_qualification'],output_group=variant+'_archive')
rule('cc_test',name='static_archive_abi',srcs=[copy(a.abi_source.resolve(strict=True))],deps=[':static_archive_qualification'],copts=['-std=c++20','-nostdinc++'],linkstatic=True,features=['fully_static_link'],size='small')
build=workspace/'BUILD.bazel';build.write_text(build.read_text()+'\n\n'+'\n\n'.join(lines)+'\n')
(root/'static-source-snapshot.json').write_text(json.dumps(dict(plan=str(planpath),plan_sha256=digest(planpath),snapshot=snapshot),indent=2)+'\n')
argv=json.loads(a.build_command.read_text())['argv']
argv=[('--build_event_json_file='+str(root/'build.events.json') if x.startswith('--build_event_json_file=') else '--execution_log_json_file='+str(root/'build.execution.json') if x.startswith('--execution_log_json_file=') else x) for x in argv]
if 'test' not in argv or not any(x.startswith('--jobs=') for x in argv):raise ValueError('Bazel test command with explicit parallelism required')
env=dict(os.environ,BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1',JAVA_HOME=str(a.java_home.resolve(strict=True)))
(root/'test-command.json').write_text(json.dumps({'argv':argv},indent=2)+'\n')
with (root/'build.stdout').open('w') as stdout,(root/'build.stderr').open('w') as stderr:
 done=subprocess.run(['/usr/bin/time','-l',*argv],cwd=workspace,env=env,stdout=stdout,stderr=stderr)
(root/'test-command.json').write_text(json.dumps({'argv':argv,'exit_code':done.returncode},indent=2)+'\n')
print('Bazel exit:',done.returncode);print((root/'build.stdout').read_text()[-2000:]);print((root/'build.stderr').read_text()[-2200:])
if done.returncode:raise SystemExit(done.returncode)
events=[json.loads(line) for line in (root/'build.events.json').read_text().splitlines()]
tests=[e['testSummary'] for e in events if e.get('id',{}).get('testSummary',{}).get('label')=='//:static_archive_abi']
if len(tests)!=1 or tests[0]['overallStatus']!='PASSED':raise ValueError('static runtime ABI test did not pass')
archives={}
for variant,suffix in [('regular','.a'),('pic','.pic.a'),('pie','_pie.a')]:
 path=workspace/'bazel-bin'/('libstatic_archive_qualification'+suffix)
 members=subprocess.check_output([str(workspace/'toolchain/bin/llvm-ar'),'t',str(path)],text=True).splitlines()
 expected=['archive_anchor.pic.o' if variant=='pic' else 'archive_anchor.o']+([Path(r['object']).name for r in component['static_objects']] if variant=='regular' else [])
 if members!=expected:raise ValueError('incorrect archive membership/order: '+variant)
 archives[variant]=dict(path=str(path),sha256=digest(path),members=members)
receipt=dict(status='passed',scope='static-only action/archive/ABI qualification; not complete component build',archives=archives,test=tests[0],plan_sha256=digest(planpath),driver_sha256=digest(Path(__file__)),rule_sha256=digest(workspace/'native_cc.bzl'),emitter_sha256=digest(Path(static_sources.__file__)),header_collector_sha256=digest(Path(source_headers.__file__)))
(root/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('PASS: regular-only archive membership, order and runtime ABI')
