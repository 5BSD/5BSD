#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify native GROUP rescanning with circular archives and a shared member."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from libmd_environment import digest

p = argparse.ArgumentParser(description=__doc__)
for key in ('workspace', 'command-log', 'java-home', 'output'):
    p.add_argument('--'+key, type=Path, required=True)
a = p.parse_args()
origin=a.workspace.resolve(strict=True);out=a.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj') or out==Path('/usr/obj') or origin.is_relative_to(out):
    p.error('fresh nonoverlapping output below /usr/obj required')
commands=json.loads(a.command_log.read_text())
argv=next(c['argv'] for c in commands if c['name']=='bazel-test')
if argv[-1]!='//...' or '--repository_disable_download' not in argv or '--ignore_all_rc_files' not in argv:
    p.error('explicit offline native test command required')
out.mkdir();w=out/'workspace';w.mkdir()
shutil.copytree(origin/'toolchain',w/'toolchain',symlinks=True)
for name in ('MODULE.bazel','MODULE.bazel.lock'):
    shutil.copyfile(origin/name,w/name)
inputs={}
for name in ('native_cc.bzl','bsd_dtrace.bzl','bsd_fidl.bzl','source_identity.bzl','bsd_link_group.bzl'):
    path=Path(__file__).with_name(name);inputs[str(path)]=digest(path);shutil.copyfile(path,w/name)
for name,source in {
    'a1.c':'int group_b(void); int group_a1(void) { return group_b(); }\n',
    'a2.c':'int group_a2(void) { return 17; }\n',
    'b.c':'int group_a2(void); int group_b(void) { return group_a2(); }\n',
    'shared.c':'int group_shared(void) { return 20; }\n',
    'extra.c':'int group_extra(void) { return 5; }\n',
    'main.c':'int group_a1(void); int group_shared(void); int group_extra(void); int main(void) { return group_a1()+group_shared()+group_extra()!=42; }\n',
}.items():
    (w/name).write_text(source)
(w/'BUILD.bazel').write_text('''load(":native_cc.bzl", "bsd_library")
load(":bsd_link_group.bzl", "bsd_link_group")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_test")
bsd_library(name="first", srcs=["a1.c", "a2.c"], variants=["regular"], arflags=["-crsD"], archive_inputs="//toolchain:archive_inputs")
bsd_library(name="second", srcs=["b.c"], variants=["regular"], arflags=["-crsD"], archive_inputs="//toolchain:archive_inputs")
cc_binary(name="libgroup_shared.so", srcs=["shared.c"], linkshared=True, linkopts=["-Wl,-soname,libgroup_shared.so"])
cc_binary(name="libgroup_extra.so", srcs=["extra.c"], linkshared=True, linkopts=["-Wl,-soname,libgroup_extra.so"])
bsd_link_group(name="group", members=[":libgroup_shared.so", ":first", ":second", ":libgroup_extra.so"], shared_member_indices=[0, 3])
cc_test(name="group_test", srcs=["main.c"], deps=[":group"], linkstatic=True, features=["bsd_test_runtime_paths"], linkopts=["-Wl,--warn-backrefs,--fatal-warnings"], size="small")
''')
argv=[('--output_user_root='+str(out/'bazel-root') if x.startswith('--output_user_root=') else x) for x in argv]
env=dict(os.environ,JAVA_HOME=str(a.java_home.resolve(strict=True)),BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN='1')
records=[]
def run(name):
    cmd=[('--build_event_json_file='+str(out/(name+'.events.json')) if x.startswith('--build_event_json_file=') else '--execution_log_json_file='+str(out/(name+'.execution.json')) if x.startswith(('--execution_log_json_file=', '--execution_log_compact_file=')) else x) for x in argv]
    with (out/(name+'.stdout')).open('w') as stdout,(out/(name+'.stderr')).open('w') as stderr:
        r=subprocess.run(['/usr/bin/time','-l',*cmd],cwd=w,env=env,stdout=stdout,stderr=stderr)
    records.append(dict(name=name,argv=cmd,exit_status=r.returncode))
    (out/'commands.json').write_text(json.dumps(records,indent=2)+'\n')
    return r.returncode
assert run('group')==0, 'native GROUP build/runtime failed'
rule=w/'bsd_link_group.bzl';original=rule.read_text()
try:
    rule.write_text(original.replace('"GROUP ( "','"INPUT ( "'))
    assert run('without-rescan')!=0, 'negative control unexpectedly passed'
    error=(out/'without-rescan.stderr').read_text()
    assert 'backward reference detected' in error and 'group_a2' in error, 'negative control failed for another reason'
finally:
    rule.write_text(original)
assert run('restored')==0, 'restored GROUP failed'
for path,h in inputs.items():
    assert digest(Path(path))==h, 'source changed: '+path
(out/'receipt.json').write_text(json.dumps(dict(status='passed',records=records,inputs=inputs,
    scope='native mixed shared/archive GROUP; circular archive rescan; linked runtime consumer',
    limitations=['Not complete libc integration.', 'No general transitive runtime dependency propagation qualification.']),indent=2)+'\n')
print('PASS: mixed GROUP runtime; circular archive rescan; negative control; restoration')
