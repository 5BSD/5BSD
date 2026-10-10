#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Build a multi-library native C application and reject inconsistent IR graphs."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
# Host-side builds use their own object root.  Plain make -C would otherwise
# write host-linked objects into the world's object tree, which an
# incremental buildworld then trusts and installs.
os.environ['MAKEOBJDIRPREFIX'] = '/usr/obj/5bsd-fidl-hostobj'

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--src',type=Path,default=Path('/usr/src'))
p.add_argument('--obj',type=Path,default=Path('/usr/obj/5bsd-fidl-runtime'))
p.add_argument('--tools',type=Path,default=Path('/usr/obj/5bsd-fidl'))
p.add_argument('--dependency-root',type=Path,help='separate native channel dependency stage for extracted package tests')
p.add_argument('--sdk',type=Path,help='installed SDK root, including its native shared libraries')
a=p.parse_args()
a.obj.mkdir(parents=True,exist_ok=True)
work=Path(tempfile.mkdtemp(prefix='library-tests-',dir=a.obj))
source=a.src/'lib/libfidl/tests'
for name in ('types.fidl','shared.fidl','app.fidl','consumer.c'):
    shutil.copyfile(source/'libraries'/name,work/name)
shutil.copyfile(source/'zx.fidl',work/'zx.fidl')
compiler=a.sdk/'usr/bin/fidlc' if a.sdk else a.tools/'fidlc'
adapter=[str(a.sdk/'usr/bin/fidlgen-bsd')] if a.sdk else [sys.executable,str(a.src/'tools/build/fuchsia/generate-bsd.py'),'--fidlgen-cpp',str(a.tools/'fidlgen_cpp')]
files=['--files',str(work/'zx.fidl')]
for name in ('types','shared','app'):
    files+=['--files',str(work/(name+'.fidl'))]
    subprocess.run([str(compiler),'--json',str(work/(name+'.json')),*files],check=True)
output=work/'generated'
command=adapter+['--json',str(work/'app.json'),'--dependency-json',str(work/'shared.json'),'--dependency-json',str(work/'types.json'),'--root',str(output),'--c']
subprocess.run(command,check=True)
def snapshot():
    return {str(p.relative_to(output)):p.read_bytes() for p in output.rglob('*') if p.is_file()}
expected=snapshot()
# Dependency arguments are deliberately supplied in reverse order above.
subprocess.run(adapter+['--json',str(work/'app.json'),'--dependency-json',str(work/'types.json'),'--dependency-json',str(work/'shared.json'),'--root',str(output),'--c'],check=True)
assert expected==snapshot(), 'dependency generation is not reproducible'
checks=1

def reject(arguments, message):
    global checks
    result=subprocess.run(adapter+arguments+['--root',str(output),'--c'],text=True,capture_output=True)
    if result.returncode==0 or message not in result.stderr:
        raise RuntimeError('unexpected dependency rejection: '+result.stdout+result.stderr)
    assert expected==snapshot(), 'rejected dependency graph replaced existing output'
    checks+=1

main=['--json',str(work/'app.json')]
deps=['--dependency-json',str(work/'shared.json'),'--dependency-json',str(work/'types.json')]
reject(main,'missing dependency IR')
reject(main+deps+['--dependency-json',str(work/'types.json')],'duplicate library IR')
shared=json.loads((work/'shared.json').read_text())
shared['struct_declarations'][0]['members'][0]['name']='renamed'
(work/'mismatch.json').write_text(json.dumps(shared))
reject(main+['--dependency-json',str(work/'mismatch.json'),'--dependency-json',str(work/'types.json')],'incompatible imported struct')
types=json.loads((work/'types.json').read_text())
types['library_dependencies'].append({'name':'cross.app','declarations':{}})
(work/'cycle.json').write_text(json.dumps(types))
reject(main+['--dependency-json',str(work/'shared.json'),'--dependency-json',str(work/'cycle.json')],'cyclic dependency IR')
# Reject a dependency after earlier dependencies have already been staged.
unsupported=json.loads((work/'shared.json').read_text())
unsupported['protocol_declarations'][0]['openness']='invalid'
(work/'unsupported.json').write_text(json.dumps(unsupported))
reject(main+['--dependency-json',str(work/'unsupported.json'),'--dependency-json',str(work/'types.json')],'unsupported protocol openness')
missing=json.loads((work/'types.json').read_text())
del missing['declarations']['cross.types/Payload']
(work/'missing.json').write_text(json.dumps(missing))
reject(main+['--dependency-json',str(work/'shared.json'),'--dependency-json',str(work/'missing.json')],'incompatible dependency declaration')
layout=json.loads((work/'types.json').read_text())
layout['enum_declarations'][0]['type']='uint64'
(work/'layout.json').write_text(json.dumps(layout))
reject(main+['--dependency-json',str(work/'shared.json'),'--dependency-json',str(work/'layout.json')],'incompatible dependency layout')
assert sum(b'struct cross_types_Payload {' in value for key,value in expected.items() if key.endswith('/c/bsd.h'))==1, 'imported C layout duplicated'
# Leave every generated public header C11-compatible, even a types-only library.
if a.sdk:
    env=dict(os.environ,PKG_CONFIG_LIBDIR=str(a.sdk/'usr/libdata/pkgconfig'),PKG_CONFIG_SYSROOT_DIR=str(a.sdk),PKG_CONFIG_PATH='')
    flags=shlex.split(subprocess.check_output(['pkgconf','--cflags','fidl'],env=env,text=True))
    libraries=shlex.split(subprocess.check_output(['pkgconf','--libs','fidl'],env=env,text=True))
    dependency=a.dependency_root or a.sdk
    flags+=['-I'+str(dependency/'usr/include')]
    libraries+=['-L'+str(dependency/'usr/lib'),'-lchannel']
    env['LD_LIBRARY_PATH']=str(a.sdk/'usr/lib')+':'+str(dependency/'usr/lib')
else:
    f=a.src/'contrib/fuchsia'
    includes=[a.src/'lib/libfidl/include',a.src/'lib/libchannel',a.src/'sys',f/'sdk',f/'src/zircon/lib/zircon/include',f/'zircon/system/public']
    includes += [f/'sdk/lib'/part/'include' for part in ('fidl_base','fidl/cpp','fidl/cpp/wire','fit','stdcompat','zircon-assert')]
    flags=['-I'+str(i) for i in includes]
    sanitized=a.obj.name=='sanitized'
    if sanitized: flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
    channel=a.obj/'libchannel-sanitized.a' if sanitized else Path(subprocess.check_output(['make','-C',str(a.src/'lib/libchannel'),'-V','.OBJDIR'],text=True).strip())/'libchannel.a'
    libraries=[str(a.obj/'libfidl_bsd.a'),str(channel),'-lc++','-lcxxrt','-lm','-pthread']
    env=dict(os.environ)
    if sanitized: env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
flags+=['-I'+str(output)]
inputs=[work/'consumer.c']
for name in ('cross.types','cross.shared','cross.app'):
    base=output/'fidl'/name
    subprocess.run(['cc','-std=c11','-pedantic-errors',*flags,'-fsyntax-only','-x','c','-'],input='#include <fidl/'+name+'/c/bsd.h>\n',text=True,check=True)
    inputs += [base/'cpp/natural_types.cc',base/'cpp/common_types.cc',base/'c/bsd.cc']
# Also compile the imported/composed C++ client API in a separate translation unit.
probe=work/'consumer.cc'
probe.write_text('#include <fidl/cross.app/cpp/bsd.h>\n#include <fidl/cross.shared/c/bridge.h>\nvoid cpp_api(fidl::bsd::Connection& c, cross_shared::Envelope v) { cross_app::bsd::AppClient client(c); (void)client.Exchange(std::move(v), [](auto){}); }\n')
inputs.append(probe)
def compile(item):
    index,source=item
    target=work/(str(index)+'.o')
    compiler=['cc','-std=c11','-pedantic-errors'] if source.suffix=='.c' else ['c++','-std=c++20']
    subprocess.run([*compiler,*flags,'-MMD','-MF',str(target)+'.d','-c',str(source),'-o',str(target)],check=True)
    if a.sdk and str(a.src) in Path(str(target)+'.d').read_text():
        raise RuntimeError('installed SDK consumer used a source-tree header')
    return target
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
    objects=list(pool.map(compile,enumerate(inputs)))
binary=work/'consumer'
subprocess.run(['cc',*flags,*map(str,objects),*libraries,'-o',str(binary)],check=True)
subprocess.run([str(binary)],env=env,check=True,timeout=25)
print(str(checks)+' dependency graph checks, three C11 headers, multi-library C/C++ compile/link and native C round trips: PASS; '+str(work),flush=True)
