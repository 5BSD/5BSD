#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Build upstream FIDL codecs, native BSD adapters, and runtime tests."""
import argparse
import concurrent.futures
import hashlib
import os
from pathlib import Path
import subprocess
import sys
# Host-side builds use their own object root.  Plain make -C would otherwise
# write host-linked objects into the world's object tree, which an
# incremental buildworld then trusts and installs.
os.environ['MAKEOBJDIRPREFIX'] = '/usr/obj/5bsd-fidl-hostobj'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--src',type=Path,default=Path('/usr/src'))
p.add_argument('--obj',type=Path,default=Path('/usr/obj/5bsd-fidl-runtime'))
p.add_argument('--tools',type=Path,default=Path('/usr/obj/5bsd-fidl'))
p.add_argument('--test',action='store_true')
p.add_argument('--sanitize',action='store_true')
p.add_argument('--fuzz',action='store_true',help='build a separate ASan/UBSan coverage-guided native codec target')
p.add_argument('--bench',action='store_true',help='build an -O2 tree and record comparative IPC measurements')
p.add_argument('--bench-calls',type=int,default=20000)
a=p.parse_args()
if a.bench and (a.test or a.sanitize or a.fuzz): p.error('--bench uses a separate optimized tree')
if a.fuzz:
 a.sanitize=True
 if a.test: p.error('--fuzz and --test use separate executables')
os.environ["PYTHONDONTWRITEBYTECODE"]="1"
r=a.src/'contrib/fuchsia'; lib=a.src/'lib/libfidl'; o=a.obj
if a.fuzz: o=o/'fuzzed'
elif a.sanitize: o=o/'sanitized'
elif a.bench: o=o/'bench'
o.mkdir(parents=True,exist_ok=True)
subprocess.run([str(a.tools/'fidlc'),'--json',str(o/'runtime.json'),'--files',str(lib/'tests/zx.fidl'),'--files',str(lib/'tests/runtime.fidl')],check=True)
subprocess.run([sys.executable,str(a.src/'tools/build/fuchsia/generate-bsd.py'),'--json',str(o/'runtime.json'),'--root',str(o/'gen'),'--c'],check=True)
inc=[lib/'include',a.src/'lib/libchannel',a.src/'sys',r/'sdk',r/'src/zircon/lib/zircon/include',r/'zircon/system/public',r/'zircon/system/ulib/zx/include',o/'gen']
inc += [r/'sdk/lib'/d/'include' for d in ['fidl_base','fidl/cpp','fidl/cpp/wire','fit','stdcompat','zircon-assert']]
flags=(['-O2'] if a.bench else ['-O1','-g'])+['-pthread']+['-I'+str(i) for i in inc]
# Pattern-fill locals so uninitialized bool/enum reads reach UBSan
# deterministically instead of depending on stale stack bytes.
if a.sanitize: flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer','-ftrivial-auto-var-init=pattern']
if a.fuzz: flags+=['-fsanitize=fuzzer-no-link']
# Keep in sync with lib/libfidl/Makefile; check-closure.py proves each is used.
names='coding_errors incoming_message outgoing_message status transport wire_coding_traits wire_decoder wire_encoder transport_channel_host'.split()
sources=[r/'sdk/lib/fidl/cpp/wire'/(n+'.cc') for n in names]
sources += [r/'sdk/lib/fidl/cpp'/(n+'.cc') for n in ['natural_coding_traits','natural_decoder','natural_encoder']]
sources += [r/'sdk/lib/fidl_base'/n for n in ['handle_close_many.cc','internal.c','wire_format_metadata.cc']]
sources += [r/'sdk/lib/zircon-assert/zx_panic_libc.cc',r/'sdk/lib/utf-utils/utf-utils.cc',r/'sdk/lib/utf-utils/internal/scalar.cc',lib/'runtime.cc',lib/'runtime_c.cc']
# Use the maintained native library for ordinary builds. Sanitizer builds
# instrument the same transport sources into a separate test archive.
separate_transport = a.sanitize or a.bench
transport_sources = [a.src/'lib/libchannel/channel.c', a.src/'lib/libchannel/channel_call.c', a.src/'lib/libchannel/channel_syscall.c'] if separate_transport else []
if not separate_transport:
 subprocess.run(['make','-C',str(a.src/'lib/libchannel'),'-j'+str(os.cpu_count()),'MK_TESTS=no','all'],check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 channel_obj=Path(subprocess.check_output(['make','-C',str(a.src/'lib/libchannel'),'-V','.OBJDIR'],text=True).strip())
 channel_archive=channel_obj/'libchannel.a'
else:
 channel_archive=o/('libchannel-bench.a' if a.bench else 'libchannel-sanitized.a')

def obj(s): return o/(s.stem+'-'+hashlib.sha256(str(s).encode()).hexdigest()[:12]+'.o')
def compile(s,extra_flags=()):
 cmd=[os.environ.get('CC','cc'),'-std=c11'] if s.suffix=='.c' else [os.environ.get('CXX','c++'),'-std=c++20']
 cmd+=list(extra_flags)+flags+['-c',str(s),'-o',str(obj(s))]
 result=subprocess.run(cmd,text=True,capture_output=True)
 (o/(obj(s).name+'.log')).write_text(result.stdout+result.stderr)
 if result.returncode: raise RuntimeError(str(s)+'\n'+result.stdout+result.stderr)
extra=[o/'gen/fidl/bsd.runtime.test/cpp/natural_types.cc',o/'gen/fidl/bsd.runtime.test/cpp/common_types.cc',o/'gen/fidl/bsd.runtime.test/c/bsd.cc']
if a.fuzz:
 extra += [lib/'tests/codec_fuzz.cc']
if a.bench:
 extra += [lib/'tests/ipc_bench.cc']
if a.test:
 incg=[a.src/'contrib/googletest/googletest/include',a.src/'contrib/googletest/googletest']
 flags+=['-I'+str(i) for i in incg]
 extra += [lib/'tests/c_binding_test.c',lib/'tests/runtime_test.cc',lib/'tests/allocation_fault.cc',a.src/'contrib/googletest/googletest/src/gtest-all.cc',a.src/'contrib/googletest/googletest/src/gtest_main.cc']
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
 list(pool.map(compile,sources+transport_sources+extra))
# Replace the archive so removed inputs cannot survive an incremental rebuild.
target=o/'libfidl_bsd.a'
if target.exists(): target.unlink()
subprocess.run(['ar','rcs',str(target),*map(str,map(obj,sources))],check=True)
if separate_transport:
 if channel_archive.exists(): channel_archive.unlink()
 subprocess.run(['ar','rcs',str(channel_archive),*map(str,map(obj,transport_sources))],check=True)
print('Built '+str(target),flush=True)
if a.fuzz:
 exe=o/'codec-fuzz'
 # Link target instantiations first. Clang's automatic -fsanitize=fuzzer
 # placement can select uninstrumented libc++ vector code from its archive.
 compiler=os.environ.get('CXX','c++')
 machine=subprocess.check_output([compiler,'-dumpmachine'],text=True).strip().split('-')[0]
 driver=Path(subprocess.check_output([compiler,'--print-file-name=libclang_rt.fuzzer_no_main-'+machine+'.a'],text=True).strip())
 if not driver.is_file(): raise RuntimeError('missing native libFuzzer no-main archive: '+str(driver))
 subprocess.run([compiler,*flags,*map(str,map(obj,extra)),str(target),str(channel_archive),str(driver),'-o',str(exe)],check=True)
 print('Built coverage-guided target '+str(exe),flush=True)
if a.bench:
 import json, platform
 exe=o/'ipc-bench'
 # Static so libc++ allocations also pass through the counting wrappers.
 subprocess.run([os.environ.get('CXX','c++'),*flags,'-static','-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free',*map(str,map(obj,extra)),str(target),str(channel_archive),'-o',str(exe)],check=True)
 results=[]
 for payload in (8,256):
  for mode in ('raw','cpp','c'):
   for trial in range(3):
    run=subprocess.run([str(exe),mode,str(payload),str(a.bench_calls),'1000'],capture_output=True,text=True,timeout=600)
    if run.returncode: raise RuntimeError('ipc-bench %s %d failed: %s'%(mode,payload,run.stderr))
    line=run.stdout
    results.append(dict(json.loads(line),trial=trial))
    print(line.strip(),flush=True)
 record={'platform':list(platform.uname()),'cpu_count':os.cpu_count(),'load_average_at_end':os.getloadavg(),'compiler_flags':flags[:2],'results':results}
 (o/'bench.json').write_text(json.dumps(record,indent=2)+'\n')
 print('IPC comparison: '+str(o/'bench.json'),flush=True)

if a.test:
 exe=o/'runtime-test'
 subprocess.run([os.environ.get('CXX','c++'),*flags,'-Wl,--wrap=malloc,--wrap=_Znwm,--wrap=_Znam',*map(str,map(obj,[x for x in extra if x.name != 'c_binding_test.c'])),str(target),str(channel_archive),'-o',str(exe)],check=True)
 env=dict(os.environ)
 if a.sanitize: env['ASAN_OPTIONS']='detect_leaks=0:abort_on_error=1'
 if a.sanitize: env['UBSAN_OPTIONS']='halt_on_error=1:print_stacktrace=1'
 subprocess.run([str(exe),'--gtest_output=xml:'+str(o/'runtime-test.xml')],cwd=o,env=env,check=True,timeout=180)

 if a.test:
  cexe=o/'c-binding-test'
  cinputs=[x for x in extra if x.name in ('natural_types.cc','common_types.cc','bsd.cc','c_binding_test.c')]
  subprocess.run([os.environ.get('CXX','c++'),*flags,*map(str,map(obj,cinputs)),str(target),str(channel_archive),'-o',str(cexe)],check=True)
  subprocess.run([str(cexe)],cwd=o,env=env,check=True,timeout=30)

if a.test:
 # Upstream GIDL conformance cases through the native codec entry points.
 conf=o/'conformance'
 subprocess.run([sys.executable,str(a.src/'tools/build/fuchsia/generate-conformance.py'),'--src',str(a.src),'--tools',str(a.tools),'--out',str(conf)],check=True)
 conf_flags=['-I'+str(lib/'tests/conformance'),'-I'+str(conf/'gen')]
 conf_sources=[conf/'conformance_test.cc',conf/'gen/fidl/test.conformance/cpp/natural_types.cc',conf/'gen/fidl/test.conformance/cpp/common_types.cc']
 with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
  list(pool.map(lambda x: compile(x,conf_flags),conf_sources))
 gtest=[x for x in extra if x.name in ('gtest-all.cc','gtest_main.cc')]
 conf_exe=o/'conformance-test'
 subprocess.run([os.environ.get('CXX','c++'),*flags,*map(str,map(obj,conf_sources+gtest)),str(target),str(channel_archive),'-o',str(conf_exe)],check=True)
 subprocess.run([str(conf_exe),'--gtest_output=xml:'+str(o/'conformance-test.xml')],cwd=o,env=env,check=True,timeout=300)
 subprocess.run([sys.executable,str(a.src/'tools/build/fuchsia/check-closure.py'),'--obj',str(o)],check=True)

if a.test:
 subprocess.run([sys.executable,str(lib/'tests/generator_test.py'),'--src',str(a.src),'--obj',str(o),'--tools',str(a.tools)],check=True,timeout=300)

if a.test:
 subprocess.run([sys.executable,str(lib/'tests/evolution_test.py'),'--src',str(a.src),'--obj',str(o),'--tools',str(a.tools)],check=True,timeout=600)

if a.test:
 subprocess.run([sys.executable,str(lib/'tests/library_test.py'),'--src',str(a.src),'--obj',str(o),'--tools',str(a.tools)],check=True,timeout=300)
