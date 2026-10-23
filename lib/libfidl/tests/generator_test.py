#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise accepted/rejected schemas through the real compiler and adapter."""
import argparse
import concurrent.futures
import os
import json
from pathlib import Path
import subprocess
import tempfile
import sys
p=argparse.ArgumentParser()
p.add_argument('--src',type=Path,default=Path('/usr/src'))
p.add_argument('--obj',type=Path,default=Path('/usr/obj/5bsd-fidl-runtime'))
p.add_argument('--tools',type=Path,default=Path('/usr/obj/5bsd-fidl'))
a=p.parse_args()
accepted=[]
cases=[
 ('closed','type Request = struct { text string:16; }; closed protocol Service { strict Call(Request) -> (Request); };',True,True),
 ('open','type Request = struct { text string:16; }; open protocol Service { flexible Call(Request) -> (Request); };',True,True),
 ('ajar','ajar protocol Service { flexible Notify(); flexible -> Changed(); strict Ping() -> (); };',True,True),
 ('flexible_empty','open protocol Service { flexible Ping() -> (); flexible Checked() -> () error uint32; };',True,True),
 ('anonymous','closed protocol Service { strict Call(struct { text string:16; }) -> (struct { text string:16; }); };',True,True),
 ('error','type Request = struct { text string:16; }; closed protocol Service { strict Call(Request) -> (Request) error uint32; };',True,True),
 ('endpoint','type Request = resource struct { ep client_end:Service; }; closed protocol Service { strict Call(Request) -> (Request); };',True,True),
 ('unsupported_rights','using zx; type Request = resource struct { fd zx.Handle:<NONE, zx.Rights.READ | zx.Rights.DUPLICATE>; }; closed protocol Service { strict Call(Request) -> (Request); };',False,False),
 ('native_handle','using zx; type Request = resource struct { fd zx.Handle:<NONE, zx.Rights.READ>; }; closed protocol Service { strict Call(Request) -> (Request); };',True,True),
 ('zircon_object','using zx; type Request = resource struct { fd zx.Handle:VMO; }; closed protocol Service { strict Call(Request) -> (Request); };',False,False),
 ('c_keyword','type Request = struct { switch uint32; UpperCase uint32; }; closed protocol Service { strict Call(Request) -> (Request); };',True,True),
 ('c_name_collision','type Request = struct { text string:16; text_size uint32; text_size_size string:16; }; closed protocol Service { strict Call(Request) -> (Request); };',True,True),
 ('no_payload','closed protocol Service { strict Ping() -> (); };',True,True),
 ('events_only','type Value = struct { value uint32; }; closed protocol Service { strict -> Changed(Value); };',True,True),
 ('nested','type Child = struct { text string:16; }; type Request = struct { items vector<Child>:8; flags array<bool,3>; next box<Request>; maybe string:<16,optional>; optional_items vector<Child>:<8,optional>; }; closed protocol Service { strict Call(Request) -> (Request); };',True,True),
 ('table_union','type State = strict enum : uint32 { OFF=0; ON=1; }; type Flags = strict bits : uint32 { FIRST=1; SECOND=2; }; type Choice = flexible union { 1: text string:16; 2: numbers vector<uint32>:4; }; type Request = table { 1: choice Choice; 2: state State; 3: flags Flags; }; closed protocol Service { strict Call(Request) -> (Request); };',True,True),
 ('containers','type Choice = strict union { 1: text string:8; 2: number uint32; }; type Request = struct { strings vector<string:<8,optional>>:4; matrix array<array<uint32,2>,3>; choices vector<Choice>:4; fixed array<Choice,2>; choice Choice:optional; nested vector<vector<bool>:4>:4; }; closed protocol Service { strict Call(Request) -> (Request); };',True,True),
 ('aggregate','type Request = struct { items vector<uint32>:8; }; closed protocol Service { strict Call(Request) -> (Request); };',True,True),
 # Owned-descriptor release passes for every aggregate kind, including a
 # recursive box and a payload without descriptors (which gets none).
 ('owned_release','using zx; type Inner = resource struct { fd zx.Handle; }; type Choice = flexible resource union { 1: fd zx.Handle; 2: inner Inner; 3: number uint32; }; type Options = resource table { 1: fd zx.Handle; 2: fds vector<zx.Handle>:4; 3: label string:8; }; type Request = resource struct { fds vector<zx.Handle>:4; fixed array<Inner,2>; maybe box<Inner>; choice Choice:optional; options Options; ep client_end:<Service, optional>; next box<Request>; label string:8; }; type Plain = struct { items vector<uint32>:8; next box<Plain>; }; closed protocol Service { strict Call(Request) -> (Plain); strict Note(Request); strict -> Changed(Request); strict Keep(Plain) -> (Plain); };',True,True),
]
with tempfile.TemporaryDirectory(prefix='generator-tests-',dir=a.obj) as tmp:
 root=Path(tmp)
 zx=root/'zx.fidl'
 zx.write_text('library zx; type ObjType = strict enum : uint32 { NONE = 0; VMO = 3; }; type Rights = strict bits : uint32 { DUPLICATE = 1; READ = 4; }; resource_definition Handle : uint32 { properties { subtype ObjType; rights Rights; }; };')
 for name,body,cpp_ok,c_ok in cases:
  source=root/(name+'.fidl'); source.write_text('library test.binding;\n'+body)
  ir=root/(name+'.json')
  compiler=subprocess.run([str(a.tools/'fidlc'),'--json',str(ir),'--files',str(zx),'--files',str(source)],text=True,capture_output=True)
  if compiler.returncode: raise RuntimeError(name+' compiler error: '+compiler.stderr)
  for c,expected in [(False,cpp_ok),(True,c_ok)]:
   output=root/(name+('-c' if c else '-cpp'))
   command=[sys.executable,str(a.src/'tools/build/fuchsia/generate-bsd.py'),'--json',str(ir),'--root',str(output)]
   if c:command+=['--c']
   result=subprocess.run(command,text=True,capture_output=True)
   if (result.returncode==0)!=expected:raise RuntimeError(name+' unexpected generation result: '+result.stdout+result.stderr)
   if not expected and output.exists() and any(output.rglob('*')):
    raise RuntimeError('rejected schema published partial bindings: '+name)
   if expected:
    accepted.append((name,c,output))
    artifacts={p.name for p in (output/'fidl/test.binding/cpp').iterdir()}
    if artifacts-{'natural_types.h','natural_types.cc','common_types.h','common_types.cc','markers.h','bsd.h'}:
     raise RuntimeError('unsupported Zircon messaging outputs escaped: '+str(artifacts))
   if expected and c and name == 'owned_release':
    # Release passes exist exactly for the aggregates that can hold
    # descriptors, and every C entry point taking one runs it on failure.
    bridge=(output/'fidl/test.binding/c/bridge.h').read_text()
    source=(output/'fidl/test.binding/c/bsd.cc').read_text()
    for present in ('CWRelease_test_binding_Request(','CWRelease_test_binding_Inner(','CWRelease_test_binding_Choice(','CWRelease_test_binding_Options('):
     if present not in bridge: raise RuntimeError('missing release pass: '+present)
    if 'CWRelease_test_binding_Plain(' in bridge: raise RuntimeError('release pass for a payload without descriptors')
    if source.count('CWRelease_test_binding_Request(fidl::bsd::cwire::OwnedRelease(e), ') != 3: raise RuntimeError('Call, Note and Changed must release owned descriptors on encode failure')
    if source.count('CWRelease_test_binding_Request(fidl::bsd::cwire::OwnedRelease(), ') != 3: raise RuntimeError('rejected arguments must release owned descriptors')
    if 'CWRelease_test_binding_Plain' in source: raise RuntimeError('Keep has no descriptors to release')
   if expected and c:
    # Compile every accepted public C header, including protocols with no requests.
    subprocess.run(['cc','-std=c11','-pedantic-errors','-fsyntax-only',
                    '-I'+str(a.src/'lib/libfidl/include'),'-I'+str(output),
                    '-x','c','-'],input='#include <fidl/test.binding/c/bsd.h>\n',
                   text=True,check=True)
   print(name+(' C' if c else ' C++')+': '+('accepted' if expected else 'rejected'),flush=True)
   if expected:
    first={str(p.relative_to(output)):p.read_bytes() for p in output.rglob('*') if p.is_file()}
    subprocess.run(command,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    second={str(p.relative_to(output)):p.read_bytes() for p in output.rglob('*') if p.is_file()}
    if first != second: raise RuntimeError('nondeterministic generation: '+name)
 # Every accepted schema must produce compilable and linkable implementations.
 f=a.src/'contrib/fuchsia'
 includes=[a.src/'lib/libfidl/include',a.src/'lib/libchannel',a.src/'sys',f/'sdk',
           f/'src/zircon/lib/zircon/include',f/'zircon/system/public']
 includes += [f/'sdk/lib'/part/'include' for part in ['fidl_base','fidl/cpp','fidl/cpp/wire','fit','stdcompat','zircon-assert']]
 flags=['-std=c++20','-pthread']+['-I'+str(p) for p in includes]
 sanitized=a.obj.name=='sanitized'
 if sanitized: flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
 channel=a.obj/'libchannel-sanitized.a' if sanitized else Path(subprocess.check_output(['make','-C',str(a.src/'lib/libchannel'),'-V','.OBJDIR'],text=True).strip())/'libchannel.a'
 def compile_case(case):
  name,c,output=case
  probe=output/'consumer.cc'
  probe.write_text('#include <fidl/test.binding/cpp/bsd.h>\nint main() { return 0; }\n')
  inputs=[output/'fidl/test.binding/cpp/natural_types.cc',output/'fidl/test.binding/cpp/common_types.cc',probe]
  if c:inputs.append(output/'fidl/test.binding/c/bsd.cc')
  binary=output/'consumer'
  command=['c++',*flags,'-I'+str(output),*map(str,inputs),str(a.obj/'libfidl_bsd.a'),str(channel),'-o',str(binary)]
  result=subprocess.run(command,text=True,capture_output=True)
  if result.returncode:raise RuntimeError(name+(' C' if c else ' C++')+' compile/link failed:\n'+result.stdout+result.stderr)
  env=dict(os.environ)
  if sanitized: env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
  subprocess.run([str(binary)],env=env,check=True,timeout=10)
 with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
  list(pool.map(compile_case,accepted))
 print(str(len(accepted))+' accepted C/C++ schemas compiled, linked, and generation repeated identically: PASS')

print(str(len(cases)*2)+' generator contract checks: PASS')
