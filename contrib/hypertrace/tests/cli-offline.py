#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual CLI tests with only dtrace_open forced to NODEV|NOSYS."""
import hashlib
import json
import os
import resource
import shutil
from pathlib import Path
import subprocess
import sys

if len(sys.argv)!=3: raise SystemExit('usage: cli-offline.py /usr/obj/output /usr/obj/objtop')
out,obj=[Path(p).resolve() for p in sys.argv[1:]]
if not all(p.is_relative_to('/usr/obj') for p in (out,obj)) or out.exists():
    raise SystemExit('Use a new isolated /usr/obj output directory')
out.mkdir(parents=True)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
root=Path(__file__).resolve().parents[3]
binary=obj/'cddl/usr.sbin/dtrace/dtrace'
library=obj/'cddl/lib/libdtrace/libdtrace.so.2'
runtime=obj/'cddl/lib/drti/drti.o'
if not runtime.is_file(): raise SystemExit('Build source-tree cddl/lib/drti first')
shim=out/'nodev.c'
shim.write_text('''#include <dlfcn.h>
#include <stdlib.h>
void *dtrace_open(int version, int flags, int *errp) {
    void *(*real_open)(int, int, int *) = dlsym(RTLD_NEXT, "dtrace_open");
    if (!real_open) abort();
    return real_open(version, flags | 3, errp);
}
''')
subprocess.run(['/usr/bin/cc','-shared','-fPIC','-o',str(out/'nodev.so'),str(shim)],check=True)
env=os.environ.copy()
env['LD_PRELOAD']=str(out/'nodev.so')
env['LD_LIBRARY_PATH']=':'.join(str(obj/p) for p in ('cddl/lib/libdtrace','cddl/lib/libctf','lib/libproc','lib/librtld_db','lib/libnghttp2'))
# Explicit list: never run tracing, daemon connection or process-control modes.
cases=[
 ('version',['-V'],0,'dtrace:', ''),
 ('conflicting-modes',['-h','-V'],2,'','only one'),
 ('invalid-option',['-?'],2,'','Usage'),
 ('compile-valid',['-e','-x','nolibs','-n','BEGIN { trace(1); }'],0,'',''),
 ('compile-invalid',['-e','-x','nolibs','-n','BEGIN { trace(1 + ); }'],1,'','syntax error'),
 ('unknown-option',['-e','-x','nolibs','-x','no_such_option_97','-n','BEGIN { trace(1); }'],1,'','option'),
 ('bad-buffer-size',['-e','-x','nolibs','-b','-1','-n','BEGIN { trace(1); }'],1,'',''),
 ('quiet-compile',['-e','-q','-x','nolibs','-n','BEGIN { trace(1); }'],0,'',''),
 ('undefined-function',['-e','-x','nolibs','-n','BEGIN { missing_function_97(); }'],1,'','missing_function_97'),
 ('script-missing',['-e','-x','nolibs','-s',str(out/'absent.d')],1,'','absent.d'),
]
provider=out/'provider.d'
provider.write_text('provider offline_test { probe event(int); };\n')
header=out/'provider.h'
cases.append(('provider-header',['-h','-x','nolibs','-s',str(provider),'-o',str(header)],0,'',''))
invalid_provider=out/'invalid-provider.d'
invalid_provider.write_text('provider offline97 { probe event(int); };\n')
cases.append(('provider-invalid-name',['-h','-x','nolibs','-s',str(invalid_provider),'-o',str(out/'invalid.h')],1,'','may not end with a digit'))
cases.extend([
 ('resolvers-missing-value',['-e','-x','nolibs','-x','resolvers','-n','BEGIN { trace(1); }'],1,'','requires a value'),
 ('resolvers-both',['-e','-x','nolibs','-x','resolvers=hostname,version','-n','BEGIN { trace(1); }'],0,'',''),
 ('resolvers-version',['-e','-x','nolibs','-x','resolvers=version','-n','BEGIN { trace(1); }'],0,'',''),
 ('invalid-stdc',['-e','-x','nolibs','-X','bogus','-n','BEGIN { trace(1); }'],1,'','failed to set -X'),
 ('verbose-compile',['-e','-v','-x','nolibs','-n','BEGIN { trace(1); }'],0,'',''),
 ('flowindent-compile',['-e','-F','-x','nolibs','-n','BEGIN { trace(1); }'],0,'',''),
 ('header-buffered-invalid',['-h','-B','-x','nolibs','-s',str(provider)],2,'','not valid'),
])
results=[]
for name,args,status,stdout_text,stderr_text in cases:
    proc=subprocess.run([str(binary),*args],cwd=out,env=env,capture_output=True,text=True,timeout=30)
    passed=proc.returncode==status and stdout_text.lower() in proc.stdout.lower() and stderr_text.lower() in proc.stderr.lower()
    if name=='provider-header':
        passed=passed and header.is_file() and 'OFFLINE_TEST_EVENT' in header.read_text()
    if 'LLVM Profile Error' in proc.stderr: passed=False
    result={'case':name,'args':args,'status':proc.returncode,'stdout':proc.stdout,'stderr':proc.stderr,'passed':passed}
    results.append(result)
# Compile consumers without executing them. nm checks that the
# C++ header preserves the C linkage required by the provider linker.
for compiler,language in (('/usr/bin/cc','c'),('/usr/bin/c++','c++')):
    for valid in (True,False):
        name='header-consumer-'+language+('-valid' if valid else '-type-error')
        source=out/(name.replace('+','p')+'.c')
        argument='7' if valid else '"wrong"'
        source.write_text('#include "provider.h"\nvoid emit(void) { if (OFFLINE_TEST_EVENT_ENABLED()) OFFLINE_TEST_EVENT('+argument+'); }\n')
        objfile=source.with_suffix('.o')
        command=[compiler,'-x',language,'-Werror','-include',str(root/'sys/sys/sdt.h'),'-c',str(source),'-o',str(objfile)]
        proc=subprocess.run(command,capture_output=True,text=True,timeout=30)
        passed=(proc.returncode==0) if valid else (proc.returncode!=0 and 'error:' in proc.stderr)
        symbols=''
        if passed and valid:
            symbols=subprocess.check_output(['/usr/bin/nm','-u',str(objfile)],text=True)
            passed=all(symbol in symbols.split() for symbol in ('__dtrace_offline_test___event','__dtraceenabled_offline_test___event'))
        results.append({'case':name,'command':command,'status':proc.returncode,'stderr':proc.stderr,'symbols':symbols,'passed':passed})
# -G rewrites input objects, so each case receives a fresh disposable copy.
for language in ('c','cpp'):
    original=out/('header-consumer-'+language+'-valid.o')
    consumer=out/('provider-consumer-'+language+'.o')
    shutil.copyfile(original,consumer)
    generated=out/('provider-'+language+'.o')
    command=[str(binary),'-G','-x','nolibs','-x','syslibdir='+str(runtime.parent),'-s',str(provider),'-o',str(generated),str(consumer)]
    proc=subprocess.run(command,cwd=out,env=env,capture_output=True,text=True,timeout=30)
    passed=proc.returncode==0 and generated.is_file()
    sections=symbols=''
    if passed:
        sections=subprocess.check_output(['/usr/bin/readelf','-S',str(generated)],text=True)
        dof=out/('provider-'+language+'.dof')
        subprocess.run(['/usr/bin/objcopy','-O','binary','--only-section=.SUNW_dof',str(generated),str(dof)],check=True)
        data=dof.read_bytes()
        passed='.SUNW_dof' in sections and data.startswith(b'\x7fDOF') and b'offline_test\0' in data and b'event\0' in data
        combined=out/('combined-'+language+'.o')
        linked=subprocess.run(['/usr/bin/ld','-r','-o',str(combined),str(consumer),str(generated)],capture_output=True,text=True,timeout=30)
        passed=passed and linked.returncode==0
        if linked.returncode==0:
            symbols=subprocess.check_output(['/usr/bin/nm','-u',str(combined)],text=True)
            passed=passed and '__dtrace_offline_test___event' not in symbols and '__dtraceenabled_offline_test___event' not in symbols
    results.append({'case':'provider-link-'+language,'command':command,'status':proc.returncode,'stderr':proc.stderr,'sections':sections,'undefined_symbols':symbols,'passed':passed})
malformed=out/'malformed.o'
malformed.write_bytes(b'not an ELF object\n')
for name,input_file,destination in (
    ('provider-malformed-object',malformed,out/'malformed-provider.o'),
    ('provider-missing-object',out/'missing.o',out/'missing-provider.o'),
    ('provider-output-missing-directory',out/'header-consumer-c-valid.o',out/'absent/provider.o')):
    command=[str(binary),'-G','-x','nolibs','-x','syslibdir='+str(runtime.parent),'-s',str(provider),'-o',str(destination),str(input_file)]
    proc=subprocess.run(command,cwd=out,env=env,capture_output=True,text=True,timeout=30)
    results.append({'case':name,'command':command,'status':proc.returncode,'stderr':proc.stderr,
        'passed':proc.returncode==1 and bool(proc.stderr) and not destination.exists() and 'LLVM Profile Error' not in proc.stderr})
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'binary':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'runtime_object_sha256':hashlib.sha256(runtime.read_bytes()).hexdigest(),'runtime_object':str(runtime),'boundary':'dtrace_open forced NODEV|NOSYS using RTLD_NEXT; no other mocked APIs'},indent=2)+'\n')
failed=[r for r in results if not r['passed']]
for r in failed: print(json.dumps(r))
print(f'{len(results)-len(failed)}/{len(results)} actual CLI cases passed')
raise SystemExit(bool(failed))
