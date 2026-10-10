#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Build BSDTime's FIDL migration and run its host-safe C provider tests."""
import argparse
import concurrent.futures
import os
import shlex
from pathlib import Path
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
p.add_argument('--sanitize',action='store_true',help='instrument the provider, C client, bindings, runtime and transport')
p.add_argument('--packages',action='store_true',help='also validate debug/manual/provider pkgbase archives')
p.add_argument('--soak-seconds',type=int,default=0,help='run the opt-in resource soak after ordinary tests')
a=p.parse_args()
if a.soak_seconds < 0 or a.soak_seconds > 86400:
 p.error('--soak-seconds must be between 0 and 86400')
if a.sanitize and a.packages:
 p.error('--packages and --sanitize are separate runs')
a.obj.mkdir(parents=True,exist_ok=True)
work=Path(tempfile.mkdtemp(prefix='provider-',dir=a.obj))
subprocess.run([sys.executable,str(a.src/'tools/build/fuchsia/test-bindings.py'),'--src',str(a.src),'--obj',str(a.obj),'--tools',str(a.tools)],check=True)
if a.sanitize:
 # Build a separate instrumented runtime/transport; never change world objects.
 subprocess.run([sys.executable,str(a.src/'tools/build/fuchsia/build-runtime.py'),
                 '--src',str(a.src),'--obj',str(a.obj),'--tools',str(a.tools),'--sanitize'],check=True)
 sanitized=a.obj/'sanitized'
 flags=shlex.split(subprocess.check_output(['make','-C',str(a.src/'lib/libtimecmp'),
                                           '-V','${CFLAGS}'],text=True))
 flags=[flag for flag in flags if not flag.startswith('-std=')]
 flags+=['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',
         '-DBSDTIME_TESTING','-I'+str(a.src/'lib/libtimecmp'),
         '-I'+str(a.src/'usr.sbin/BSDTime'),'-I'+str(a.src/'contrib/libucl/include')]
 provider=a.src/'usr.sbin/BSDTime'
 library=a.src/'lib/libtimecmp'
 common=[provider/'BSDTime.c',provider/'config.c',library/'timecmp.c',library/'timecmp_legacy.c']
 common+=list((library/'generated').rglob('*.cc'))
 tests=[provider/'tests/provider_test.c',provider/'tests/config_test.c',library/'tests/protocol_test.c']
 soak=provider/'tests/resource_soak.c'
 sources=common+tests+[soak]
 objects={source:work/(str(index)+'.o') for index,source in enumerate(sources)}
 def compile(source):
  compiler=[os.environ.get('CC','cc'),'-std=gnu17'] if source.suffix=='.c' else [os.environ.get('CXX','c++'),'-std=c++20']
  subprocess.run(compiler+flags+['-c',str(source),'-o',str(objects[source])],check=True)
 with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
  list(pool.map(compile,sources))
 for test in tests+[soak]:
  # Real clock gates are wrapped even though these tests never mint a token.
  inputs=common if test.stem in ('provider_test','resource_soak') else ([provider/'config.c'] if test.stem=='config_test' else [library/'timecmp_legacy.c'])
  command=[os.environ.get('CXX','c++'),'-fsanitize=address,undefined','-pthread',
           *[str(objects[source]) for source in [test,*inputs]]]
  if test.stem in ('provider_test','resource_soak'):
   command+=['-Wl,--wrap=service_system_settime,--wrap=service_system_adjtime'+(',--wrap=syslog' if test==soak else ''),
             str(sanitized/'libfidl_bsd.a'),'/usr/lib/libservice.a',
             str(sanitized/'libchannel-sanitized.a'),'/usr/lib/libcapability.a',
             '/usr/lib/libtrustedzfs.a','/usr/lib/libcapsulert.a']
  command+=['/usr/lib/libprivateucl.a','/usr/lib/libprivateatf-c.a','-o',str(work/test.stem)]
  subprocess.run(command,check=True)
 (work/'Kyuafile').write_text('syntax(2)\ntest_suite("bsdtime-sanitized")\n'+
     ''.join('atf_test_program{name="'+test.stem+'",timeout=120}\n' for test in tests))
 env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
          UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
 subprocess.run(['kyua','test','-k',str(work/'Kyuafile'),'--results-file='+str(work/'results.db')],
                env=env,check=True,timeout=180)
 if a.soak_seconds:
  subprocess.run([str(work/'resource_soak'),str(a.soak_seconds)],env=env,check=True,timeout=a.soak_seconds+30)
 print('BSDTime C provider/client ASan/UBSan: PASS; '+str(work))
 print('Installed service/policy support libraries are not instrumented; leak sanitizer is unavailable. Real clock gates were not exercised.')
 sys.exit(0)
for relative in ['lib/libchannel','lib/libfidl','lib/libtimecmp','usr.sbin/BSDTime','usr.sbin/BSDTimectl']:
 subprocess.run(['make','-C',str(a.src/relative),'-j'+str(os.cpu_count()),'MK_TESTS=no','MK_DEBUG_FILES=no','all'],check=True)
base=['LIB'+name+'DIR=/usr/lib' for name in ['C','SYS','PTHREAD','CPLUSPLUS','CXXRT','M','COMPILER_RT','REGEX','ATF_C']]
# Keep kernel-matched base libraries local to this host validation.
for name,relative in [('TIMECMP','lib/libtimecmp'),('FIDL_BSD','lib/libfidl'),('CHANNEL','lib/libchannel')]:
 directory=Path(subprocess.check_output(['make','-C',str(a.src/relative),'-V','.OBJDIR'],text=True).strip())
 base+=['LIB'+name+'DIR='+str(directory),'LIB'+name+'='+str(directory/('lib'+{'TIMECMP':'timecmp','FIDL_BSD':'fidl_bsd','CHANNEL':'channel'}[name]+'.a'))]
for name,relative,selected in [('provider','usr.sbin/BSDTime/tests',['provider_test','config_test']),('legacy-abi','lib/libtimecmp/tests',[])]:
 directory=work/name;directory.mkdir()
 env=dict(os.environ,MAKEOBJDIR=str(directory))
 command=['make','-C',str(a.src/relative),'MK_DEBUG_FILES=no',*base]
 subprocess.run(command+['-j'+str(os.cpu_count()),'all'],env=env,check=True)
 subprocess.run(['kyua','test','-k',str(directory/'Kyuafile'),'--results-file='+str(directory/'results.db'),*selected],check=True,timeout=180)
if a.soak_seconds:
 subprocess.run([str(work/'provider/resource_soak'),str(a.soak_seconds)],check=True,timeout=a.soak_seconds+30)
print('BSDTime generated C provider/client, host-safe policy/adversarial/lifecycle tests and legacy ABI validator: PASS; '+str(work))
print('Real gate_test and full capability-plane activation remain VM requirements; no clock gate was exercised on this host.')

# Exercise the public ABI from installed headers, without generated or source
# includes. Static peers use kernel-matched system support libraries.
stage=work/'root'
for directory in ['usr/lib','usr/include','usr/share/fidl']:
 (stage/directory).mkdir(parents=True,exist_ok=True)
for relative in ['lib/libchannel','lib/libfidl','lib/libtimecmp']:
 subprocess.run(['make','-C',str(a.src/relative),'DESTDIR='+str(stage),'NO_ROOT=yes',
                 'INSTALL=install -U -M '+str(stage/'METALOG')+' -D '+str(stage),
                 'MK_DEBUG_FILES=no','MK_TESTS=no','MK_MAN=no','install','installincludes'],check=True)
probe=work/'api.c'
probe.write_text("""#include <timecmp.h>
#include <channel.h>
#include <unistd.h>
#include <errno.h>
int main(void) {
 struct timecmp_client *client = 0;
 struct timecmp_msg legacy = {TIMECMP_MAGIC, TIMECMP_OP_GET, 0, 0};
 if (timecmp_validate_message(&legacy, sizeof(legacy), TIMECMP_MESSAGE_REQUEST)) return 1;
 if (timecmp_client_create(-1, &client) != -1 || errno != EBADF || client != 0) return 2;
 if (timecmp_get(0, 0) != -1 || errno != EINVAL) return 3;
 if (timecmp_set(0, 0) != -1 || errno != EINVAL) return 4;
 if (timecmp_adjust(0, 0, 0) != -1 || errno != EINVAL) return 5;
 timecmp_client_close(0);
 int ends[2];
 if (mac_capability_channel_create(ends)) return 6;
 if (timecmp_client_create(ends[0], &client)) return 7;
 timecmp_client_close(client);
 close(ends[1]);
 return 0;
}
""")
env=dict(os.environ,LD_LIBRARY_PATH=str(stage/'usr/lib'))
for compiler,standard in [('cc','c11'),('c++','c++20')]:
 for mode in ['shared','static']:
  binary=work/('api-'+compiler+'-'+mode)
  flags=['-L'+str(stage/'usr/lib'),'-ltimecmp','-lchannel','-Wl,-rpath,'+str(stage/'usr/lib')]
  if mode=='static':
   flags=[str(stage/'usr/lib/libtimecmp.a'),'/usr/lib/libservice.a',
          str(stage/'usr/lib/libfidl_bsd.a'),str(stage/'usr/lib/libchannel.a'),
          '-lcapability','-ltrustedzfs','-lcapsulert','-lprivateucl','-lc++','-lcxxrt','-lm','-pthread']
  subprocess.run([compiler,'-x','c' if compiler=='cc' else 'c++','-std='+standard,
                  '-I'+str(stage/'usr/include'),'-c',str(probe),'-o',str(binary)+'.o'],check=True)
  subprocess.run([compiler,str(binary)+'.o',*flags,'-o',str(binary)],check=True)
  dynamic=subprocess.check_output(['readelf','-d',str(binary)],text=True)
  if ('libtimecmp.so.1' in dynamic)!=(mode=='shared'):
   raise RuntimeError('unexpected timecmp linkage in '+str(binary))
  subprocess.run([str(binary)],env=env,check=True,timeout=10)
print('Staged libtimecmp public C11/C++20 API, shared/static links and legacy C ABI: PASS; '+str(work))

if a.packages:
 subprocess.run([sys.executable,str(a.src/'tools/build/fuchsia/test-provider-packages.py'),
                 '--src',str(a.src),'--stage',str(stage),'--tools',str(a.tools)],check=True)
