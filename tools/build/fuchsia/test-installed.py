#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Build/install into disposable /usr/obj staging and run external C/C++ consumers."""
import argparse
import concurrent.futures
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

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--src', type=Path, default=Path('/usr/src'))
p.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-fidl-runtime'))
p.add_argument('--tools', type=Path, default=Path('/usr/obj/5bsd-fidl'))
p.add_argument('--packages', action='store_true', help='also create and test pkgbase archives')
a = p.parse_args()
a.obj.mkdir(parents=True, exist_ok=True)
work = Path(tempfile.mkdtemp(prefix='installed-api-', dir=a.obj))
stage = work/'root'
for directory in ['usr/lib','usr/include','usr/share/man/man3']:
    (stage/directory).mkdir(parents=True, exist_ok=True)
for relative in ['lib/libchannel','lib/libfidl','tools/build/fuchsia']:
    make = ['make','-C',str(a.src/relative),'FIDL_TOOLS_OBJ='+str(a.tools)]
    subprocess.run(make+['-j'+str(os.cpu_count()), 'MK_TESTS=no','MK_DEBUG_FILES=no','all'], check=True)
    subprocess.run(make+['DESTDIR='+str(stage),'NO_ROOT=yes','INSTALL=install -U -M '+str(stage/'METALOG')+' -D '+str(stage),'MK_DEBUG_FILES=no',
                        'MK_MAN=no','MK_TESTS=no','install',*(['installincludes'] if relative.startswith('lib/') else [])], check=True)
# Copy the consumer sources out of the checkout. The compiler has access only
# to public staged include paths and the application's generated sources.
generated = work/'generated'
for name in ['runtime.fidl','zx.fidl']:
    shutil.copyfile(a.src/'lib/libfidl/tests'/name,work/name)
subprocess.run([str(stage/'usr/bin/fidlc'),'--json',str(work/'runtime.json'),
                '--files',str(work/'zx.fidl'),'--files',str(work/'runtime.fidl')],check=True)
generator_command=[str(stage/'usr/bin/fidlgen-bsd'),'--json',str(work/'runtime.json'),
                   '--root',str(generated),'--c']
# An incomplete SDK must not silently borrow a source-tree host generator.
private=stage/'usr/libexec/fidl/fidlgen_cpp'
missing=private.with_suffix('.held')
private.rename(missing)
try:
    failure=subprocess.run(generator_command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if failure.returncode==0 or str(private) not in failure.stdout:
        raise RuntimeError('incomplete installed SDK did not fail at its pinned generator')
finally:
    missing.rename(private)
subprocess.run(generator_command,check=True)
for name in ['fidl-format','fidl-lint']:
    help_result=subprocess.run([str(stage/'usr/bin'/name),'--help'],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    # Upstream fidl-lint reports its help/usage exit status as 2.
    expected=2 if name=='fidl-lint' else 0
    if help_result.returncode != expected or '--help' not in help_result.stdout:
        raise RuntimeError(name+' help failed: '+help_result.stdout)

for name in ['c_binding_test.c','installed_client.cc']:
    shutil.copyfile(a.src/'lib/libfidl/tests'/name, work/name)
env = dict(os.environ, PKG_CONFIG_LIBDIR=str(stage/'usr/libdata/pkgconfig'),
           PKG_CONFIG_SYSROOT_DIR=str(stage), PKG_CONFIG_PATH='')
cflags = shlex.split(subprocess.check_output(['pkgconf','--cflags','fidl'], env=env, text=True))
libs = shlex.split(subprocess.check_output(['pkgconf','--libs','fidl'], env=env, text=True))
assert all('/usr/src' not in item for item in cflags+libs)
sources = [generated/'fidl/bsd.runtime.test/cpp/natural_types.cc',
           generated/'fidl/bsd.runtime.test/c/bsd.cc',work/'c_binding_test.c',work/'installed_client.cc',generated/'fidl/bsd.runtime.test/cpp/common_types.cc']
def compile(source):
    index=sources.index(source)
    target=work/(str(index)+'.o')
    compiler=['cc','-std=c11','-pedantic-errors'] if source.suffix=='.c' else ['c++','-std=c++20']
    subprocess.run(compiler+cflags+['-I'+str(generated),'-MMD','-MF',str(target)+'.d',
                                  '-c',str(source),'-o',str(target)],check=True)
    # Dependency files must prove headers came from the staged API, not checkout.
    if str(a.src) in Path(str(target)+'.d').read_text():
        raise RuntimeError('source-tree dependency escaped into installed API consumer')
    return target
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
    objects=list(pool.map(compile,sources))
runenv=dict(os.environ,LD_LIBRARY_PATH=str(stage/'usr/lib'))
for linkage in ['shared','static']:
 linkflags=shlex.split(subprocess.check_output(['pkgconf',*(['--static'] if linkage=='static' else []),'--libs','fidl'],env=env,text=True))
 linkflags+=['-lchannel']  # Consumers in this test create native channel pairs.
 if linkage=='static':
  linkflags=[str(stage/'usr/lib'/('lib'+flag[2:]+'.a')) if flag in ('-lfidl_bsd','-lchannel') else flag for flag in linkflags]
 for name,selected in [('c',[0,1,2,4]),('cpp',[0,3,4])]:
    binary=work/('consumer-'+name+'-'+linkage)
    # A C application may use its C linker; pkg-config supplies the C++ runtime.
    linker='cc' if name=='c' else 'c++'
    subprocess.run([linker,*map(str,[objects[i] for i in selected]),*linkflags,
                    '-Wl,-rpath,'+str(stage/'usr/lib'),'-o',str(binary)],check=True)
    dynamic=subprocess.check_output(['readelf','-d',str(binary)],text=True)
    for library in ['libfidl_bsd.so.1','libchannel.so.1']:
     if (library in dynamic) != (linkage=='shared'):
      raise RuntimeError('unexpected '+linkage+' dependency on '+library)
    subprocess.run([str(binary)],env=runenv,check=True,timeout=30)
# The maintained native LIBADD rules must also support a C-only program
# linking the runtime completely statically, including C++ ABI dependencies.
native=work/'native-c'
native.mkdir()
(native/'probe.c').write_text('#include <fidl/bsd/runtime_c.h>\nint main(void) { return fidl_bsd_runtime_abi_version() != FIDL_BSD_ABI_VERSION; }\n')
(native/'Makefile').write_text('PROG= probe\nSRCS= probe.c\nMAN=\nNO_SHARED= yes\nLIBADD= fidl_bsd\nCFLAGS+= '+shlex.join(cflags)+'\n.include <bsd.prog.mk>\n')
make=['make','-m',str(a.src/'share/mk'),'-C',str(native),'SRCTOP='+str(a.src),'MK_DEBUG_FILES=no','MK_TESTS=no',
      'LIBFIDL_BSD='+str(stage/'usr/lib/libfidl_bsd.a'),
      'LIBFIDL_BSDDIR='+str(stage/'usr/lib'),
      'LIBCHANNEL='+str(stage/'usr/lib/libchannel.a'),
      'LIBCHANNELDIR='+str(stage/'usr/lib'),'LIBSYS=/usr/lib/libsys.a','LIBSYSDIR=/usr/lib']
# Existing system C/C++ support libraries are appropriate for this native-host
# SDK check. Cross builds must use a complete target sysroot instead.
make += [name+'=/usr/lib' for name in ['LIBCPLUSPLUSDIR','LIBCXXRTDIR','LIBMDIR','LIBPTHREADDIR']]
subprocess.run(make+['-j'+str(os.cpu_count()),'all'],check=True)
native_obj=Path(subprocess.check_output(make+['-V','.OBJDIR'],text=True).strip())
probe=native_obj/'probe'
if 'NEEDED' in subprocess.check_output(['readelf','-d',str(probe)],text=True):
    raise RuntimeError('native C LIBADD probe was not fully static')
subprocess.run([str(probe)],check=True,timeout=10)
subprocess.run([sys.executable,str(a.src/'lib/libfidl/tests/library_test.py'),'--src',str(a.src),'--obj',str(work),'--sdk',str(stage)],check=True,timeout=300)
# Build the normal bsd.test.mk targets, stage them, and run the actual Kyuafile.
# These static binaries exercise library allocation wrapping and require no SDK
# or source files when run from an extracted test package.
subprocess.run([sys.executable,str(a.src/'tools/build/fuchsia/test-bindings.py'),
                '--src',str(a.src),'--obj',str(a.obj),'--tools',str(a.tools)],check=True)
testmake=['make','-C',str(a.src/'lib/libfidl/tests'),'MK_DEBUG_FILES=no',
          'MK_GOOGLETEST=yes']
# A host check must not pick target syscall stubs from an unfinished world.
# The host's kernel-matched base libraries supply native syscalls; FIDL and
# libchannel still come from the freshly built stage.
testmake += ['LIBFIDL_BSD='+str(stage/'usr/lib/libfidl_bsd.a'),
             'LIBFIDL_BSDDIR='+str(stage/'usr/lib'),
             'LIBCHANNEL='+str(stage/'usr/lib/libchannel.a'),
             'LIBCHANNELDIR='+str(stage/'usr/lib')]
for name in ['C','SYS','PTHREAD','CPLUSPLUS','CXXRT','M','COMPILER_RT','REGEX',
             'GTEST','GTEST_MAIN']:
    testmake += ['LIB'+name+'DIR=/usr/lib']
# Keep host-linked test objects separate from the target world's test objects.
testobj=work/'native-tests'
testobj.mkdir()
testenv=dict(os.environ,MAKEOBJDIR=str(testobj))
subprocess.run(testmake+['-j'+str(os.cpu_count()),'all'],env=testenv,check=True)
subprocess.run(testmake+['DESTDIR='+str(stage),'NO_ROOT=yes',
    'INSTALL=install -U -M '+str(stage/'METALOG')+' -D '+str(stage),'install'],env=testenv,check=True)
testdir=stage/'usr/tests/lib/libfidl'
for name in ['runtime_test','c_binding_test']:
    if 'NEEDED' in subprocess.check_output(['readelf','-d',str(testdir/name)],text=True):
        raise RuntimeError('packaged test must be static for allocation fault injection: '+name)
subprocess.run(['kyua','test','-k',str(testdir/'Kyuafile'),
                '--results-file='+str(work/'native-tests.db')],check=True,timeout=240)
print('Installed SDK, C11/C++ shared/static consumers, native static C LIBADD, packaged native tests: PASS; artifacts '+str(work),flush=True)

if a.packages:
    subprocess.run([sys.executable,str(a.src/'tools/build/fuchsia/test-packages.py'),
                    '--src',str(a.src),'--stage',str(stage)],check=True)
