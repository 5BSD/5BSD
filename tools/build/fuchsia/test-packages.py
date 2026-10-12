#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Create and inspect FIDL pkgbase archives from an existing native SDK stage.

This is a native-host packaging check, not a world/release publication. It
uses the normal plist and package generators. REPODIR stays canonical, but
stagepackages/publish targets are never called and no package is installed.
"""
import argparse
import json
import os
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
p.add_argument('--stage',type=Path,required=True)
a=p.parse_args()
stage=a.stage.resolve()
if not str(stage).startswith('/usr/obj/') or not (stage/'METALOG').is_file():
    p.error('use a completed native SDK stage under /usr/obj')
work=stage.parent/'package-check'
work.mkdir(exist_ok=True)
# Mirror the world packaging pipeline's metadata-to-plist conversion.
subprocess.run(['awk','-f',str(a.src/'release/scripts/mtree-to-plist.awk')],
    input='\n'.join(sorted((stage/'METALOG').read_text().splitlines()))+'\n',
    text=True,cwd=stage,check=True)
versions={name:subprocess.check_output(['pkg','query','%v',name],text=True).strip()
          for name in ['python312','re2']}
if any(not value or '\n' in value for value in versions.values()):
    raise RuntimeError('native SDK check needs installed Python 3.12 and RE2 versions')
env=dict(os.environ,MAKEOBJDIR=str(work))
make=['make','-C',str(a.src/'packages/libfidl'),
    'REPODIR=/usr/obj/usr/src/repo','PKG_VERSION=0.20261009.fidltest',
    'WSTAGEDIR='+str(stage),'PKG_ABI_FILE=/usr/bin/uname',
    'MK_DEBUG_FILES=no','MK_MAN=no','FIDL_SDK=yes']
missing=subprocess.run(make+['-V','_ALLPACKAGES'],env=env,text=True,
    stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
if missing.returncode==0 or 'FIDL_SDK requires' not in missing.stdout:
    raise RuntimeError('SDK packaging accepted unspecified target ports versions')
make+=['FIDL_PYTHON_VERSION='+versions['python312'],'FIDL_RE2_VERSION='+versions['re2']]
obj=Path(subprocess.check_output(make+['-V','.OBJDIR'],env=env,text=True).strip())
if obj!=work:
    raise RuntimeError('package check escaped its isolated object directory: '+str(obj))
subprocess.run(make+['clean'],env=env,check=True)
subprocess.run(make+['-j'+str(os.cpu_count()),'all'],env=env,check=True)
testmake=['make','-C',str(a.src/'packages/libfidl-tests'),
    'REPODIR=/usr/obj/usr/src/repo','PKG_VERSION=0.20261009.fidltest',
    'WSTAGEDIR='+str(stage),'PKG_ABI_FILE=/usr/bin/uname','MK_DEBUG_FILES=no']
subprocess.run(testmake+['-j'+str(os.cpu_count()),'all'],env=env,check=True)
expected={
 '5BSD-libfidl-tests': {'/usr/tests/lib/libfidl/Kyuafile',
                        '/usr/tests/lib/libfidl/runtime_test','/usr/tests/lib/libfidl/c_binding_test',
                        '/usr/share/licenses/libfidl-tests/fuchsia/LICENSE',
                        '/usr/share/licenses/libfidl-tests/fuchsia/PATENTS',
                        '/usr/share/licenses/libfidl-tests/googletest/LICENSE'},
 '5BSD-libfidl': {'/usr/lib/libfidl_bsd.so.1','/usr/share/licenses/libfidl/LICENSE',
                 '/usr/share/licenses/libfidl/PATENTS'},
 '5BSD-libfidl-dev': {'/usr/include/fidl/bsd/runtime_c.h','/usr/include/fidl/bsd/sync_c.h','/usr/share/fidl/zx.fidl','/usr/include/fidl/bsd/runtime.h',
                    '/usr/include/fidl/bsd/endpoint.h','/usr/lib/libfidl_bsd.a','/usr/libdata/pkgconfig/fidl.pc'},
 '5BSD-libfidl-tools': {'/usr/bin/fidlc','/usr/bin/fidl-format','/usr/bin/fidl-lint',
                      '/usr/bin/fidlgen-bsd','/usr/libexec/fidl/generate_bsd_c.py','/usr/libexec/fidl/generate_bsd_c_types.py',
                      '/usr/libexec/fidl/fidlgen_natural.py','/usr/libexec/fidl/fidlgen_reserved.py','/usr/libexec/fidl/gotemplate.py',
                      *['/usr/libexec/fidl/templates/'+t+'.tmpl' for t in ('file_markers','file_common_types_header','file_common_types_source','file_natural_types_header','file_natural_types_source','natural_struct','natural_table','natural_union','fragment_enum','fragment_bits','fragment_const','fragment_alias')],
                      '/usr/share/licenses/libfidl-tools/fuchsia/LICENSE',
                      '/usr/share/licenses/libfidl-tools/fuchsia/PATENTS',
                      '/usr/share/licenses/libfidl-tools/icu/LICENSE'},
}
seen={}; files=set()
for archive in sorted(work.glob('*.pkg')):
    manifest=json.loads(subprocess.check_output(['tar','-xOf',str(archive),'+MANIFEST'],text=True))
    name=manifest['name']; owned=set(manifest['files'])
    if name not in expected or not expected[name]<=owned:
        raise RuntimeError('unexpected or incomplete package '+name)
    if files&owned:
        raise RuntimeError('overlapping file ownership: '+str(files&owned))
    files|=owned;seen[name]=manifest
    if manifest['licenselogic']!='and':
        raise RuntimeError('mixed upstream/native licenses were not preserved')
if seen.keys()!=expected.keys():
    raise RuntimeError('missing package archives: '+str(expected.keys()-seen.keys()))
for name in ['5BSD-libchannel','5BSD-clibs']:
    if name not in seen['5BSD-libfidl']['deps']:
        raise RuntimeError('missing runtime dependency '+name)
for name in ['5BSD-libfidl','5BSD-libchannel-dev','5BSD-clibs-dev']:
    if name not in seen['5BSD-libfidl-dev']['deps']:
        raise RuntimeError('missing development dependency '+name)
tools=seen['5BSD-libfidl-tools']['deps']
for name,origin in [('python312','lang/python312'),('re2','devel/re2')]:
    if tools.get(name)!={'origin':origin,'version':versions[name]}:
        raise RuntimeError('incorrect ports dependency '+name+': '+str(tools))
    if '5BSD-'+name in tools:
        raise RuntimeError('ports dependency incorrectly prefixed as pkgbase')
if '5BSD-libfidl-dev' not in tools:
    raise RuntimeError('tools package is missing its native SDK headers dependency')
for name in ['5BSD-kyua','5BSD-set-base']:
    if name not in seen['5BSD-libfidl-tests']['deps']:
        raise RuntimeError('missing test package dependency '+name)
# Exercise the actual archive payload without installing packages on the host.
extracted=Path(tempfile.mkdtemp(prefix='extracted-',dir=work))
for archive in sorted(work.glob('*.pkg')):
    subprocess.run(['tar','--no-same-owner','-xf',str(archive),'-C',str(extracted),
                    '--exclude','+*'],check=True)
subprocess.run(['kyua','test','-k',str(extracted/'usr/tests/lib/libfidl/Kyuafile'),
                '--results-file='+str(work/'extracted-tests.db')],check=True,timeout=240)
runenv=dict(os.environ,LD_LIBRARY_PATH=str(extracted/'usr/lib')+':'+str(stage/'usr/lib'))
for language in ['c','cpp']:
    subprocess.run([str(stage.parent/('consumer-'+language+'-shared'))],
                   env=runenv,check=True,timeout=30)
# libchannel and base libraries are dependencies supplied by the native test
# host/stage. FIDL itself and its generator must come from the new archives.
subprocess.run([str(extracted/'usr/bin/fidlc'),'--json',str(extracted/'test.json'),
    '--files',str(stage.parent/'zx.fidl'),'--files',str(stage.parent/'runtime.fidl')],check=True)
subprocess.run([str(extracted/'usr/bin/fidlgen-bsd'),'--json',str(extracted/'test.json'),
    '--root',str(extracted/'generated'),'--c'],check=True)
subprocess.run([sys.executable,str(a.src/'lib/libfidl/tests/library_test.py'),'--src',str(a.src),'--obj',str(work),'--sdk',str(extracted),'--dependency-root',str(stage)],check=True,timeout=300)
(work/'result.json').write_text(json.dumps({'packages':sorted(seen),
    'files':len(files),'ports_versions':versions,'extracted_sdk_and_binary_roundtrips':True,'published':False},indent=2)+'\n')
print('FIDL runtime/development/tools/tests pkgbase archives, ownership, dependencies, extracted native tests: PASS; '+str(work))
