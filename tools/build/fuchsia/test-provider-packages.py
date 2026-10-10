#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check debug/manual/provider pkgbase payloads without publishing or installing.

Runtime archives contain only the staged BSDTime/BSDTimectl subset. They are
validation artifacts, not complete world packages or deployment candidates.
"""
import argparse
import json
import os
import re
import struct
import zlib
from pathlib import Path
import shutil
import subprocess
import tempfile
# Host-side builds use their own object root.  Plain make -C would otherwise
# write host-linked objects into the world's object tree, which an
# incremental buildworld then trusts and installs.
os.environ['MAKEOBJDIRPREFIX'] = '/usr/obj/5bsd-fidl-hostobj'

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--src', type=Path, default=Path('/usr/src'))
p.add_argument('--stage', type=Path, required=True, help='completed test-provider.py root')
p.add_argument('--tools', type=Path, default=Path('/usr/obj/5bsd-fidl'))
p.add_argument('--verify-work', type=Path, help='recheck existing archives from this tool without rebuilding')
a = p.parse_args()
a.stage = a.stage.resolve()
if not a.stage.is_relative_to('/usr/obj') or not (a.stage.parent/'api.c').is_file():
    p.error('use a completed provider API stage under /usr/obj')
package_sets = {
    'libfidl': ['libfidl','libfidl-dev','libfidl-dbg','libfidl-man','libfidl-tools'],
    'libfidl-tests': ['libfidl-tests','libfidl-tests-dbg'],
    'libtimecmp': ['libtimecmp','libtimecmp-dev','libtimecmp-dbg','libtimecmp-man'],
    'libtimecmp-tests': ['libtimecmp-tests','libtimecmp-tests-dbg'],
    'bsdtime-tests': ['bsdtime-tests','bsdtime-tests-dbg'],
    'runtime': ['runtime','runtime-dbg','runtime-man'],
}
if a.verify_work:
    work = a.verify_work.resolve()
    if work.parent != a.stage.parent or not work.name.startswith('package-validation-'):
        p.error('--verify-work must name a validation directory beside the supplied stage')
else:
    work = Path(tempfile.mkdtemp(prefix='package-validation-', dir=a.stage.parent))
stage = work/'root'
def build_packages():
    for directory in ['usr/lib', 'usr/include', 'usr/libdata/pkgconfig', 'usr/share/fidl',
                      'usr/share/man/man1', 'usr/share/man/man3', 'usr/share/man/man7',
                      'usr/share/man/man8', 'usr/sbin', 'usr/bin']:
        (stage/directory).mkdir(parents=True, exist_ok=True)
    # Support libraries match the running kernel; objects and debug files are fresh.
    base = ['LIB'+name+'DIR=/usr/lib' for name in
            ['C','SYS','PTHREAD','CPLUSPLUS','CXXRT','M','COMPILER_RT','REGEX','ATF_C','GTEST','GTEST_MAIN']]
    base += ['LIBCHANNELDIR='+str(a.stage/'usr/lib'),
             'LIBCHANNEL='+str(a.stage/'usr/lib/libchannel.a')]
    common = ['MK_DEBUG_FILES=yes', 'MK_MAN=yes', 'MK_MANSPLITPKG=yes', 'MK_TESTS=no']
    install = ['DESTDIR='+str(stage), 'NO_ROOT=yes',
               'INSTALL=install -U -M '+str(stage/'METALOG')+' -D '+str(stage)]
    projects = [
        ('fidl', 'lib/libfidl', 'FIDL_BSD', 'fidl_bsd'),
        ('timecmp', 'lib/libtimecmp', 'TIMECMP', 'timecmp'),
        ('provider', 'usr.sbin/BSDTime', None, None),
        ('ctl', 'usr.sbin/BSDTimectl', None, None),
        ('fidl-tests', 'lib/libfidl/tests', None, None),
        ('timecmp-tests', 'lib/libtimecmp/tests', None, None),
        ('provider-tests', 'usr.sbin/BSDTime/tests', None, None),
        ('tools', 'tools/build/fuchsia', None, None),
        ('overview', 'share/man/man7', None, None),
    ]
    for name, relative, library, filename in projects:
        obj = work/'obj'/name
        obj.mkdir(parents=True)
        env = dict(os.environ, MAKEOBJDIR=str(obj))
        extra = ['MK_GOOGLETEST=yes', 'FIDL_TOOLS_OBJ='+str(a.tools)]
        if name == 'overview':
            extra += ['MANGROUPS=FIDL', 'MAN=']
        make = ['make', '-C', str(a.src/relative), *common, *base, *extra]
        subprocess.run(make+['-j'+str(os.cpu_count()), 'all'], env=env, check=True)
        subprocess.run(make+install+['install', *(['installincludes'] if library else [])],
                       env=env, check=True)
        if library:
            base += ['LIB'+library+'DIR='+str(obj),
                     'LIB'+library+'='+str(obj/('lib'+filename+'.a'))]
    # Preserve the native channel dependency outside these component archives.
    shutil.copyfile(a.stage/'usr/lib/libchannel.so.1', stage/'usr/lib/libchannel.so.1')
    # Production metadata conversion, with no installation or publication targets.
    subprocess.run(['awk', '-f', str(a.src/'release/scripts/mtree-to-plist.awk')],
                   input='\n'.join(sorted((stage/'METALOG').read_text().splitlines()))+'\n',
                   text=True, cwd=stage, check=True)
    version = '0.20261009.fidltest'
    ports = {name: subprocess.check_output(['pkg','query','%v',name], text=True).strip()
             for name in ['python312','re2']}

    archives = []
    for directory, packages in package_sets.items():
        obj = work/'packages'/directory
        obj.mkdir(parents=True)
        env = dict(os.environ, MAKEOBJDIR=str(obj))
        command = ['make','-C',str(a.src/'packages'/directory),
                   'REPODIR=/usr/obj/usr/src/repo','PKG_VERSION='+version,
                   'WSTAGEDIR='+str(stage),'PKG_ABI_FILE=/usr/bin/uname',
                   'MK_DEBUG_FILES=yes','MK_MAN=yes','MK_MANSPLITPKG=yes',
                   'FIDL_SDK=yes','FIDL_PYTHON_VERSION='+ports['python312'],
                   'FIDL_RE2_VERSION='+ports['re2']]
        # Explicit targets let us check the provider subset of runtime without
        # manufacturing unrelated runtime-dev files from an incomplete world.
        subprocess.run(command+['-j'+str(os.cpu_count()),
                       *['5BSD-'+name+'-'+version+'.pkg' for name in packages]], env=env, check=True)
        archives += list(obj.glob('*.pkg'))
    return archives
archives = (list((work/'packages').glob('*/*.pkg')) if a.verify_work else build_packages())
seen, owners = {}, {}
evidence = Path(tempfile.mkdtemp(prefix='verification-', dir=work))
extracted = evidence/'extracted'
extracted.mkdir()
for archive in sorted(archives):
    manifest = json.loads(subprocess.check_output(['tar','-xOf',str(archive),'+MANIFEST'], text=True))
    name = manifest['name']
    if name in seen:
        raise RuntimeError('duplicate package '+name)
    seen[name] = manifest
    if name.endswith(('-dbg','-man','-dev')) and name.rsplit('-',1)[0] not in manifest.get('deps',{}):
        raise RuntimeError('subpackage lacks its base dependency: '+name)
    for filename in manifest['files']:
        if filename in owners:
            raise RuntimeError('overlapping file: '+filename)
        owners[filename] = name
    subprocess.run(['tar','--no-same-owner','-xf',str(archive),'-C',str(extracted),
                    '--exclude','+*'], check=True)
expected = {'5BSD-'+name for values in package_sets.values() for name in values}
if seen.keys() != expected:
    raise RuntimeError('incorrect archive set: '+str(seen.keys() ^ expected))
checks = {
    '/usr/lib/libfidl_bsd.so.1': 'libfidl',
    '/usr/lib/libtimecmp.so.1': 'libtimecmp',
    '/usr/lib/libtimecmp.a': 'libtimecmp-dev',
    '/usr/include/timecmp.h': 'libtimecmp-dev',
    '/usr/include/timecmp_protocol.h': 'libtimecmp-dev',
    '/usr/share/fidl/timecmp.fidl': 'libtimecmp-dev',
    '/usr/lib/debug/usr/lib/libfidl_bsd.so.1.debug': 'libfidl-dbg',
    '/usr/lib/debug/usr/lib/libtimecmp.so.1.debug': 'libtimecmp-dbg',
    '/Capabilities/System/Time.cap/Units/bsdtime.unit/bin/BSDTime': 'runtime',
    '/Capabilities/System/Time.cap/Bundle.ucl': 'runtime',
    '/Capabilities/System/Time.cap/Units/bsdtime.unit/Unit.ucl': 'runtime',
    '/Capabilities/System/Time.cap/Units/bsdtime.unit/Config/time.conf': 'runtime',
    '/usr/sbin/BSDTimectl': 'runtime',
    '/usr/share/licenses/libtimecmp/fuchsia/LICENSE': 'libtimecmp',
    '/usr/share/licenses/bsdtime-tests/fuchsia/LICENSE': 'bsdtime-tests',
    '/usr/share/licenses/bsdtime-tests/libucl/COPYING': 'bsdtime-tests',
}
for package, directory, tests in [
    ('libfidl-tests','lib/libfidl',['runtime_test','c_binding_test']),
    ('libtimecmp-tests','lib/libtimecmp',['protocol_test']),
    ('bsdtime-tests','usr.sbin/BSDTime',['provider_test','config_test','gate_test','resource_soak'])]:
    checks['/usr/tests/'+directory+'/Kyuafile'] = package
    for test in tests:
        checks['/usr/tests/'+directory+'/'+test] = package
        checks['/usr/lib/debug/usr/tests/'+directory+'/'+test+'.debug'] = package+'-dbg'
for filename, package in checks.items():
    if owners.get(filename) != '5BSD-'+package:
        raise RuntimeError('wrong/missing owner for '+filename+': '+str(owners.get(filename)))
for section, name, package in [('3','libfidl_bsd','libfidl-man'),
    ('1','fidlgen-bsd','libfidl-man'),('3','libtimecmp','libtimecmp-man'),
    ('3','timecmp_client_create','libtimecmp-man'),('7','fidl','runtime-man'),
    ('8','BSDTime','runtime-man'),('8','BSDTimectl','runtime-man')]:
    filename='/usr/share/man/man'+section+'/'+name+'.'+section+'.gz'
    if owners.get(filename) != '5BSD-'+package:
        raise RuntimeError('missing manual or alias '+filename)
for package, dependencies in {
    'libtimecmp': ['libservice','libfidl','clibs'],
    'libtimecmp-dev': ['libtimecmp','libservice-dev','libfidl-dev','clibs-dev'],
    'runtime': ['libtimecmp','libfidl','libservice','libchannel','libucl'],
    'bsdtime-tests': ['atf','kyua','set-base','libucl'],
}.items():
    for dependency in dependencies:
        if '5BSD-'+dependency not in seen['5BSD-'+package]['deps']:
            raise RuntimeError('missing dependency '+package+' -> '+dependency)
for package in ['libfidl','libfidl-tests','libtimecmp','bsdtime-tests']:
    manifest = seen['5BSD-'+package]
    if manifest['licenselogic'] != 'and' or not {'BSD2CLAUSE','BSD3CLAUSE'} <= set(manifest['licenses']):
        raise RuntimeError('incomplete license declaration in '+package)
# Every staged payload, including aliases/notices, must reach an archive.
for line in (stage/'METALOG').read_text().splitlines():
    fields = line.split()
    if fields and any(part in ('type=file','type=link') for part in fields):
        filename = fields[0].removeprefix('.')
        if filename not in owners:
            raise RuntimeError('unpackaged staged payload: '+filename)
# Every split debug file must carry DWARF and match an installed ELF debuglink.
for filename, owner in owners.items():
    if not owner.endswith('-dbg'):
        continue
    debug = extracted/filename.lstrip('/')
    sections = subprocess.check_output(['readelf','-S',str(debug)], text=True)
    if '.debug_info' not in sections and '.zdebug_info' not in sections:
        raise RuntimeError('debug file lacks DWARF: '+filename)
    relative = filename.removeprefix('/usr/lib/debug').removesuffix('.debug')
    if '/.debug/' in relative:
        relative = relative.replace('/.debug/','/')
    binary = extracted/relative.lstrip('/')
    link = subprocess.check_output(['readelf','--string-dump=.gnu_debuglink',str(binary)],text=True)
    if debug.name not in link:
        raise RuntimeError('debuglink mismatch for '+str(binary))
    dump = subprocess.check_output(['readelf','--hex-dump=.gnu_debuglink',str(binary)],text=True)
    data = bytearray()
    for line in dump.splitlines():
        if not line.startswith('0x'):
            continue
        for word in line.split()[1:5]:
            if not re.fullmatch('[0-9a-fA-F]{8}', word):
                break
            data.extend(bytes.fromhex(word))
    terminator = data.index(0)
    crc_offset = (terminator + 4) & ~3
    crc = struct.unpack_from('<I', data, crc_offset)[0]
    if crc != zlib.crc32(debug.read_bytes()):
        raise RuntimeError('debuglink CRC mismatch for '+str(binary))
# Execute archive contents on the host without installing or activating BSDTime.
test_counts = {}
for name, directory, selected in [
    ('fidl','lib/libfidl',[]),('timecmp','lib/libtimecmp',[]),
    ('provider','usr.sbin/BSDTime',['provider_test','config_test'])]:
    subprocess.run(['kyua','test','-k',str(extracted/'usr/tests'/directory/'Kyuafile'),
                    '--results-file='+str(evidence/(name+'.db')),*selected], check=True, timeout=240)
    report = subprocess.check_output(['kyua','report','--results-file='+str(evidence/(name+'.db'))],text=True)
    summary = re.search(r'Test cases: (\d+) total, (\d+) skipped, (\d+) expected failures, (\d+) broken, (\d+) failed',report)
    if not summary or int(summary[1]) == 0 or any(int(summary[i]) for i in range(2,6)):
        raise RuntimeError('incomplete extracted test run: '+report)
    test_counts[name] = int(summary[1])
# The auxiliary soak is installed but must never run implicitly through Kyua.
if 'resource_soak' in (extracted/'usr/tests/usr.sbin/BSDTime/Kyuafile').read_text():
    raise RuntimeError('opt-in resource soak was registered in ordinary Kyua tests')
soak_output = subprocess.check_output(
    [str(extracted/'usr/tests/usr.sbin/BSDTime/resource_soak'),'1'], text=True, timeout=30)
(evidence/'soak-smoke.jsonl').write_text(soak_output)
soak_result = json.loads(soak_output.splitlines()[-1])
if soak_result['status'] != 'PASS' or soak_result['measured_soak']:
    raise RuntimeError('extracted resource soak smoke failed or overstates coverage')
# Verify the safety interlock without enabling or exercising real clock gates.
gate_result = evidence/'gate-default.txt'
subprocess.run([str(extracted/'usr/tests/usr.sbin/BSDTime/gate_test'),
                '-r',str(gate_result),'gate_roundtrip'],check=True,timeout=10)
if not gate_result.read_text().startswith('skipped:') or 'vm_clock_test' not in gate_result.read_text():
    raise RuntimeError('real clock gate test was not disabled by default')
runenv = dict(os.environ, LD_LIBRARY_PATH=str(extracted/'usr/lib')+':'+str(a.stage/'usr/lib'))
# Compile anew against extracted headers and link extracted timecmp archives.
for compiler, standard in [('cc','c11'),('c++','c++20')]:
    for mode in ['shared','static']:
        binary=work/('api-'+compiler+'-'+mode)
        flags=['-L'+str(extracted/'usr/lib'),'-L'+str(a.stage/'usr/lib'),'-ltimecmp','-lchannel']
        if mode=='static':
            flags=[str(extracted/'usr/lib/libtimecmp.a'),'/usr/lib/libservice.a',
                   str(extracted/'usr/lib/libfidl_bsd.a'),str(a.stage/'usr/lib/libchannel.a'),
                   '-lcapability','-ltrustedzfs','-lcapsulert','-lprivateucl','-lc++','-lcxxrt','-lm','-pthread']
        subprocess.run([compiler,'-x','c' if compiler=='cc' else 'c++','-std='+standard,
                        '-I'+str(extracted/'usr/include'),'-I'+str(a.stage/'usr/include'),
                        '-c',str(a.stage.parent/'api.c'),'-o',str(binary)+'.o'],check=True)
        subprocess.run([compiler,str(binary)+'.o',*flags,'-o',str(binary)],check=True)
        subprocess.run([str(binary)],env=runenv,check=True,timeout=10)
(work/'result.json').write_text(json.dumps({'packages':sorted(seen),'owned_files':len(owners),
    'debug_dwarf_and_links':True,'manuals_and_aliases':True,'extracted_tests':test_counts,
    'soak_smoke':soak_result,'extracted_api':'C11/C++20 shared/static','real_clock_gate':'not run',
    'runtime_scope':'BSDTime/BSDTimectl subset only','published':False,'evidence':str(evidence)},indent=2)+'\n')
print('Debug/manual/provider package validation: PASS; '+str(work),flush=True)
