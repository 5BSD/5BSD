#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Build a selected hardware profile using native, unprivileged ports staging."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
from types import SimpleNamespace
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('hardware', Path(__file__).with_name('hardware-packages.py'))
hw = importlib.util.module_from_spec(spec); spec.loader.exec_module(hw)

# A target without hardware ports says so with this one profile entry.
NO_PORTS = 'no-hardware-ports'
ORIGIN = re.compile(r'[a-z0-9+_.-]+/[a-zA-Z0-9+_.-]+(@[a-zA-Z0-9+_.-]+)?')
BACKENDS = ('kernel-identity-only', 'native-ports')


def parse_profile(data):
    """Return the selected port origins, or None for a profile without ports.

    build-bsd reads the same grammar in profile_has_ports(), and
    usr.sbin/bsd-build/tests/hardware-profile-cases pins both readers.  A
    profile is ASCII text in lines ended by a newline.  '#' starts a comment,
    and blanks, tabs and carriage returns around an entry are ignored.  The
    entries are port origins, or NO_PORTS once and alone.
    """
    if b'\0' in data or not data.isascii():
        raise ValueError('hardware profile must be ASCII text')
    origins = []
    none = 0
    for line in data.decode('ascii').split('\n'):
        entry = line.split('#', 1)[0].strip(' \t\r')
        if entry == NO_PORTS:
            none += 1
        elif ORIGIN.fullmatch(entry):
            origins.append(entry)
        elif entry:
            raise ValueError('invalid port: ' + entry)
    if not none and not origins:
        raise ValueError('empty hardware profile')
    if none and (origins or none > 1):
        raise ValueError(NO_PORTS + ' must be the only hardware profile entry')
    return None if none else origins


def build(args):
    base = args.base.resolve(strict=True)
    archives = hw.inventory(base)
    kernels = [p for p,m in archives.values() if '/boot/kernel/kernel' in m.get('files', {})]
    if len(kernels) != 1:
        raise ValueError('select a base generation containing one kernel')
    kernel = kernels[0]
    # The profile is read once: what is parsed here is what is recorded.
    profile = args.profile.read_bytes()
    origins = parse_profile(profile)
    profile = profile.decode('ascii')
    backend = 'kernel-identity-only' if origins is None else 'native-ports'
    # build-bsd passes the backend its plan reported; a profile that no
    # longer selects it must not be published under that plan.
    if args.expect_backend not in (None, backend):
        raise ValueError('hardware profile selects ' + backend + ', not the planned ' +
                         args.expect_backend)
    if origins is not None:
        kernel_abi = hw.manifest(kernel)['abi']
        host_abi = hw.run(args.pkg, 'config', 'ABI', capture_output=True).stdout.strip()
        if kernel_abi.split(':')[-1] != host_abi.split(':')[-1]:
            raise ValueError('hardware ports require a target-native builder: kernel ABI ' +
                             kernel_abi + ', builder ABI ' + host_abi)
    digest = hw.kernel_hash(kernel)
    if hw.sha256(args.kernel_build / 'kernel') != digest:
        raise ValueError('kernel objects do not match base package')
    if not args.check and (args.output.exists() or args.output.is_symlink()):
        raise ValueError('output already exists; select a new output')
    if origins is None:
        # Nothing is compiled, so neither a ports tree, packaged source nor a
        # target-native builder is needed.  The kernel identity is sealed as
        # it is for a profile with ports, which keeps the publication format.
        if args.check:
            print('Kernel identity inputs verified (no hardware ports): ' + str(base))
            return
        with tempfile.TemporaryDirectory() as empty:
            hw.seal(SimpleNamespace(packages=Path(empty), seeds=[], kernel_package=kernel,
                output=args.output, epoch=int(time.time()), pkg=args.pkg))
        hw.verify(args.output, kernel)
        (args.output/'native-build.json').write_text(json.dumps(dict(uid=os.getuid(),
            base=str(base), profile=profile,
            kernel_sha256=digest, ports_built=[]), indent=2) + '\n')
        print('Verified kernel identity repository (no hardware ports): ' +
              str(args.output), flush=True)
        return
    if not (args.ports / 'Mk/bsd.port.mk').is_file():
        raise ValueError('PORTSDIR is not a ports checkout')
    for name in ('5BSD-src', '5BSD-src-sys'):
        if name not in archives:
            raise ValueError('missing source package: ' + name)
    for origin in origins:
        if not (args.ports / origin.split('@', 1)[0] / 'Makefile').is_file():
            raise ValueError('port missing from PORTSDIR: ' + origin)
    if args.check:
        print('Native hardware inputs verified: ' + str(base))
        return
    args.work.mkdir(parents=True, exist_ok=False)
    (args.work / 'uid').write_text(str(os.getuid()) + '\n')
    srcroot = args.work / 'source'
    srcroot.mkdir()
    for name in ('5BSD-src','5BSD-src-sys'):
        hw.run('tar', '-xf', archives[name][0], '-C', srcroot, '--exclude', '+*')
    src = srcroot / 'usr/src'
    version = re.search(r'^#define\s+__FreeBSD_version\s+(\d+)',
                       (src/'sys/sys/param.h').read_text(), re.M).group(1)
    config = args.work / 'make.conf'
    for path in (src, args.kernel_build, args.work, args.distfiles, args.ports):
        if not re.fullmatch(r'/[a-zA-Z0-9_./:+-]+', str(path)):
            raise ValueError('unsupported build path: ' + str(path))
    config.write_text(f'SRC_BASE={src}\nOSVERSION={version}\n'
        f'MAKE_ENV+= KERNBUILDDIR={args.kernel_build}\nBATCH=yes\n'
        f'MAKE_JOBS_NUMBER={os.cpu_count() or 1}\nWRKDIRPREFIX={args.work}/objects\n'
        f'DISTDIR={args.distfiles}\nNO_DEPENDS=yes\n')
    nodes = {}; visiting = set(); order = []
    def query(origin):
        if origin in nodes:
            return
        if origin in visiting:
            raise ValueError('dependency cycle: ' + origin)
        if not ORIGIN.fullmatch(origin):
            raise ValueError('invalid port: ' + origin)
        visiting.add(origin)
        port, _, flavor = origin.partition('@')
        cmd = ['make','-C',str(args.ports/port),'__MAKE_CONF='+str(config)]
        if flavor: cmd += ['FLAVOR='+flavor]
        keys = ['PKGBASE','PKGVERSION','PKGORIGIN','WRKDIR','RUN_DEPENDS',
                'BUILD_DEPENDS','LIB_DEPENDS','FETCH_DEPENDS','EXTRACT_DEPENDS','PATCH_DEPENDS']
        values = hw.run(*cmd,*[x for k in keys for x in ('-V',k)],capture_output=True).stdout.splitlines()
        if len(values) != len(keys): raise ValueError('invalid ports metadata: '+origin)
        data = dict(zip(keys,values)); deps = []
        # This native path never installs dependencies on the build host.
        # Require external build tools to be prepared explicitly.
        for key in keys[5:]:
            if data[key].strip():
                raise ValueError(f'{origin}: prepare declared {key} separately: {data[key]}')
        for dep in data['RUN_DEPENDS'].split():
            parts = dep.split(':')
            if len(parts) < 2: raise ValueError('invalid dependency: '+dep)
            deporigin = parts[1]
            # Firmware selection is separate from the DRM driver metapackage
            # in 5BSD. Broad profiles explicitly select gpu-firmware-kmod.
            if port == 'graphics/drm-kmod' and deporigin == 'graphics/gpu-firmware-kmod':
                continue
            query(deporigin); deps.append(deporigin)
        data.update(cmd=cmd,deps=deps)
        nodes[origin] = data; visiting.remove(origin); order.append(origin)
    seeds = []
    for origin in origins:
        query(origin); seeds.append(nodes[origin]['PKGBASE'])
    raw = args.work/'packages'; raw.mkdir()
    for index,origin in enumerate(order):
        data=nodes[origin]
        deps={nodes[d]['PKGBASE']: {'origin':nodes[d]['PKGORIGIN'], 'version':nodes[d]['PKGVERSION']} for d in data['deps']}
        depfile=args.work/('deps-'+str(index)+'.ucl')
        depfile.write_text(',\n'.join(json.dumps(k)+': '+json.dumps(v) for k,v in deps.items())+'\n')
        print(f'[{index+1}/{len(order)}] {origin}',flush=True)
        with (args.work/('port-'+str(index)+'.log')).open('w') as log:
            hw.run(*data['cmd'],'ACTUAL-PACKAGE-DEPENDS=cat '+str(depfile),
                   'package', stdout=log, stderr=log)
        package=Path(data['WRKDIR'])/'pkg'/(data['PKGBASE']+'-'+data['PKGVERSION']+'.pkg')
        meta=hw.manifest(package)
        if meta.get('deps',{}) != deps:
            raise ValueError('package dependency metadata mismatch: '+origin)
        shutil.copy2(package,raw/package.name)
    hw.closure(hw.inventory(raw),seeds)
    if hw.sha256(args.kernel_build/'kernel') != digest:
        raise ValueError('kernel changed during build')
    hw.seal(SimpleNamespace(packages=raw,seeds=seeds,kernel_package=kernel,
        output=args.output,epoch=int(time.time()),pkg=args.pkg))
    hw.verify(args.output,kernel)
    (args.output/'native-build.json').write_text(json.dumps(dict(uid=os.getuid(),
        base=str(base),ports=str(args.ports),profile=profile,
        kernel_sha256=digest,ports_built=order,work=str(args.work)),indent=2)+'\n')
    print('Verified native hardware repository: '+str(args.output),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('base','ports','kernel-build','profile','distfiles','work','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--pkg',default='/usr/local/sbin/pkg-static')
    p.add_argument('--check',action='store_true')
    p.add_argument('--expect-backend',choices=BACKENDS)
    args=p.parse_args()
    try: build(args)
    except (ValueError,OSError,KeyError,hw.subprocess.CalledProcessError) as e: p.exit(1,str(e)+'\n')

if __name__=='__main__': main()
