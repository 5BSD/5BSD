#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Inventory evaluated build inputs; never execute tests or build/install targets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

TARGETS = (
    'cddl/lib/libdtrace', 'cddl/lib/drti', 'cddl/usr.sbin/dtrace',
    'usr.sbin/dtraced', 'usr.sbin/dtracedctl',
    'usr.sbin/BSDTrace', 'usr.sbin/tracectl', 'lib/libtracecmp',
    'lib/libservice', 'lib/libfidl', 'lib/libchannel', 'lib/liblogcmp',
    'usr.sbin/bhyve', 'usr.sbin/bhyvectl', 'lib/libvmmapi',
    'cddl/lib/libctf', 'lib/libelf', 'lib/libproc', 'lib/librtld_db',
    'sys/modules/dtrace/dtrace', 'sys/modules/dtrace/hypertrace',
    'sys/modules/dttransport', 'sys/modules/virtio/dtrace',
)
ARCHES = (('amd64', 'amd64'), ('arm64', 'aarch64'), ('riscv', 'riscv64'))
VARIABLES = ('SRCS', 'DPSRCS', 'LIBADD', 'INCS', 'MAN', 'SCRIPTS', 'FILES',
             'CONFS', 'BINDIR', 'LIBDIR', 'INCSDIR', 'PACKAGE', 'PROG',
             'PROG_CXX', 'LIB', 'LIB_CXX', 'KMOD', 'SUBDIR', 'FILESGROUPS',
             'GENSRCS', 'CLEANFILES', 'FIDL_BINDINGS', '_FIDLGEN_TOOLS',
             'CAPIMAGE_MANIFEST', '.PATH', '.MAKE.MAKEFILES')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--dependencies', action='store_true',
        help='Recursively evaluate declared LIBADD source directories')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    out = args.output.resolve()
    if not out.is_relative_to('/usr/obj') or out.exists():
        parser.error('Use a new isolated /usr/obj output directory')
    out.mkdir(parents=True)
    report = {'scope': ('Evaluated declared LIBADD closure; implicit toolchain dependencies and installed inventory remain open'
                        if args.dependencies else 'Evaluated seed build manifests, not a frozen transitive or installed inventory'),
              'live_tests': False, 'builds_executed': False, 'configurations': [],
              'limitations': [('Implicit compiler/runtime dependencies and static-only _DP dependencies are not recursively closed'
                   if args.dependencies else 'LIBADD dependencies are recorded but not recursively closed'),
                  'Architecture manifest evaluation does not prove architecture support',
                  'Generated inputs require build-output attribution',
                  'Conditional configurations beyond baseline and snapshot remain unenumerated',
                  'Installed-file paths require staging/package verification'],
              'driver_sha256': digest(Path(__file__)),
              'supplemental_inputs': [
                  {'path': name, 'sha256': digest(root/name),
                   'coverage': 'not-established-by-inventory',
                   'scope': 'service startup and install-manifest evidence; no installation verified'}
                  for name in ('libexec/rc/rc.d/dtraced', 'libexec/rc/rc.d/Makefile')]}

    # Do not inherit instrumentation or host make configuration into inventory.
    env = os.environ.copy()
    for name in ('MAKEFLAGS', 'MFLAGS', 'MAKEOBJDIR', 'MAKEOBJDIRPREFIX',
                 'CFLAGS', 'CXXFLAGS', 'LDFLAGS'):
        env.pop(name, None)
    for machine, arch in ARCHES:
        for snapshot in (False, True):
            targets = list(TARGETS)
            for target in targets:
                directory = root / target
                command = ['make', '-C', str(directory), '-m', str(root/'share/mk'),
                    'SRCTOP='+str(root), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
                    'MACHINE='+machine, 'MACHINE_ARCH='+arch,
                    'TARGET='+machine, 'TARGET_ARCH='+arch,
                    'WITH_BHYVE_SNAPSHOT=yes' if snapshot else 'WITHOUT_BHYVE_SNAPSHOT=yes']
                for variable in VARIABLES:
                    command += ['-V', '${'+variable+'}']
                process = subprocess.run(command, env=env, capture_output=True, text=True)
                entry = {'target': target, 'machine': machine, 'arch': arch,
                         'snapshot': snapshot, 'command': command,
                         'returncode': process.returncode, 'diagnostics': process.stderr,
                         'coverage': 'not-established-by-inventory'}
                lines = process.stdout.splitlines()
                if process.returncode or len(lines) != len(VARIABLES):
                    entry['status'] = 'evaluation-failed'
                    entry['stdout'] = process.stdout
                else:
                    values = dict(zip(VARIABLES, lines))
                    entry.update(status='evaluated', variables=values, inputs=[], makefiles={})
                    # Capability bundles and other nonstandard install groups
                    # are omitted by querying FILES alone.
                    groups = values['FILESGROUPS'].split()
                    group_variables = list(dict.fromkeys(v for g in groups
                        for v in (g, g+'DIR', g+'NAME', g+'PACKAGE')))
                    install_variables = set(group_variables)
                    bindings = values['FIDL_BINDINGS'].split()
                    fidl_inputs = ['FIDL_SCHEMAS.'+b for b in bindings]
                    group_variables += [v for b in bindings for v in
                        ('FIDL_SCHEMAS.'+b, 'FIDL_LIBRARY.'+b, 'FIDLGEN_SRCS.'+b)]
                    libraries = sorted(set(values['LIBADD'].split())) if args.dependencies else []
                    if libraries:
                        group_variables += ['_LIB_OBJTOP'] + ['LIB'+lib.upper()+'DIR' for lib in libraries]
                    if group_variables:
                        group_command = command[:command.index('-V')]
                        for variable in group_variables:
                            group_command += ['-V', '${'+variable+'}']
                        group_process = subprocess.run(group_command, env=env,
                            capture_output=True, text=True)
                        group_lines = group_process.stdout.splitlines()
                        if group_process.returncode or len(group_lines) != len(group_variables):
                            raise RuntimeError('Cannot inventory install groups: '+group_process.stderr)
                        extra_values = dict(zip(group_variables, group_lines))
                        entry['install_groups'] = {k:v for k,v in extra_values.items() if k in install_variables}
                        entry['build_metadata'] = {k:v for k,v in extra_values.items() if k not in install_variables}
                        values.update(extra_values)
                    entry['dependencies'] = []
                    for library in libraries:
                        name = values.get('LIB'+library.upper()+'DIR', '')
                        objtop = values.get('_LIB_OBJTOP', '')
                        dep = {'library': library, 'object_directory': name,
                               'target': None, 'status': 'unresolved-source-directory'}
                        if name and objtop and Path(name).is_absolute() and Path(objtop).is_absolute():
                            try:
                                relative = Path(name).relative_to(objtop)
                            except ValueError:
                                relative = None
                            if relative is not None:
                                source_dir = (root/relative).resolve()
                                if source_dir.is_relative_to(root) and (source_dir/'Makefile').is_file():
                                    dep.update(target=str(source_dir.relative_to(root)), status='manifest-discovered')
                                    if dep['target'] not in targets:
                                        targets.append(dep['target'])
                        entry['dependencies'].append(dep)
                    search = [directory] + [Path(p) if Path(p).is_absolute() else directory/p
                                            for p in values['.PATH'].split()]
                    for kind in dict.fromkeys(['SRCS', 'DPSRCS', 'INCS', 'MAN', 'SCRIPTS', 'FILES', 'CONFS',
                            '_FIDLGEN_TOOLS', 'CAPIMAGE_MANIFEST'] + groups + fidl_inputs):
                        for name in values[kind].split():
                            # FIDL schemas are explicitly SRCTOP-relative, unlike SRCS.
                            roots = [root] if kind in fidl_inputs else search
                            candidates = [Path(name)] if Path(name).is_absolute() else [p/name for p in roots]
                            found = next((p.resolve() for p in candidates if p.is_file()), None)
                            item = {'kind': kind, 'name': name,
                                    'resolution': 'unresolved-or-generated', 'path': None}
                            if found:
                                item.update(resolution='source' if found.is_relative_to(root) else 'external',
                                    path=str(found.relative_to(root)) if found.is_relative_to(root) else str(found),
                                    sha256=digest(found))
                            entry['inputs'].append(item)
                    for name in values['.MAKE.MAKEFILES'].split():
                        path = Path(name)
                        if not path.is_absolute(): path = directory/path
                        if path.is_file(): entry['makefiles'][str(path.resolve())] = digest(path)
                report['configurations'].append(entry)
    report['counts'] = {'evaluations': len(report['configurations']),
        'failures': sum(e['status'] != 'evaluated' for e in report['configurations']),
        'unique_resolved_inputs': len({i['path'] for e in report['configurations']
            for i in e.get('inputs', []) if i['path']}),
        'unresolved_dependency_occurrences': sum(d['target'] is None for e in report['configurations']
            for d in e.get('dependencies', [])),
        'unresolved_input_occurrences': sum(i['path'] is None for e in report['configurations']
            for i in e.get('inputs', []))}
    (out/'inventory.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report['counts']))

if __name__ == '__main__':
    main()
