#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Build and stage a native Make component as a Bazel comparison baseline.

This does not import Bazel outputs or establish package/runtime parity.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess

import libmd_environment
from libmd_environment import BuildEnvironment, digest


def path(value, *, existing=True):
    if not value.is_absolute() or any(ord(c) < 32 or c == '$' for c in str(value)):
        raise ValueError('absolute paths without control characters or Make expansion required')
    return value.resolve(strict=existing)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'objtop', 'profile', 'component', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--jobs', type=int, required=True)
    parser.add_argument('--make', type=Path, default=Path('/usr/bin/make'))
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    src, objtop, profile, component, make = [path(p) for p in
        (args.src, args.objtop, args.profile, args.component, args.make)]
    output = path(args.output, existing=False)
    if (args.output.is_symlink() or output.exists() or
            output == Path('/usr/obj') or not output.is_relative_to('/usr/obj') or
            output.is_relative_to(src) or src.is_relative_to(output) or
            output == objtop or objtop.is_relative_to(output) or
            output.is_relative_to(objtop / 'tmp')):
        parser.error('output must be fresh below /usr/obj, separate from source and staged SDK')
    if component == src or not component.is_relative_to(src) or not (component / 'Makefile').is_file():
        parser.error('component must be a maintained directory within the actual source tree')
    environment = BuildEnvironment(src, objtop, profile, make, component)
    source_hashes = {str(p): digest(p) for p in component.rglob('*') if p.is_file()}
    # The baseline uses the maintained source layout, including tests' RELDIR.
    output.mkdir(parents=True, exist_ok=False)
    objects, stage = output / 'objects', output / 'stage'
    objects.mkdir(); stage.mkdir()
    metalog = output / 'METALOG'
    # Preserve distinct object directories for recursively visited components.
    build_environment = dict(environment.env, MAKEOBJDIR='${REFERENCE_OBJROOT}${.CURDIR}',
                             REFERENCE_OBJROOT=str(objects))
    implementations = {str(Path(__file__).resolve()): digest(Path(__file__)),
                       str(Path(libmd_environment.__file__).resolve()): digest(Path(libmd_environment.__file__))}
    receipt = {'format': 1, 'status': 'running', 'scope': 'native-amd64-Make-installation-reference',
               'component': str(component), 'jobs': args.jobs, 'source_hashes': source_hashes,
               'implementation_hashes': implementations,
               'object_environment': {key: build_environment[key] for key in ('MAKEOBJDIR', 'REFERENCE_OBJROOT')},
               'bazel_parity_qualified': False, 'runtime_qualified': False,
               'package_archives_created': False, 'host_installed': False,
               'limitations': ['Uses external Make-built SDK and execution runtime.',
                              'Component and Make configuration hashes are not a complete hermetic input closure.',
                              'NO_ROOT ownership and modes are logical METALOG values.'],
               'commands': []}

    def run(command, label):
        log = output / (label + '.log')
        with log.open('w') as stream:
            result = subprocess.run(command, env=build_environment, stdout=stream, stderr=subprocess.STDOUT)
        receipt['commands'].append({'argv': command, 'status': result.returncode,
                                    'log': log.name, 'log_sha256': digest(log)})
        if result.returncode:
            raise RuntimeError(label + ' failed; see ' + str(log))

    def buildenv(inner):
        return [str(make), '-C', str(src), *environment.fixed, *environment.options,
                'buildenv', 'BUILDENV_SHELL=' + shlex.join(inner)]

    try:
        base = [str(make), '-C', str(component),
                *environment.fixed, *environment.options]
        run(buildenv(base + ['-j' + str(args.jobs), 'all']), 'build')
        flags = ['NO_ROOT=yes', 'DB_FROM_SRC=yes', 'BUILD_PKGS=yes',
                 'DESTDIR=' + str(stage), 'METALOG=' + str(metalog)]
        # Query the actual top-level install contract, rather than duplicating flags.
        install = environment.query(['-f', 'Makefile.inc1', '-V', 'IMAKE_INSTALL'],
                                    component=src, extra=flags)
        assignments = shlex.split(install.strip())
        if len(assignments) != 1 or not assignments[0].startswith('INSTALL='):
            raise ValueError('ambiguous top-level installation configuration')
        receipt['install_configuration'] = install.strip()
        run([str(make), '-C', str(src), *environment.fixed, *environment.options,
             *flags, 'distrib-dirs'], 'directories')
        run(buildenv(base + flags + assignments + ['install']), 'install')
        environment.verify()
        if {str(p): digest(p) for p in component.rglob('*') if p.is_file()} != source_hashes:
            raise ValueError('component file set or contents changed during baseline')
        for implementation, expected in implementations.items():
            if digest(Path(implementation)) != expected:
                raise ValueError('helper changed during baseline: ' + implementation)
        receipt.update(status='passed', inputs_rechecked=True, metalog_sha256=digest(metalog))
    except Exception as error:
        receipt.update(status='failed', error=str(error))
        raise
    finally:
        receipt['environment'] = environment.receipt()
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(output / 'receipt.json')


if __name__ == '__main__':
    main()
