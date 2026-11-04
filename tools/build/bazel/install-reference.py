#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Build and stage a native Make component as a Bazel comparison baseline.

This does not import Bazel outputs or establish package/runtime parity.
"""
import argparse
import json
import os
import re
from pathlib import Path
import shlex
import subprocess

import libmd_environment
import install_reference_options
from libmd_environment import BuildEnvironment, digest


def path(value, *, existing=True):
    if not value.is_absolute() or any(ord(c) < 32 or c == '$' for c in str(value)):
        raise ValueError('absolute paths without control characters or Make expansion required')
    return value.resolve(strict=existing)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'objtop', 'profile', 'component', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--target-arch', choices=['amd64','aarch64','riscv64'], default='amd64',
                        help='explicit recorded target ABI; execution tools remain native')
    parser.add_argument('--jobs', type=int, required=True)
    parser.add_argument('--make', type=Path, default=Path('/usr/bin/make'))
    parser.add_argument('--make-meta', action='store_true',
                        help='record original build recipes with supported metadata mode, without filemon')
    parser.add_argument('--with-option', action='append', default=[],
                        help='enable a component option against the unchanged recorded SDK')
    parser.add_argument('--without-option', action='append', default=[],
                        help='disable a component option against the unchanged recorded SDK')
    parser.add_argument('--with-local-option', action='append', default=[],
                        help='enable a library-local MK_ option not declared in src.opts.mk')
    parser.add_argument('--without-local-option', action='append', default=[],
                        help='disable a library-local MK_ option not declared in src.opts.mk')
    parser.add_argument('--make-define', action='append', default=[],
                        help='presence-only NAME=1 selector in the component basename namespace')
    parser.add_argument('--build-utc', type=int,
                        help='explicit nonnegative BUILD_UTC input for reproducible verifier references')
    parser.add_argument('--local-generated-header', action='append', default=[],
                        help='require this generated header basename from the isolated component object directory')
    args = parser.parse_args()
    if args.build_utc is not None and not 0 <= args.build_utc <= 2**63 - 1:
        parser.error('--build-utc must fit a nonnegative signed 64-bit integer')
    if (len(set(args.local_generated_header)) != len(args.local_generated_header) or
            any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*\.h', name) for name in args.local_generated_header)):
        parser.error('local generated headers require distinct simple .h basenames')
    if args.local_generated_header and not args.make_meta:
        parser.error('local generated-header auditing requires --make-meta')
    selected = args.with_option + args.without_option + args.with_local_option + args.without_local_option
    if len(set(selected)) != len(selected) or any(not re.fullmatch(r'[A-Z][A-Z0-9_]*', value) for value in selected):
        parser.error('component options must be distinct uppercase option names')
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
    definitions = install_reference_options.component_definitions(
        component, args.make_define, option_names=selected)
    environment = BuildEnvironment(src, objtop, profile, make, component, target_architecture=args.target_arch)
    definitions = install_reference_options.component_definitions(
        component, args.make_define, option_names=selected,
        profile_names=environment.assignments)
    # Verify the baseline before changing the isolated component configuration.
    environment.verify()
    component_options = {name: 'yes' for name in args.with_option}
    component_options.update({name: 'no' for name in args.without_option})
    for name, expected in component_options.items():
        # Keep the recorded world profile/SDK identity checks intact. Only this
        # isolated component reference receives explicit feature overrides.
        keys = {'WITH_' + name, 'WITHOUT_' + name}
        environment.options = [value for value in environment.options
                               if value.split('=', 1)[0] not in keys]
        environment.options.append(('WITH_' if expected == 'yes' else 'WITHOUT_') + name + '=1')
    local_options = {name: 'yes' for name in args.with_local_option}
    local_options.update({name: 'no' for name in args.without_local_option})
    for name, expected in local_options.items():
        environment.options.append('MK_' + name + '=' + expected)
    component_options.update(local_options)
    for name, expected in component_options.items():
        if environment.query(['-V', 'MK_' + name]).strip() != expected:
            raise ValueError('component option is unknown or ineffective: ' + name)
    for name, value in definitions.items():
        environment.options.append(name + '=' + value)
        if environment.query(['-V', name]).strip() != value:
            raise ValueError('component define is ineffective: ' + name)
    if args.build_utc is not None:
        environment.options.append('BUILD_UTC=' + str(args.build_utc))
        if environment.query(['-V', 'BUILD_UTC']).strip() != str(args.build_utc):
            raise ValueError('explicit reference BUILD_UTC input is ineffective')
    if definitions or args.build_utc is not None:
        identity = environment.query(['-V', 'OBJTOP', '-V', 'MACHINE', '-V', 'MACHINE_ARCH',
                                      '-V', '${CC}'], component=src / 'lib/libmd').splitlines()
        if (len(identity) != 4 or identity[:3] != [str(objtop), environment.assignments['TARGET'], environment.assignments['TARGET_ARCH']] or
                shlex.split(identity[3]) != environment.cc):
            raise ValueError('component define changed baseline SDK/target/compiler identity')
    if args.make_meta:
        install_reference_options.validate_metadata_component(environment.query)
    # Feature overrides can legitimately add/remove Makefile includes. Freeze
    # the selected configuration before building, retaining baseline hashes too.
    selected_closure = environment.capture_closure()
    for name, expected in environment.inputs.items():
        if digest(Path(name)) != expected:
            raise ValueError('build input changed while selecting component options: ' + name)
    environment.closure = selected_closure
    environment.inputs.update(selected_closure)
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
                       str(Path(libmd_environment.__file__).resolve()): digest(Path(libmd_environment.__file__)),
                       str(Path(install_reference_options.__file__).resolve()): digest(Path(install_reference_options.__file__))}
    receipt = {'format': 1, 'status': 'running', 'scope': 'native-amd64-Make-installation-reference' if args.target_arch == 'amd64' else 'cross-Make-installation-reference', 'target_architecture': args.target_arch,
               'component': str(component), 'jobs': args.jobs,
               'make_metadata': {'enabled': args.make_meta,
                                 'mode': 'meta missing-meta=yes nofilemon curdirok=yes' if args.make_meta else None},
               'component_options': component_options,
               'component_definitions': definitions,
               'build_utc': args.build_utc,
               'local_generated_headers': args.local_generated_header,
               'sdk_reconfigured': False, 'source_hashes': source_hashes,
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
        if args.local_generated_header:
            # Use the actual isolated component directory. A .OBJDIR expansion
            # here would be evaluated by the outer buildenv Make, not its child.
            component_objects = objects / str(component).lstrip('/')
            base += ['CFLAGS_EARLY=' + shlex.quote('-I' + str(component_objects))]
        if args.make_meta:
            base += ['.MAKE.MODE=meta missing-meta=yes nofilemon curdirok=yes']
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
        # Preserve phase ownership: common directory setup can emit package-tagged
        # links unrelated to this component. Keep the complete METALOG as well.
        directory_metadata = metalog.read_bytes()
        (output / 'directories.METALOG').write_bytes(directory_metadata)
        run(buildenv(base + flags + assignments + ['install']), 'install')
        # Make's distribution path installs configuration separately from install.
        groups=environment.query(['-V','CONFGROUPS'],extra=flags).split()
        configuration={group:environment.query(['-V',group],extra=flags).split() for group in groups}
        receipt['configuration_groups']=configuration
        if any(configuration.values()):
            run(buildenv(base + flags + assignments + ['installconfig']), 'installconfig')
        combined_metadata = metalog.read_bytes()
        if not combined_metadata.startswith(directory_metadata):
            raise ValueError('component install rewrote directory metadata')
        (output / 'component.METALOG').write_bytes(combined_metadata[len(directory_metadata):])
        receipt['metadata_phases'] = {
            name: digest(output / name)
            for name in ('directories.METALOG', 'component.METALOG')
        }
        component_objects = objects / str(component).lstrip('/')
        if component_objects.is_dir():
            header_audit = install_reference_options.audit_generated_headers(
                component_objects, objtop, args.local_generated_header)
            receipt['generated_header_audit'] = header_audit['required']
            receipt['equivalent_external_generated_headers'] = header_audit['equivalent_external_generated_headers']
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
