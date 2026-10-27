#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Export native amd64 libmd driver inputs from the matching maintained Make profile.

No recipes are scraped or executed. ATF harness generation,
Bazel compilation, execution and installation remain separate qualification.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import shlex

import libmd_environment
from libmd_environment import BuildEnvironment, digest


def checked_path(value, existing=True):
    if not value.is_absolute() or any(ord(c) < 32 or c == '$' for c in str(value)):
        raise ValueError('absolute paths without control characters or Make expansion required')
    return value.resolve(strict=existing)


def query_values(environment, names, extra=()):
    arguments = [x for name in names for x in ['-V', name]]
    values = environment.query(arguments, extra=extra).splitlines()
    if len(values) != len(names):
        raise ValueError('ambiguous multiline Make metadata')
    return dict(zip(names, values))



def reference_inputs(files, programs, component, src):
    """Match maintained package .ref files to the existing <digest>driver ABI."""
    references, mapping = {}, {}
    for value in shlex.split(files):
        relative = PurePosixPath(value)
        if relative.suffix != '.ref':
            continue
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('reference must be relative to maintained test sources')
        source = (component / str(relative)).resolve(strict=True)
        if not source.is_relative_to(component) or not source.is_file():
            raise ValueError('reference escapes maintained tests')
        program = relative.stem + 'driver'
        if program not in programs or program in mapping:
            raise ValueError('unmatched or duplicate maintained reference: ' + value)
        record = {'staged_path': 'sources/' + str(source.relative_to(src)), 'sha256': digest(source)}
        references[str(source)] = record
        mapping[program] = {'reference': record['staged_path'],
                            'reference_origin': str(source), 'reference_sha256': record['sha256']}
    if set(mapping) != set(programs):
        raise ValueError('every maintained driver requires one package-listed source reference')
    return references, mapping



def artifact_contract(metadata, program):
    """Reject post-link policies for which the candidate has no declared actions."""
    if metadata['MK_DEBUG_FILES'] not in ('yes', 'no'):
        raise ValueError('unsupported MK_DEBUG_FILES policy')
    if metadata['MK_CTF'] != 'no':
        raise ValueError('CTF driver transformation requires explicit graph support')
    for key in ('ELF_FEATURES', '_ELF_FEATURE_EDIT', 'CAPIMAGE_MANIFEST', '_CAPIMAGE_INSTALL'):
        if metadata[key].strip():
            raise ValueError('unsupported driver transformation: ' + key)
    strip = shlex.split(metadata['STRIP'])
    if strip not in ([], ['-s']):
        raise ValueError('unsupported install STRIP policy')
    for key in ('PROG_FULL', 'PROGNAME'):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.+-]*', metadata[key]):
            raise ValueError('unsupported artifact basename: ' + key)
    if not re.fullmatch(r'[0-7]{3,4}', metadata['BINMODE']):
        raise ValueError('unsupported installed driver mode')
    for key in ('BINOWN', 'BINGRP'):
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', metadata[key]):
            raise ValueError('unsupported installed driver ownership: ' + key)
    debug = metadata['MK_DEBUG_FILES'] == 'yes'
    if debug:
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.+-]*', metadata['DEBUGFILE']):
            raise ValueError('unsupported debug artifact basename')
        directory = PurePosixPath(metadata['DEBUGFILEDIR'])
        if not directory.is_absolute() or '..' in directory.parts:
            raise ValueError('invalid maintained DEBUGFILEDIR')
        if len({metadata['PROG_FULL'], program, metadata['DEBUGFILE']}) != 3:
            raise ValueError('driver raw/stripped/debug outputs must be distinct')
    elif metadata['PROG_FULL'] != program:
        raise ValueError('non-debug driver raw output must match maintained program target')
    return {'raw_output': metadata['PROG_FULL'], 'program_output': program,
            'installed_name': metadata['PROGNAME'], 'split_debug': debug,
            'debug_output': metadata['DEBUGFILE'] if debug else None,
            'debug_install_directory': metadata['DEBUGFILEDIR'] if debug else None,
            'install_strip_flags': strip, 'install_directory': metadata['BINDIR'],
            'mode': metadata['BINMODE'], 'owner': metadata['BINOWN'], 'group': metadata['BINGRP']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'objtop', 'profile', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--make', type=Path, default=Path('/usr/bin/make'))
    args = parser.parse_args()
    src, objtop, profile, make = [checked_path(p) for p in (args.src, args.objtop, args.profile, args.make)]
    output = checked_path(args.output, existing=False)
    if (args.output.is_symlink() or output.exists() or output == Path('/usr/obj') or
            not output.is_relative_to('/usr/obj') or output.is_relative_to(src) or
            src.is_relative_to(output) or objtop.is_relative_to(output) or
            output.is_relative_to(objtop / 'tmp')):
        parser.error('output must be fresh below /usr/obj, separate from source and SDK')
    component = src / 'lib/libmd/tests'
    implementations = {str(p): digest(p) for p in
        [Path(__file__).resolve(), Path(libmd_environment.__file__).resolve()]}
    environment = BuildEnvironment(src, objtop, profile, make, component)
    base = query_values(environment, ['PROGS', 'TESTSDIR', 'ATF_TESTS_SH', 'PACKAGE', 'DIGESTS', 'LIBMD_TEST_GENERATOR', 'ATF_TESTS_SH_INTERPRETER'])
    programs = shlex.split(base['PROGS'])
    if not programs or len(programs) != len(set(programs)):
        raise ValueError('expected nonempty unique maintained PROGS')
    package = base['PACKAGE']
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', package):
        raise ValueError('unsupported maintained PACKAGE identifier')
    base.update(query_values(environment, [package + 'FILES', package + 'FILESDIR']))
    references, reference_map = reference_inputs(base[package + 'FILES'], programs, component, src)
    digests = shlex.split(base['DIGESTS'])
    if (not digests or len(set(digests)) != len(digests) or
            any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) for name in digests) or
            [name + 'driver' for name in digests] != programs):
        raise ValueError('maintained DIGESTS must correspond to the ordered driver inventory')
    generators = shlex.split(base['LIBMD_TEST_GENERATOR'])
    if len(generators) != 1:
        raise ValueError('one explicit maintained harness generator required')
    relative = PurePosixPath(generators[0])
    if relative.is_absolute() or '..' in relative.parts or relative.suffix != '.sh':
        raise ValueError('harness generator must be a relative shell source')
    generator = (component / str(relative)).resolve(strict=True)
    if not generator.is_relative_to(component) or not generator.is_file():
        raise ValueError('harness generator escapes maintained tests')
    generator_inputs = {str(generator): {'staged_path': 'sources/' + str(generator.relative_to(src)),
                                        'sha256': digest(generator)}}
    targets = shlex.split(base['ATF_TESTS_SH'])
    if not targets or len(set(targets)) != len(targets):
        raise ValueError('nonempty unique maintained ATF_TESTS_SH required')
    interpreter = base['ATF_TESTS_SH_INTERPRETER']
    if not re.fullmatch(r'/[A-Za-z0-9_./+-]+', interpreter) or '..' in PurePosixPath(interpreter).parts:
        raise ValueError('ATF interpreter must be an absolute target-system path without arguments')
    harness_targets = []
    for target in targets:
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', target):
            raise ValueError('unsupported maintained ATF target name')
        values = query_values(environment, ['ATF_TESTS_SH_SRC_' + target,
            'ATF_TESTS_SH_SED_' + target, 'SCRIPTSDIR_' + target,
            'SCRIPTSMODE_' + target, 'SCRIPTSOWN_' + target, 'SCRIPTSGRP_' + target])
        bodies = shlex.split(values['ATF_TESTS_SH_SRC_' + target])
        if len(bodies) != 1 or PurePosixPath(bodies[0]).is_absolute() or '..' in PurePosixPath(bodies[0]).parts:
            raise ValueError('one relative maintained ATF body target required')
        harness_targets.append({'target': target, 'body_target': bodies[0],
            'sed': values['ATF_TESTS_SH_SED_' + target],
            'scriptsdir': values['SCRIPTSDIR_' + target],
            'mode': values['SCRIPTSMODE_' + target], 'owner': values['SCRIPTSOWN_' + target],
            'group': values['SCRIPTSGRP_' + target]})
    harness = {'generator': generator_inputs[str(generator)]['staged_path'],
        'generator_origin': str(generator), 'generator_sha256': digest(generator),
        'arguments': digests, 'targets': harness_targets, 'output_kind': 'ATF shell body',
        'interpreter': interpreter, 'executable_wrapper': 'interpreter prefix plus generated body; configured sed requires explicit support'}
    drivers, sources, closures = [], {}, {}
    for program in programs:
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', program):
            raise ValueError('unsupported program identifier: ' + program)
        extra = ['PROG=' + program]
        closure = environment.capture_closure(extra=extra)
        names = ['LIBMD_TEST_SOURCE_' + program, 'SRCS', 'CFLAGS', 'CPPFLAGS',
                 'LDFLAGS', 'LIBADD', 'BINDIR', 'PROGNAME', 'PROG_FULL', 'DEBUGFILE',
                 'MK_DEBUG_FILES', 'STRIP', 'BINMODE', 'BINOWN', 'BINGRP', 'DEBUGFILEDIR',
                 'MK_CTF', 'CTFFLAGS', 'ELF_FEATURES', '_ELF_FEATURE_EDIT',
                 'CAPIMAGE_MANIFEST', '_CAPIMAGE_INSTALL', 'NO_SHARED', 'MK_PIE',
                 'DEBUG_FLAGS', 'DEBUG_FILES_CFLAGS', '_INSTALLFLAGS', 'TAGS']
        metadata = query_values(environment, names, extra)
        artifacts = artifact_contract(metadata, program)
        declared = shlex.split(metadata[names[0]])
        if len(declared) != 1:
            raise ValueError('driver requires one explicit maintained LIBMD_TEST_SOURCE: ' + program)
        relative = PurePosixPath(declared[0])
        if relative.is_absolute() or '..' in relative.parts or not relative.parts or relative.suffix != '.c':
            raise ValueError('driver source must be a relative C source inside maintained tests')
        source = (component / str(relative)).resolve(strict=True)
        if not source.is_relative_to(component) or not source.is_file():
            raise ValueError('driver source escapes maintained tests')
        staged = 'sources/' + str(source.relative_to(src))
        sources[str(source)] = {'staged_path': staged, 'sha256': digest(source)}
        destination = PurePosixPath(metadata['BINDIR'])
        if not destination.is_absolute() or '..' in destination.parts:
            raise ValueError('invalid maintained driver BINDIR')
        if environment.capture_closure(extra=extra) != closure:
            raise ValueError('per-program Make include closure changed during query')
        closures[program] = closure
        drivers.append({'program': program, 'source': staged, 'source_origin': str(source),
                        'source_sha256': sources[str(source)]['sha256'],
                        'cflags': shlex.split(metadata['CFLAGS']),
                        'cppflags': shlex.split(metadata['CPPFLAGS']),
                        'ldflags': shlex.split(metadata['LDFLAGS']),
                        'libadd': shlex.split(metadata['LIBADD']),
                        'bindir': metadata['BINDIR'], 'metadata': metadata, 'artifacts': artifacts, **reference_map[program]})
    environment.verify()
    for program, closure in closures.items():
        if environment.capture_closure(extra=['PROG=' + program]) != closure:
            raise ValueError('per-program Make closure changed before staging')
    # Validate all metadata before making output; stage declared original inputs,
    # never the generated per-program driver copies in the object tree.
    staged_inputs = {**sources, **references, **generator_inputs}
    output.mkdir(parents=True)
    try:
        for source, record in staged_inputs.items():
            destination = output / record['staged_path']
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(Path(source).read_bytes())
            if digest(destination) != record['sha256'] or digest(Path(source)) != record['sha256']:
                raise ValueError('source changed during snapshot: ' + source)
        environment.verify()
        for program, closure in closures.items():
            if environment.capture_closure(extra=['PROG=' + program]) != closure:
                raise ValueError('per-program Make closure changed during snapshot')
        for source, record in staged_inputs.items():
            if digest(Path(source)) != record['sha256'] or digest(output / record['staged_path']) != record['sha256']:
                raise ValueError('source changed before receipt: ' + source)
        for path, expected in implementations.items():
            if digest(Path(path)) != expected:
                raise ValueError('exporter changed during snapshot')
        receipt = {'format': 1, 'status': 'exported', 'scope': 'native-amd64-maintained-libmd-test-inputs',
                   'drivers': drivers, 'sources': sources, 'references': references, 'generator_inputs': generator_inputs, 'harness': harness, 'base_metadata': base,
                   'build_environment': environment.receipt(), 'program_make_include_closures': closures,
                   'implementation_sha256': implementations,
                   'limitations': ['C header and complete SDK closure are not exported here.',
                       'ATF body and wrapper policy are exported; Kyuafile graph support remains pending.',
                       'No Bazel compilation, runtime, installation or package parity is claimed.']}
        (output / 'inventory.json').write_text(json.dumps(receipt, indent=2) + '\n')
    except Exception as error:
        (output / 'FAILED.json').write_text(json.dumps({'status': 'failed', 'error': str(error)}, indent=2) + '\n')
        raise
    print(json.dumps({'inventory': str(output / 'inventory.json'), 'drivers': len(drivers), 'sources': len(sources), 'references': len(references)}))


if __name__ == '__main__':
    main()
