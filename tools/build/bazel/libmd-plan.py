#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Export maintained libmd configuration and generator actions; no compile wrapper."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
from libmd_environment import BuildEnvironment
from libmd_paths import rewrite_includes

VARIABLES = ['MACHINE_ARCH', 'SRCS', '.PATH', 'CFLAGS', 'ACFLAGS', 'INCS', 'MAN',
             'MLINKS', 'SHLIB_MAJOR', 'SHLIBDIR', 'LIBDIR', 'PACKAGE', 'SYMBOL_MAPS',
             'VERSION_DEF', 'MK_MACHDEP_OPTIMIZATIONS', 'USE_ASM_SOURCES', 'LDFLAGS',
             'SOLINKOPTS', 'SSP_CFLAGS', 'LDADD', 'MK_CTF', 'ARFLAGS', 'MK_DEBUG_FILES', 'SHLIB_NAME', 'SHLIB_NAME_FULL', 'DEBUGFILE', 'STRIP', 'DEBUGFILEDIR', 'LIBMODE', 'LIBOWN', 'LIBGRP']


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def generate(src, output, make, assembly, objtop, profile, component=None):
    src = src.resolve(strict=True)
    output = output.absolute()
    if output.exists() or not output.is_relative_to('/usr/obj'):
        raise ValueError('output must be a new path under /usr/obj')
    if any(c in str(src) + str(output) for c in '\n\r\t $'):
        raise ValueError('source/output require unambiguous Make paths')
    if not (src / 'lib/libmd/Makefile').is_file():
        raise ValueError('source lacks maintained libmd')
    component = (component or (src / 'lib/libmd')).resolve(strict=True)
    buildenv = BuildEnvironment(src, objtop, profile, make, component)
    # All querying is configuration; Bazel actions never execute Make.
    output.mkdir(parents=True)
    obj = output / 'query-obj'
    obj.mkdir()
    extra = ['MK_MACHDEP_OPTIMIZATIONS=no'] if not assembly else []
    def query(args):
        return buildenv.query(args, obj=obj, extra=extra)
    values = query([x for key in VARIABLES for x in ('-V', '${' + key + '}')]).splitlines()
    if len(values) != len(VARIABLES):
        raise ValueError('ambiguous Make metadata')
    metadata = dict(zip(VARIABLES, values))
    component_closure = buildenv.capture_closure(obj=obj, extra=extra)
    if metadata['MACHINE_ARCH'] != 'amd64':
        raise ValueError('only maintained amd64 graph supported by this candidate')
    workspace = output / 'workspace'
    workspace.mkdir()
    snapshots = {}
    origins = {}
    copied_hashes = {}

    def copy(path):
        path = path.absolute()
        if not (path.resolve(strict=True).is_relative_to(src) or path.resolve(strict=True).is_relative_to(component)):
            raise ValueError('source alias escapes source tree: ' + str(path))
        relative = Path('lib/libmd') / path.relative_to(component) if path.is_relative_to(component) else path.relative_to(src)
        before = sha(path)
        target = workspace / 'sources' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copyfile(path, target)
        if sha(path) != before or sha(target) != before:
            raise ValueError('source snapshot changed during copy: ' + str(path))
        snapshots[str(relative)] = before
        origins[str(relative)] = str(path)
        copied_hashes[str(target.relative_to(workspace))] = before
        return 'sources/' + str(relative)

    dirs = [Path(x) if Path(x).is_absolute() else obj / x
            for x in shlex.split(metadata['.PATH'])]
    header_aliases = query(['-v', 'LIBMD_HEADER_ALIASES']).split()
    header_origins = query([v for name in header_aliases for v in ('-v', 'LIBMD_HEADER_SOURCE.' + name)]).splitlines() if header_aliases else []
    if len(header_origins) != len(header_aliases) or len(set(header_aliases)) != len(header_aliases):
        raise ValueError('invalid maintained header alias inventory')
    sources = []
    generated = []
    for name in shlex.split(metadata['SRCS']):
        if name in header_aliases:
            continue
        matches = [p / name for p in dirs if (p / name).is_file()]
        if matches:
            sources.append({'name': name, 'path': copy(matches[0]), 'generated': False})
        elif name.endswith('hl.c'):
            sources.append({'name': name, 'path': name, 'generated': True})
            generated.append(name)
        else:
            raise ValueError('unresolved source: ' + name)
    generated += [name for name in shlex.split(metadata['MAN']) if not (component / name).exists()]
    rewritten_flags, include_directories = rewrite_includes(shlex.split(metadata['CFLAGS']), src, obj, component)
    headers = []
    for directory in include_directories:
        headers.extend(copy(path) for path in sorted(directory.rglob('*'))
                       if path.is_file() and path.suffix in ('.h', '.inc', '.def'))
    for name, origin in zip(header_aliases, header_origins, strict=True):
        relative = Path(name)
        source = Path(origin).resolve(strict=True)
        if relative.is_absolute() or '..' in relative.parts or relative.suffix != '.h' or not source.is_relative_to(src):
            raise ValueError('invalid maintained header mapping')
        target = workspace / 'sources/lib/libmd' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        before = sha(source)
        shutil.copyfile(source, target)
        if sha(source) != before or sha(target) != before:
            raise ValueError('header mapping changed during copy')
        snapshots[str(source.relative_to(src))] = before
        origins[str(source.relative_to(src))] = str(source)
        copied_hashes[str(target.relative_to(workspace))] = before
        headers.append(str(target.relative_to(workspace)))
    actions = []
    hl_sources = query(['-v', 'LIBMD_GENHL_SRCS']).split()
    if set(hl_sources) != {s['name'] for s in sources if s['generated']}:
        raise ValueError('maintained high-level generator declaration missing or incomplete')
    for target in generated:
        high_level = target in hl_sources
        variable = ('LIBMD_GENHL_ARGS.' if high_level else 'LIBMD_GENMAN_ARGS.') + target
        arguments = shlex.split(query(['-v', variable]).strip())
        if len(arguments) != (4 if high_level else 2):
            raise ValueError('missing maintained generator arguments: ' + target)
        script = Path(query(['-v', 'LIBMD_GENHL_SCRIPT']).strip()) if high_level else component / 'genman.sh'
        inputs = [query(['-v', 'LIBMD_GENHL_TEMPLATE']).strip()] if high_level else ['mdX.3', arguments[0] + '.copyright']
        actions.append({'output': target, 'script': copy(script),
                        'kind': 'high_level' if high_level else 'manual',
                        'arguments': arguments,
                        'template': copy(component / inputs[0]),
                        'copyright': copy(component / inputs[1]) if not high_level else None,
                        'inputs': [copy(component / name) for name in inputs]})
    keys = [('ACFLAGS.' if item['name'].endswith('.S') else 'CFLAGS.') + item['name'] for item in sources]
    per_values = query([x for key in keys for x in ('-v', key)]).splitlines()
    if len(per_values) != len(sources):
        raise ValueError('ambiguous per-file Make options')
    per_file = {item['name']: value.strip() for item, value in zip(sources, per_values)}
    per_file_rewritten = {}
    for name, flags in per_file.items():
        per_file_rewritten[name], directories = rewrite_includes(shlex.split(flags), src, obj, component)
        for directory in directories:
            headers.extend(copy(path) for path in sorted(directory.rglob('*'))
                           if path.is_file() and path.suffix in ('.h', '.inc', '.def'))
    rewritten_acflags, directories = rewrite_includes(shlex.split(metadata['ACFLAGS']), src, obj, component)
    for directory in directories:
        headers.extend(copy(path) for path in sorted(directory.rglob('*'))
                       if path.is_file() and path.suffix in ('.h', '.inc', '.def'))
    for name in ('lib/libmd/Makefile', 'lib/libmd/Symbol.map', 'lib/libc/Versions.def',
                 'share/mk/version_gen.awk', 'share/mk/bsd.lib.mk', 'share/mk/bsd.prog.mk'):
        copy(component / Path(name).relative_to('lib/libmd') if name.startswith('lib/libmd/') else src / name)
    result = {'format': 1, 'scope': 'libmd graph configuration; not build/package qualification',
              'metadata': metadata, 'rewritten_cflags': rewritten_flags,
              'include_directories': [str(p) for p in include_directories],
              'sources': sources, 'headers': sorted(set(headers)),
              'generators': actions, 'per_file_flags': per_file,
              'per_file_rewritten': per_file_rewritten, 'rewritten_acflags': rewritten_acflags,
              'component_make_include_closure': component_closure,
              'source_root': str(src), 'make': str(make.resolve()), 'make_sha256': sha(make.resolve()),
              'source_sha256': snapshots, 'source_origins': origins, 'snapshot_sha256': copied_hashes, 'build_environment': buildenv.receipt(),
              'component_overrides': extra,
              'tool_execution_runtime': 'shell/sed/cat runtime closure must be explicitly staged before Bazel qualification',
              'bazel_runtime_qualified': False, 'package_qualified': False}
    buildenv.verify()
    if buildenv.capture_closure(obj=obj, extra=extra) != component_closure:
        raise ValueError('component Make include closure changed during export')
    for name, expected in snapshots.items():
        if sha(Path(origins[name])) != expected:
            raise ValueError('source changed during export: ' + name)
    for name, expected in copied_hashes.items():
        if sha(workspace / name) != expected:
            raise ValueError('snapshot changed during export: ' + name)
    (output / 'plan.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--src', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--make', type=Path, default=Path('/usr/bin/make'))
    p.add_argument('--objtop', type=Path, required=True)
    p.add_argument('--profile', type=Path, required=True)
    p.add_argument('--component', type=Path, help='explicit reviewed libmd overlay; defaults to source lib/libmd')
    p.add_argument('--without-asm', action='store_true')
    a = p.parse_args()
    generate(a.src, a.output, a.make, not a.without_asm, a.objtop, a.profile, a.component)


if __name__ == '__main__':
    main()
