#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Audit a configured Make kernel's selected link products; never build them.

This is an independent migration audit, not native build-time discovery.
Missing generated files and unbound custom products remain explicit in output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


VARIABLES = (
    '.CURDIR', '.OBJDIR', '.TARGET', 'S', 'KERN_IDENT', 'MACHINE', 'MACHINE_ARCH',
    'SYSTEM_OBJS', 'SYSTEM_LD_BASECMD', 'SYSTEM_LD', 'CFILES', 'SFILES',
    'GEN_CFILES', 'SYSTEM_CFILES', 'MFILES', 'BEFORE_DEPEND', 'DPSRCS',
    'FULLKERNEL', 'KERNEL_KO', 'LDSCRIPT', 'CC', 'CFLAGS', 'CTFFLAGS',
)
SOURCE_LISTS = ('CFILES', 'SFILES', 'GEN_CFILES', 'SYSTEM_CFILES', 'MFILES')


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def parse_query(text):
    lines = text.splitlines()
    if len(lines) != len(VARIABLES):
        raise ValueError('expected one Make output line per inventory variable')
    return dict(zip(VARIABLES, lines))


def link_objects(values):
    """Retain final-link additions that SYSTEM_OBJS alone does not include."""
    target = values['.TARGET']
    if target not in ('', '${.TARGET}'):
        raise ValueError('inventory query must not have an automatic target')
    prefix = shlex.split(values['SYSTEM_LD_BASECMD'])
    lexer = shlex.shlex(values['SYSTEM_LD'].removeprefix('@'), posix=True, punctuation_chars=';&|')
    lexer.whitespace_split = True
    lexer.commenters = ''
    tokens = list(lexer)
    split = next((i for i, token in enumerate(tokens) if token in (';', '&&', '||', '|', '&')), len(tokens))
    command, post_link_tokens = tokens[:split], tokens[split:]
    if not prefix or command[:len(prefix)] != prefix or command.count('-o') != 1:
        raise ValueError('unrecognized final kernel link expression')
    output_index = command.index('-o')
    if output_index < len(prefix):
        raise ValueError('final kernel output flag is inside base command')
    extra_link_arguments = command[len(prefix):output_index]
    # BSD Make retains unbound automatic variables in -V output. Remove
    # only the exact .TARGET placeholder, never a guessed output pathname.
    objects = command[output_index + 1:]
    if target:
        if not objects or objects[0] != target:
            raise ValueError('final kernel link output placeholder is missing')
        objects = objects[1:]
    system = shlex.split(values['SYSTEM_OBJS'])
    if not system or objects[:len(system)] != system:
        raise ValueError('final kernel link does not preserve SYSTEM_OBJS order')
    if any(not value.endswith(('.o', '.pico', '.fwo')) for value in objects):
        raise ValueError('unrecognized final-link product; inspect Make command')
    if len(objects) != len(set(objects)):
        raise ValueError('duplicate final kernel link product')
    return objects, objects[len(system):], extra_link_arguments, post_link_tokens


def describe(values, source_root, kernel_build_dir):
    source_root = Path(source_root).resolve(strict=True)
    kernel_build_dir = Path(kernel_build_dir).resolve(strict=True)
    for name in ('.CURDIR', '.OBJDIR'):
        if Path(values[name]).resolve(strict=True) != kernel_build_dir:
            raise ValueError('kernel query used an unexpected ' + name)
    configured_source = Path(values['S'])
    if not configured_source.is_absolute():
        configured_source = kernel_build_dir / configured_source
    if configured_source.resolve(strict=True) != source_root / 'sys':
        raise ValueError('configured kernel uses a different source tree')
    if not values['KERN_IDENT']:
        raise ValueError('configured kernel identity is missing')
    ordered, additions, extra_link_arguments, post_link_tokens = link_objects(values)
    files = {}
    candidates = {}
    for variable in SOURCE_LISTS:
        for token in shlex.split(values[variable]):
            path = Path(token)
            path = path if path.is_absolute() else kernel_build_dir / path
            path = path.resolve(strict=False)
            in_source = path.is_relative_to(source_root)
            if not in_source and not path.is_relative_to(kernel_build_dir):
                raise ValueError('kernel source escapes input roots: ' + str(path))
            present = path.is_file()
            if in_source and not present:
                raise ValueError('selected physical source is missing: ' + str(path))
            record = files.setdefault(str(path), {
                'origin': 'source' if in_source else 'generated',
                'present': present, 'sha256': sha256(path) if present else None,
                'lists': [],
            })
            record['lists'].append(variable)
            # Interface descriptions produce generated .c files, not direct
            # compiler inputs. GEN_CFILES carries their actual C identities.
            if path.suffix in ('.c', '.S', '.s', '.cc', '.cpp'):
                candidates.setdefault(path.with_suffix('.o').name, set()).add(str(path))
    products = []
    for name in ordered:
        matches = sorted(candidates.get(name, set()))
        products.append({'object': name, 'source_candidates': matches,
                         'binding': 'unique' if len(matches) == 1 else
                                    'ambiguous' if matches else 'unresolved'})
    return {
        'format': 1, 'query_status': 'passed',
        'scope': 'Configured Make kernel product audit; not native coverage, a build, or runtime qualification.',
        'kernel_identity': values['KERN_IDENT'], 'machine': values['MACHINE'],
        'machine_arch': values['MACHINE_ARCH'], 'variables': values,
        'configured_makefile_sha256': sha256(kernel_build_dir / 'Makefile'),
        'source_files': files, 'ordered_link_products': products,
        'final_link_additions': additions,
        'extra_link_arguments': extra_link_arguments,
        'post_link_tokens': post_link_tokens,
        'unresolved_products': [p['object'] for p in products if p['binding'] != 'unique'],
        'missing_generated_files': [p for p, record in files.items() if not record['present']],
    }


def audit(source_root, kernel_build_dir, machine, machine_arch, make='/usr/bin/make',
          src_conf='/dev/null', make_conf='/dev/null', source_env_conf='/dev/null'):
    source_root = Path(source_root).resolve(strict=True)
    kernel_build_dir = Path(kernel_build_dir).resolve(strict=True)
    command = [make, '-C', str(kernel_build_dir), '-m', str(source_root / 'share/mk'),
               'SRCCONF=' + str(src_conf), '__MAKE_CONF=' + str(make_conf),
               'SRC_ENV_CONF=' + str(source_env_conf)]
    for name in VARIABLES:
        command += ['-V', '${' + name + '}']
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise ValueError('Make kernel query failed: ' + result.stderr)
    values = parse_query(result.stdout)
    if (values['MACHINE'], values['MACHINE_ARCH']) != (machine, machine_arch):
        raise ValueError('configured kernel architecture does not match requested audit')
    report = describe(values, source_root, kernel_build_dir)
    report.update(command=command, query_stderr=result.stderr,
                  configuration={'src_conf': str(src_conf), 'make_conf': str(make_conf),
                                 'source_env_conf': str(source_env_conf)})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--kernel-build-dir', required=True, type=Path)
    parser.add_argument('--machine', required=True)
    parser.add_argument('--machine-arch', required=True)
    parser.add_argument('--make', default='/usr/bin/make')
    parser.add_argument('--src-conf', default='/dev/null')
    parser.add_argument('--make-conf', default='/dev/null')
    parser.add_argument('--source-env-conf', default='/dev/null')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = audit(args.source_root, args.kernel_build_dir, args.machine,
                   args.machine_arch, args.make, args.src_conf, args.make_conf,
                   args.source_env_conf)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({
        'query_status': report['query_status'],
        'selected_link_products': len(report['ordered_link_products']),
        'unresolved_products': report['unresolved_products'],
        'missing_generated_files': len(report['missing_generated_files']),
    }, sort_keys=True))


if __name__ == '__main__':
    main()
