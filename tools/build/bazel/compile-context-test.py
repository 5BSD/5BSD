#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare configured compile contexts with real Make dry-run recipes.

Case JSON is an array of source, target, language, variant records. Sources
are the exact .IMPSRC spelling expected in the maintained recipe. The comparison
removes only the separately queried Make dependency-file arguments; Bazel owns
its own dependency output. This does not execute compilation or qualify emission.
"""
import argparse
import json
from pathlib import Path
import shlex
from compile_context import capture, compile_flags
from libmd_environment import BuildEnvironment, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('src', 'objtop', 'profile', 'component', 'cases', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    args = parser.parse_args()
    src = args.src.resolve(strict=True)
    component = (src / args.component).resolve(strict=True)
    out = args.output.resolve()
    if not component.is_relative_to(src):
        raise ValueError('component outside source tree')
    if out.exists() or not out.is_relative_to('/usr/obj') or out == Path('/usr/obj'):
        raise ValueError('fresh output below /usr/obj required')
    cases = json.loads(args.cases.read_text())
    if not isinstance(cases, list) or not cases:
        raise ValueError('nonempty case array required')
    out.mkdir()
    env = BuildEnvironment(src, args.objtop, args.profile, Path('/usr/bin/make'), component)
    results = []
    for index, case in enumerate(cases):
        obj = out / ('objects-' + str(index))
        obj.mkdir()
        source, target, language, variant = (case[k] for k in ('source', 'target', 'language', 'variant'))
        if variant not in ('regular', 'pic', 'pie', 'nossp_pic'):
            raise ValueError('unsupported variant')
        extra = case.get('make_assignments', [])
        if not isinstance(extra, list) or any(not isinstance(value, str) or '=' not in value or value.startswith('-') for value in extra):
            raise ValueError('Make test assignments must be variable assignments')
        record = capture(env, component, source, target, language, extra=extra, obj=obj)
        compiler = shlex.split(env.query(['-v', 'CXX' if language == 'c++' else 'CC'], obj=obj, extra=extra))
        dry = env.query(['-n', target], obj=obj, extra=extra)
        (out / ('make-' + str(index) + '.txt')).write_text(dry)
        commands = [shlex.split(line) for line in dry.splitlines() if line.strip()]
        tail = ['-c', source, '-o', target]
        actual = [line for line in commands if line[-4:] == tail]
        if len(actual) != 1:
            raise ValueError('expected exactly one source/object compile command')
        command = actual[0]
        dep = record['dependency_flags']
        starts = [i for i in range(len(command) - len(dep) + 1) if command[i:i + len(dep)] == dep] if dep else []
        if len(starts) > 1:
            raise ValueError('ambiguous Make dependency-file arguments')
        normalized = command[:starts[0]] + command[starts[0] + len(dep):] if starts else command
        expected = compiler + compile_flags(record, variant) + tail
        result = dict(case=case, context=record, actual=command, expected=expected,
                      make_dependency_arguments_present=bool(starts), passed=normalized == expected)
        results.append(result)
        (out / 'cases.json').write_text(json.dumps(results, indent=2) + '\n')
        if normalized != expected:
            raise ValueError('effective context differs from Make recipe; see cases.json')
    env.verify()
    helpers = [Path(__file__), Path(__file__).with_name('compile_context.py')]
    receipt = dict(status='passed', scope='Make compile-context parity only; no native build',
                   cases=results, environment=env.receipt(),
                   input_sha256={str(p.resolve()): digest(p) for p in [args.cases, *helpers]})
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('PASS:', len(results), 'Make compile contexts')


if __name__ == '__main__':
    main()
