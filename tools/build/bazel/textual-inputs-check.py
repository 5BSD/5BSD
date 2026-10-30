#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Verify per-source textual dependency edges in actual native compile actions."""
import argparse
import json
from pathlib import Path
from libmd_environment import digest


def actions(path):
    decoder = json.JSONDecoder()
    with path.open() as stream:
        buffer = ''; eof = False
        while True:
            buffer = buffer.lstrip()
            if not buffer and eof:
                return
            try:
                value, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                if eof:
                    raise ValueError('truncated or invalid execution log')
                chunk = stream.read(1024 * 1024)
                eof = not chunk
                buffer += chunk
                continue
            yield value
            buffer = buffer[end:]


def check_edges(source, inputs, inventory, textual):
    matches = [key for key in inventory if source == key or source.endswith('/' + key)]
    if not matches:
        if source in textual:
            raise ValueError('undeclared textual input compiled as a separate source')
        return
    if len(matches) != 1:
        raise ValueError('ambiguous source action')
    key = matches[0]
    entry = inventory[key]
    # Some fragments are also configured translation units (for example libm's
    # argument-reduction routines). The primary source is not a dependency edge.
    actual = (set(inputs) & textual) - {key}
    if actual != entry['expected']:
        raise ValueError('incorrect textual dependency edge: ' + source)
    entry['seen'] += 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'execution-log', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--component', required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    selected = [c for c in plan['components'] if c['component'] == args.component]
    if len(selected) != 1:
        raise ValueError('one selected component required')
    component = selected[0]; inventory = {}
    for record in component['sources']:
        suffix = ('sources/' + record['path'] if record['resolution'] == 'source' else
                  'generated/' + component['metadata']['LIB'] + '/' + record['name'])
        inventory[suffix] = dict(expected={'sources/' + item['path'] for item in record['textual_inputs']},
                                 count=len(record['compile_contexts']), seen=0)
    textual = set().union(*(entry['expected'] for entry in inventory.values()))
    if not textual:
        raise ValueError('selected component has no textual dependencies to qualify')
    for action in actions(args.execution_log):
        if action.get('mnemonic') != 'CppCompile':
            continue
        argv = action['commandArgs']
        if '-c' not in argv:
            continue
        source = argv[argv.index('-c') + 1]
        check_edges(source, [item['path'] for item in action['inputs']], inventory, textual)
    if any(entry['seen'] != entry['count'] for entry in inventory.values()):
        raise ValueError('incomplete selected compile action coverage')
    out = args.output.resolve()
    if out.exists() or not out.is_relative_to('/usr/obj') or out == Path('/usr/obj'):
        raise ValueError('fresh result directory below /usr/obj required')
    out.mkdir()
    (out/'receipt.json').write_text(json.dumps(dict(status='passed',
        scope='complete selected compile action textual-input edges; not cache mutation testing',
        plan_sha256=digest(args.plan), execution_log_sha256=digest(args.execution_log),
        driver_sha256=digest(Path(__file__)), sources=len(inventory),
        compile_actions=sum(entry['seen'] for entry in inventory.values()),
        textual_inputs=sorted(textual)), indent=2)+'\n')
    print('PASS: precise textual inputs across', sum(entry['seen'] for entry in inventory.values()), 'compile actions')


if __name__ == '__main__':
    main()
