#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect real module CTF with host Python; never execute target code."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect(reader, module, full, policy, machine, elf_type):
    graphs = [reader.read_elf(path, allow_shared=elf_type == 3) for path in (full, module)]
    for graph in graphs:
        require(graph.elf_identity[:2] == (elf_type, machine), 'module ELF type/machine differs')
    require(graphs[0].ctf_sha256 == graphs[1].ctf_sha256, 'debug split changed CTF payload')
    equivalence = reader.compare(*graphs)
    expected = policy['ctf_types']
    require(isinstance(expected, dict) and expected, 'nonempty expected CTF object types required')
    checked = []
    for graph in graphs:
        for name, description in expected.items():
            parts = description.split(' ', 1)
            require(len(parts) == 2 and parts[0] == 'STRUCT' and parts[1],
                    'policy must name an exact STRUCT type')
            matches = [refs for (identity, _), refs in graph.symbols.items()
                       if identity[0] == name and identity[1] == 1]
            require(len(matches) == 1 and len(matches[0]) == 1 and matches[0][0] != 0,
                    'missing, unknown or ambiguous CTF object: ' + name)
            attrs, _ = graph.nodes[matches[0][0]]
            require(attrs[0] == 6 and attrs[2] == parts[1], 'CTF object type differs: ' + name)
        checked.append(len(expected))
    exports = {identity[0] for identity, _ in graphs[1].symbols
               if identity[2] in (1, 2)}
    require(exports == set(policy['exports']), 'module export identities differ')
    return {'passed': True, 'machine': machine, 'elf_type': elf_type,
            'symbol_associations': equivalence['symbol_associations'],
            'types': [len(graph.nodes) for graph in graphs],
            'expected_type_checks': sum(checked), 'exports': sorted(exports),
            'ctf_sha256': graphs[0].ctf_sha256,
            'scope': 'Static CTF type/symbol, export and full/runtime split checks only; no target execution, debug lookup, loader or runtime proof.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('reader', 'module', 'full', 'policy'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--machine', type=int, choices=(62, 183, 243), required=True)
    parser.add_argument('--elf-type', type=int, choices=(1, 3), required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    inputs = {name: hashlib.sha256(getattr(args, name).read_bytes()).hexdigest()
              for name in ('reader', 'module', 'full', 'policy')}
    report = {'passed': False, 'input_sha256': inputs}
    try:
        spec = importlib.util.spec_from_file_location('ctf_reader', args.reader)
        reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reader)
        report.update(inspect(reader, args.module, args.full,
                              json.loads(args.policy.read_text()), args.machine, args.elf_type))
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        encoded = json.dumps(report, indent=2) + '\n'
        destination = args.report
        if destination is None and os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR'):
            destination = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']) / 'module-ctf.json'
        if destination is not None:
            destination.write_text(encoded)
        print(encoded, end='')


if __name__ == '__main__':
    main()
