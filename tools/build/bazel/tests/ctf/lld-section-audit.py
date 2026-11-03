#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise LLD CTF sections with explicit tools and independent ABI fixtures."""
import argparse
import importlib.util
import itertools
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from types import SimpleNamespace


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--linker', required=True)
    p.add_argument('--fixtures', required=True)
    p.add_argument('--reader', required=True)
    p.add_argument('--work', default=os.environ.get('TEST_TMPDIR'))
    a = p.parse_args()
    if not a.work:
        p.error('--work is required outside Bazel')
    linker = str(Path(a.linker).resolve())
    reader = load('ctf_semantics', a.reader)
    fixtures = load('ctf_fixture', a.fixtures)
    work = Path(a.work).resolve() / 'lld-ctf-sections'
    work.mkdir(exist_ok=False, parents=True)
    commands, results = [], []

    def run(args, success=True):
        r = subprocess.run([linker] + list(map(str, args)), cwd=work,
                           capture_output=True, text=True)
        commands.append({'argv': [linker] + list(map(str, args)), 'exit': r.returncode,
                         'stdout': r.stdout, 'stderr': r.stderr})
        (work / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        assert (r.returncode == 0) == success, r.stderr
        return r

    def canonical(graph):
        symbols = {}
        for (identity, root), refs in graph.symbols.items():
            name, kind, binding, other, section, value, size = identity
            key = ((name, kind, binding, other, size), root)
            assert key not in symbols
            symbols[key] = refs
        return SimpleNamespace(nodes=graph.nodes, labels=graph.labels,
                               symbols=symbols, elf_identity=('CTF metadata',))

    def expected(graphs, selected=None):
        nodes, symbols, base = {}, {}, 0
        for number, graph in enumerate(graphs):
            for index, (attrs, refs) in graph.nodes.items():
                nodes[base + index] = (attrs, tuple(base + ref if ref else 0 for ref in refs))
            for key, refs in canonical(graph).symbols.items():
                if selected is None or number == selected:
                    symbols[key] = tuple(base + ref if ref else 0 for ref in refs)
            base += max(graph.nodes, default=0)
        return SimpleNamespace(nodes=nodes, labels=graphs[0].labels,
                               symbols=symbols, elf_identity=('CTF metadata',))

    def make(name, fmt, prefix, binding=1, distinct=False):
        version, endian, compressed = fmt
        def mutate(defs):
            defs[4][2] = 'different_gateway'
        ctf, symbols = fixtures.fixture(version=version, endian=endian,
            compressed=compressed, mutation=mutate if distinct else None)
        symbols = [(prefix + row[0], row[1], binding, *row[3:]) for row in symbols]
        graph = reader.Graph(ctf, symbols)
        path = work / name
        path.write_bytes(fixtures.elf(ctf, symbols))
        return path, graph

    formats = list(itertools.product((2, 3), ('<', '>'), (False, True)))
    for i, left in enumerate(formats):
        for j, right in enumerate(formats):
            lp, lg = make('left.o', left, 'left_')
            rp, rg = make('right.o', right, 'right_')
            want = expected([lg, rg])
            for mode in ('-r', '-shared'):
                output = work / f'pair-{i}-{j}-{mode[1:]}'
                run([mode, '-o', output, lp, rp])
                graph = reader.read_elf(output, allow_shared=mode == '-shared')
                comparison = reader.compare(want, canonical(graph))
                assert comparison['symbol_associations'] == 4
                results.append({'case': 'format-pair', 'left': left, 'right': right,
                                'mode': mode, 'types': len(graph.nodes)})

    # A losing file's types remain in the dictionary, while selected symbol
    # associations must follow the prevailing definition's exact input index.
    for first_binding, second_binding, selected in ((2, 1, 1), (1, 2, 0), (2, 2, 0)):
        lp, lg = make('left.o', formats[0], '', first_binding)
        rp, rg = make('right.o', formats[-1], '', second_binding, distinct=True)
        want = expected([lg, rg], selected)
        output = work / f'resolution-{first_binding}-{second_binding}'
        run(['-r', '-o', output, lp, rp])
        graph = reader.read_elf(output)
        reader.compare(want, canonical(graph))
        results.append({'case': 'definition-selection', 'bindings': [first_binding, second_binding]})

    lp, lg = make('left.o', formats[0], 'left_')
    rp, rg = make('right.o', formats[-1], 'right_')
    script = work / 'selection.ld'
    script.write_text('SECTIONS { .text : { *(.text) } .data : { *(.data) } '
                      '.SUNW_ctf : { left.o(.SUNW_ctf) } '
                      '/DISCARD/ : { right.o(.SUNW_ctf) } }\n')
    output = work / 'selected.o'
    run(['-r', '-T', script, '-o', output, 'left.o', 'right.o'])
    graph = reader.read_elf(output)
    want = expected([lg])
    for (identity, root), refs in canonical(rg).symbols.items():
        want.symbols[(identity, False)] = (0,) if identity[1] == 1 else ()
    reader.compare(want, canonical(graph))
    results.append({'case': 'script-file-selection-and-discard'})

    # Both malformed linkage and invalid output containers must be rejected.
    original = lp.read_bytes()
    shoff = struct.unpack_from('<Q', original, 40)[0]
    malformed = bytearray(original)
    struct.pack_into('<I', malformed, shoff + 5 * 64 + 40, 3) # STRTAB, not SYMTAB.
    (work / 'bad-link.o').write_bytes(malformed)
    r = run(['-r', '-o', 'bad.o', 'bad-link.o'], success=False)
    assert 'CTF sh_link' in r.stderr
    results.append({'case': 'reject-wrong-input-symtab-link'})
    malformed = bytearray(original)
    struct.pack_into('<Q', malformed, shoff + 5 * 64 + 8, 2) # SHF_ALLOC.
    (work / 'allocated.o').write_bytes(malformed)
    r = run(['-r', '-o', 'bad.o', 'allocated.o'], success=False)
    assert 'unsupported CTF section' in r.stderr
    results.append({'case': 'reject-allocated-input-ctf'})
    script.write_text('SECTIONS { .SUNW_ctf : { *(.SUNW_ctf) BYTE(0) } }\n')
    r = run(['-r', '-T', script, '-o', 'bad.o', 'left.o'], success=False)
    assert 'must occupy its output section' in r.stderr
    results.append({'case': 'reject-trailing-output-data'})
    script.write_text('SECTIONS { /DISCARD/ : { *(.SUNW_ctf) } }\n')
    run(['-r', '-T', script, '-o', 'discarded.o', 'left.o', 'right.o'])
    data = (work / 'discarded.o').read_bytes()
    shoff = struct.unpack_from('<Q', data, 40)[0]
    count, names = struct.unpack_from('<HH', data, 60)
    entry = struct.unpack_from('<IIQQQQIIQQ', data, shoff + names * 64)
    strings = data[entry[4]:entry[4] + entry[5]]
    for i in range(count):
        offset = struct.unpack_from('<I', data, shoff + i * 64)[0]
        assert strings[offset:strings.index(0, offset)] != b'.SUNW_ctf'
    results.append({'case': 'discard-all-ctf'})
    # Stripping selects the real dynamic table, or leaves only the dictionary
    # when a static image has no output symbol table. Decode the explicitly
    # linked DYNSYM here; the kernel module reader keeps its SYMTAB requirement.
    lp, lg = make('strip-input.o', formats[-1], 'strip_')
    for mode in ('shared', 'static'):
        output = work / ('stripped-' + mode)
        run(['--strip-all', '-shared' if mode == 'shared' else '-static',
             '-e', 'strip_lookup', '-o', output, lp])
        data = output.read_bytes()
        offset = struct.unpack_from('<Q', data, 40)[0]
        count, name_index = struct.unpack_from('<HH', data, 60)
        entries = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * 64)
                   for i in range(count)]
        def payload(entry):
            return data[entry[4]:entry[4] + entry[5]]
        def string(table, start):
            return table[start:table.index(0, start)].decode()
        names = payload(entries[name_index])
        names = [string(names, entry[0]) for entry in entries]
        ctf = entries[names.index('.SUNW_ctf')]
        symbols = []
        if mode == 'shared':
            table = entries[ctf[6]]
            assert table[1] == 11, 'stripped shared CTF must link to DYNSYM'
            strings = payload(entries[table[6]])
            for i in range(table[5] // 24):
                nm, info, other, section, value, size = struct.unpack_from(
                    '<IBBHQQ', data, table[4] + i * 24)
                if nm and section and info & 15 in (1, 2):
                    symbols.append((string(strings, nm), info & 15, info >> 4,
                                    other, names[section], value, size))
        else:
            assert ctf[6] == 0 and '.symtab' not in names
        actual = reader.Graph(payload(ctf), symbols)
        want = expected([lg])
        if mode == 'static':
            want.symbols = {}
        reader.compare(want, canonical(actual))
        results.append({'case': 'strip-all-' + mode, 'associations': len(symbols)})

    summary = {'passed': len(results), 'cases': results,
               'scope': 'Static CTF section/layout, exact association/type graph and script controls; no target execution.'}
    (work / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    if os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR'):
        destination = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR'])
        (destination / 'lld-ctf-sections.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'passed': len(results)}))


if __name__ == '__main__':
    main()
