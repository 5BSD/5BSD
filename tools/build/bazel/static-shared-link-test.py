#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect a shared fixture and prove its selected static archive is required.

Replays the recorded link response with exactly that archive removed and a fresh
output. This is bounded linkage evidence, not full component ABI qualification.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
from libmd_environment import digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'compiler', 'archive', 'library', 'link-params', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--symbol', action='append', required=True)
    parser.add_argument('--require-no-needed', action='store_true')
    args = parser.parse_args()
    workspace = args.workspace.resolve(strict=True)
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to('/usr/obj') or output == Path('/usr/obj'):
        raise ValueError('fresh output below /usr/obj required')
    files = [args.compiler.resolve(strict=True), args.archive.resolve(strict=True),
             args.library.resolve(strict=True), args.link_params.resolve(strict=True)]
    hashes = {str(p): digest(p) for p in files}
    compiler, archive, library, params = files
    argv = shlex.split(params.read_text())
    if '-shared' not in argv or '-Wl,-z,defs' not in argv or argv.count('-o') != 1:
        raise ValueError('strict shared link with one output required')
    index = argv.index('-o')
    if (workspace / argv[index + 1]).resolve(strict=True) != library:
        raise ValueError('response file does not name the selected shared object')
    matches = [i for i, value in enumerate(argv) if not value.startswith('-') and
               (workspace / value).resolve() == archive]
    if len(matches) != 1:
        raise ValueError('exactly one selected archive input required')
    env = dict(PATH='/bin:/usr/bin', LC_ALL='C')
    dynamic = subprocess.check_output(['/usr/bin/readelf', '-d', str(library)], env=env, text=True)
    if args.require_no_needed and '(NEEDED)' in dynamic:
        raise ValueError('unexpected dynamic dependency in fixture')
    symbols = subprocess.check_output(['/usr/bin/readelf', '-Ws', str(library)], env=env, text=True)
    defined = {fields[7] for line in symbols.splitlines()
               if len(fields := line.split()) >= 8 and fields[0].endswith(':') and fields[6] != 'UND'}
    if not set(args.symbol) <= defined:
        raise ValueError('selected static runtime symbols are not defined in shared fixture')
    output.mkdir()
    argv[index + 1] = str(output / 'missing-archive.so')
    del argv[matches[0]]
    command = [str(compiler), *argv]
    negative = subprocess.run(command, cwd=workspace, env=env, text=True, capture_output=True)
    (output / 'negative.stdout').write_text(negative.stdout)
    (output / 'negative.stderr').write_text(negative.stderr)
    if not negative.returncode or not any(symbol in negative.stderr for symbol in args.symbol) or 'undefined symbol' not in negative.stderr:
        raise ValueError('archive omission did not fail for a selected undefined symbol')
    for path, sha in hashes.items():
        if digest(Path(path)) != sha:
            raise ValueError('linkage evidence changed during test')
    (output / 'dynamic.txt').write_text(dynamic)
    (output / 'symbols.txt').write_text(symbols)
    receipt = dict(status='passed', scope=__doc__, input_sha256=hashes,
                   symbols=args.symbol, require_no_needed=args.require_no_needed,
                   negative_command=command, negative_exit=negative.returncode,
                   driver_sha256=digest(Path(__file__)))
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('PASS: shared symbol definitions and required static archive negative link')


if __name__ == '__main__':
    main()
