#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Verify explicit module selection using real ELF metadata fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kldxref', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    tool = args.kldxref.resolve(strict=True)
    fixtures = args.fixtures.resolve(strict=True)
    root = args.work.resolve(strict=False); root.mkdir(mode=0o700)
    selected = root / 'selected.ko'
    shutil.copyfile(fixtures / 'pnp-0.ko', selected)
    output = root / 'linker.hints'
    records = []

    def invoke(*arguments):
        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return subprocess.run([str(tool), *map(str, arguments)], capture_output=True,
                              timeout=15, preexec_fn=limits)

    def require(value, message):
        if not value:
            raise AssertionError(message)

    r = invoke(root)
    require(r.returncode == 0 and output.is_file(), 'directory-mode positive control failed')
    expected = output.read_bytes()
    output.unlink()
    r = invoke('-o', output, selected)
    require(r.returncode == 0 and output.read_bytes() == expected, 'explicit output differs')
    records.append('explicit_matches_directory_output')
    malformed = root / 'ambient.ko'; malformed.write_bytes(b'not ELF\n')
    r = invoke('-o', output, selected)
    require(r.returncode == 0 and output.read_bytes() == expected, 'ambient file influenced output')
    records.append('ambient_input_ignored')

    def reject(name, arguments):
        before = output.read_bytes()
        r = invoke(*arguments)
        require(r.returncode > 0, name + ' was accepted or crashed')
        require(output.read_bytes() == before, name + ' changed prior output')
        require(not list(root.glob('lhint.*')), name + ' left temporary files')
        records.append(name)

    reject('selected_malformed_rejected', ['-o', output, selected, malformed])
    reject('duplicate_rejected', ['-o', output, selected, selected])
    reject('output_as_input_rejected', ['-o', output, output])
    reject('directory_rejected', ['-o', output, root])
    fifo = root / 'fifo.ko'; os.mkfifo(fifo)
    reject('fifo_rejected', ['-o', output, fifo])
    link = root / 'link.ko'; link.symlink_to(selected)
    reject('symlink_rejected', ['-o', output, link])
    other = root / 'other'; other.mkdir()
    shutil.copyfile(selected, other / 'other.ko')
    reject('different_directory_rejected', ['-o', output, other / 'other.ko'])
    reject('relative_input_rejected', ['-o', output, 'selected.ko'])
    reject('noncanonical_input_rejected', ['-o', output, str(root) + '/./selected.ko'])
    reject('empty_selection_rejected', ['-o', output])
    for flag in ('-d', '-R', '-v'):
        reject('mode_conflict_' + flag, [flag, '-o', output, selected])
    reject('filename_mode_conflict', ['-f', 'different.hints', '-o', output, selected])
    reject('display_mode_conflict', ['-m', selected, '-o', output])
    alias = root / 'aliased-output'; alias.symlink_to(output)
    reject('symlink_output_rejected', ['-o', alias, selected])
    empty = root / 'empty.ko'; shutil.copyfile(fixtures / 'pnp-6.ko', empty)
    r = invoke('-o', output, empty)
    encoding = 'little' if empty.read_bytes()[5] == 1 else 'big'
    require(r.returncode == 0 and output.read_bytes() == (1).to_bytes(4, encoding),
            'no-record selection did not produce a version-only index')
    records.append('version_only_index')
    # Different machine, same valid no-metadata ELF layout: it must still constrain
    # the architecture of subsequent files, even though it contributed no records.
    data = bytearray(empty.read_bytes())
    machine = int.from_bytes(data[18:20], encoding)
    data[18:20] = (183 if machine != 183 else 62).to_bytes(2, encoding)
    foreign = root / 'foreign.ko'; foreign.write_bytes(data)
    reject('mixed_architecture_rejected', ['-o', output, foreign, selected])
    report = dict(format=1, result='PASS', scope='explicit module utility inputs', checks=records,
                  tool_sha256=hashlib.sha256(tool.read_bytes()).hexdigest(),
                  fixture_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in (fixtures / 'pnp-0.ko', fixtures / 'pnp-6.ko')})
    (root / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('MODULE_INPUT_AUDIT ' + json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
