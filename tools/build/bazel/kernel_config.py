# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Generate config from source and apply only effective declarative changes."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from kernel_options import defined_options, validate_directory


def generate(program, config, source_root, output, debug, requests, expected, active, env):
    if (not isinstance(requests, dict) or set(requests) != {'format', 'settings'} or
            type(requests['format']) is not int or requests['format'] != 1 or
            not isinstance(requests['settings'], list)):
        raise ValueError('format-1 declarative kernel settings required')
    seen = set()
    for row in requests['settings']:
        if (not isinstance(row, dict) or set(row) != {'option', 'enabled', 'device'} or
                not isinstance(row['option'], str) or not re.fullmatch(r'[A-Z0-9_]+', row['option']) or
                type(row['enabled']) is not bool or row['option'] in seen or
                (row['device'] is not None and
                 (not isinstance(row['device'], str) or not re.fullmatch(r'[a-z0-9_]+', row['device'])))):
            raise ValueError('distinct typed kernel option/device requests required')
        seen.add(row['option'])
    # Bazel precreates empty tree-artifact directories. Accept only that empty
    # transport root; never reuse a symlink, non-directory or previous contents.
    if (active.exists() or active.is_symlink() or output.is_symlink() or
            (output.exists() and (not output.is_dir() or any(output.iterdir())))):
        raise ValueError('fresh kernel configuration outputs required')
    output.parent.mkdir(parents=True, exist_ok=True)

    def invoke(selected, destination):
        command = [str(program), '-J'] + (['-g'] if debug else [])
        command += ['-d', str(destination), '-s', os.path.relpath(source_root, destination), str(selected)]
        subprocess.run(command, cwd=config.parent, env=env, check=True)

    # Native config owns include resolution and baseline option semantics. Do
    # not parse GENERIC, duplicate defaults, or reorder unchanged source options.
    with tempfile.TemporaryDirectory(prefix='kernel-config-', dir=output.parent) as scratch:
        baseline = Path(scratch) / 'baseline'
        invoke(config, baseline)
        defined = defined_options(baseline)
        lines = []
        for row in requests['settings']:
            if (row['option'] in defined) == row['enabled']:
                continue
            symbol = row['device'] or row['option']
            remove, add = ('nodevice', 'device') if row['device'] else ('nooptions', 'options')
            lines.append(remove + ' ' + symbol)
            if row['enabled']:
                lines.append(add + ' ' + symbol)
        active.write_text(('include ' + json.dumps(config.name) + '\n' + '\n'.join(lines) + '\n') if lines else '')
        selected = active if lines else config
        # The accepted output is generated fresh at its real declared location;
        # the temporary baseline is never adopted or copied into that output.
        invoke(selected, output)
    validate_directory(output, expected)
    return selected


def main():
    program, config, anchor, output = [Path(p).absolute() for p in sys.argv[1:5]]
    identity = Path(sys.argv[5]).absolute()
    debug = sys.argv[6] == '1'
    overrides, manifest, expectation, active = [Path(p).absolute() for p in sys.argv[7:11]]
    libraries = [Path(p).absolute() for p in sys.argv[11:]]
    env = dict(os.environ)
    if libraries:
        env['LD_LIBRARY_PATH'] = ':'.join(dict.fromkeys(str(p.parent) for p in libraries))
    source_root = anchor.parent.parent
    selected = generate(program, config, source_root, output, debug,
                        json.loads(overrides.read_text()), json.loads(expectation.read_text()), active, env)
    result = subprocess.run([str(program), '-i', '-s', str(source_root), str(selected)],
                            cwd=config.parent, env=env, check=True, capture_output=True)
    identity.write_bytes(result.stdout)
    manifest.write_bytes((output / 'kernel-inputs.json').read_bytes())


if __name__ == '__main__':
    main()
