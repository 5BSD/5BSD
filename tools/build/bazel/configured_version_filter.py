# SPDX-License-Identifier: BSD-2-Clause
"""Capture explicitly declared sed-generated version maps without recipe parsing."""
from pathlib import Path
import re
import shlex
from libmd_environment import digest


def export(src, component, metadata, env, extra, inputs):
    output = metadata['VERSION_MAP']
    if not output or metadata['SYMBOL_MAPS']:
        return None
    keys = ['VERSION_MAP_TEMPLATE.' + output, 'VERSION_MAP_SED_ARGS.' + output]
    command = [arg for key in keys for arg in ('-v', key)]
    raw = env.query(command, component=component, extra=extra)
    values = raw.splitlines()
    if len(values) != 2:
        raise ValueError('ambiguous version-filter metadata')
    if not any(values):
        return None
    if not all(values) or Path(output).name != output or output in ('.', '..'):
        raise ValueError('incomplete version-filter declaration')
    template = (component / values[0]).resolve(strict=True)
    if not template.is_file() or not template.is_relative_to(src):
        raise ValueError('version-filter template outside maintained source')
    flags = shlex.split(values[1])
    # Only declared inline substitutions are supported. File-reading/writing sed
    # commands need separate input/output declarations, never implicit access.
    if not flags or len(flags) % 2 or any(flags[i] != '-e' or not re.fullmatch(r's/[^/\n\\]*/[^/\n\\]*/g?', flags[i+1]) for i in range(0, len(flags), 2)):
        raise ValueError('version filter requires declared inline substitutions')
    inputs[str(template)] = digest(template)
    if env.query(command, component=component, extra=extra) != raw:
        raise ValueError('version-filter configuration changed')
    return {'output': output, 'template': {'path': str(template.relative_to(src)), 'sha256': inputs[str(template)]}, 'arguments': flags}
