# SPDX-License-Identifier: BSD-2-Clause
"""Explicit Make execution-tool selections for component configuration export."""
import json
import os
from pathlib import Path
import re
from libmd_environment import digest

VARIABLES = frozenset(('GENCAT', 'DTRACE', 'FIDLC', 'PYTHON', 'LEX', 'YACC', 'M4', 'RPCGEN_TOOL', 'LIBMD_GEN_SH', 'LIBMD_GEN_SED', 'LIBMD_GEN_MV', 'LIBMD_GEN_RM'))


def load(path, inputs):
    if path is None:
        return []
    origin = path.resolve(strict=True)
    data = json.loads(origin.read_text())
    if not isinstance(data, dict) or set(data) != {'format', 'tools'} or type(data['format']) is not int or data['format'] != 1:
        raise ValueError('tool overrides require format 1 and tools fields')
    tools = data['tools']
    if not isinstance(tools, dict) or not set(tools) <= VARIABLES:
        raise ValueError('unsupported Make execution-tool variable')
    arguments = []
    inputs[str(origin)] = digest(origin)
    for name, value in sorted(tools.items()):
        # Make interprets dollars and recipes may consume an unquoted tool name.
        # This interface selects executable files, not shell command fragments.
        if not isinstance(value, str) or not re.fullmatch(r'/[A-Za-z0-9_./+:-]+', value):
            raise ValueError('execution tool requires an absolute path without shell or Make syntax')
        executable = Path(value).resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError('execution tool is not executable: ' + value)
        inputs[str(executable)] = digest(executable)
        arguments.append(name + '=' + str(executable))
    return arguments
