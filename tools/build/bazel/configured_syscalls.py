# SPDX-License-Identifier: BSD-2-Clause
"""Export syscall assembly generation from metadata consumed by Make itself."""
from pathlib import Path
import re
import shlex
from libmd_environment import digest


def export(src, component, query, inputs):
    keys = ['SYSCALL_ASM_SOURCES', 'SYSCALL_ASM_GENERATOR', 'SYSCALL_ASM_SHELL', 'NOTE_GNU_STACK', 'FEATURE_NOTE']
    base = query(component, keys)
    names = shlex.split(base['SYSCALL_ASM_SOURCES'])
    if not names:
        return None
    if len(names) != len(set(names)) or any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.S', name) for name in names):
        raise ValueError('unique syscall assembly basenames required')
    if shlex.split(base['SYSCALL_ASM_SHELL']) != ['sh']:
        raise ValueError('syscall generator requires declared POSIX sh tool mapping')
    script = Path(base['SYSCALL_ASM_GENERATOR']).resolve(strict=True)
    if not script.is_relative_to(src) or not script.is_file():
        raise ValueError('syscall generator must be a maintained source input')
    inputs[str(script)] = digest(script)
    notes = [shlex.split(base[key]) for key in ('NOTE_GNU_STACK', 'FEATURE_NOTE')]
    if any(len(note) != 1 for note in notes):
        raise ValueError('single quoted syscall note format required')
    fields = [prefix + name for name in names for prefix in ('SYSCALL_ASM_MACRO.', 'SYSCALL_ASM_SYMBOL.')]
    values = query(component, fields)
    outputs = []
    for name in names:
        macro, symbol = (values[prefix + name] for prefix in ('SYSCALL_ASM_MACRO.', 'SYSCALL_ASM_SYMBOL.'))
        if macro not in ('RSYSCALL', 'PSEUDO') or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', symbol):
            raise ValueError('unsupported configured syscall invocation')
        outputs.append(dict(name=name, arguments=[macro, symbol, notes[0][0], notes[1][0]]))
    if query(component, keys) != base or query(component, fields) != values:
        raise ValueError('syscall generation configuration changed')
    return dict(generator=dict(path=str(script.relative_to(src)), sha256=inputs[str(script)]), outputs=outputs)
