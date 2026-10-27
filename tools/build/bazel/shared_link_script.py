# SPDX-License-Identifier: BSD-2-Clause
"""Export bsd.lib.mk's configured shared-library linker-script transformation."""
from pathlib import Path
import re
import shlex
from libmd_environment import digest


def export(src, component, metadata, inputs):
    template = metadata['SHLIB_LDSCRIPT']
    if not template:
        return None
    origin = (component / template).resolve(strict=True)
    if not origin.is_relative_to(src) or not origin.is_file():
        raise ValueError('shared-library script template outside source tree')
    link = metadata['SHLIB_LINK']
    library = metadata['SHLIB_NAME']
    for name in (link, library):
        if not name or Path(name).name != name or name in ('.', '..'):
            raise ValueError('shared-library script requires configured link/library basenames')
    directories = {}
    for key in ('_LIBDIR', '_SHLIBDIR'):
        value = metadata[key]
        # bsd.lib.mk uses comma-delimited sed replacements. Reject values whose
        # semantics would differ from literal Bazel template substitution.
        if not Path(value).is_absolute() or '..' in Path(value).parts or any(c in value for c in ',&\\\n\r'):
            raise ValueError('unsupported shared-library script directory: ' + key)
        directories[key] = value
    substitutions = {'@@SHLIB@@': directories['_SHLIBDIR'] + '/' + library,
                     '@@LIBDIR@@': directories['_LIBDIR']}
    inputs[str(origin)] = digest(origin)
    return {'template': {'path': str(origin.relative_to(src)), 'sha256': inputs[str(origin)]},
            'output': str(Path(link).with_suffix('.ld')), 'substitutions': substitutions,
            'install_path': directories['_LIBDIR'] + '/' + link}


def dynamic_group(component, components, dependencies, src):
    """Validate simple installed GROUP scripts against declared shared inputs.

ELF shared-only GROUP members become ordered native shared dependencies. Scripts
with archives, search options, AS_NEEDED or other linker commands need distinct
semantics and are rejected. Installed script bytes remain a separate artifact.
"""
    record = component.get('shared_link_script')
    if not record:
        return False
    origin = src / record['template']['path']
    if digest(origin) != record['template']['sha256']:
        raise ValueError('shared link script template changed')
    text = origin.read_text()
    for token, replacement in record['substitutions'].items():
        text = text.replace(token, replacement)
    match = re.fullmatch(r'\s*GROUP\s*\(\s*([A-Za-z0-9_./+\-\s]+)\s*\)\s*', text)
    if not match:
        raise ValueError('shared link script requires explicit support for its linker commands')
    selected = {c['metadata']['LIB']: c for c in components if c['metadata']['LIB']}
    metadata = component['metadata']
    expected = [metadata['_SHLIBDIR'] + '/' + metadata['SHLIB_NAME']]
    for name in dependencies:
        candidate = selected[name]['metadata']
        if (not candidate['SHLIB_NAME'] or candidate['SHLIB_NAME'] not in shlex.split(candidate['_LIBS']) or
                not candidate['SHLIB_LINK'] or candidate['SHLIB_LDSCRIPT']):
            raise ValueError('shared GROUP dependency requires a direct configured shared library: ' + name)
        expected.append(candidate['_LIBDIR'] + '/' + candidate['SHLIB_LINK'])
    if match.group(1).split() != expected:
        raise ValueError('shared GROUP members differ from ordered configured shared dependencies')
    if len(expected) != len(set(expected)):
        raise ValueError('repeated shared GROUP members require explicit sequence support')
    return True
