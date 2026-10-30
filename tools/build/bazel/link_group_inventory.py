# SPDX-License-Identifier: BSD-2-Clause
"""Resolve simple installed GROUP members to configured native artifacts.

Resolution preserves the linker sequence. It does not lower GROUP to ordinary
Bazel dependencies: archive rescan semantics must be preserved by the caller.
"""
from pathlib import Path
import re
import shlex
from libmd_environment import digest


def resolve(component, components, src):
    record = component.get('shared_link_script')
    if not record:
        return []
    origin = (src / record['template']['path']).resolve(strict=True)
    if not origin.is_relative_to(src.resolve()) or digest(origin) != record['template']['sha256']:
        raise ValueError('shared GROUP template escaped source tree or changed')
    text = origin.read_text()
    for token, replacement in record['substitutions'].items():
        text = text.replace(token, replacement)
    match = re.fullmatch(r'\s*GROUP\s*\(\s*([A-Za-z0-9_./+\-\s]+)\s*\)\s*', text)
    if not match:
        raise ValueError('shared GROUP requires explicit support for its linker commands')
    members = match.group(1).split()
    if not members or len(members) != len(set(members)):
        raise ValueError('empty or repeated GROUP members')
    inventory = {}
    libraries = set()

    def add(directory, name, owner, component_path, kind, variant):
        path = Path(directory)
        if not path.is_absolute() or '..' in path.parts or str(path) != directory:
            raise ValueError('GROUP inventory requires normalized absolute install directories')
        if not name or Path(name).name != name or name in ('.', '..'):
            raise ValueError('GROUP inventory requires artifact basenames')
        installed = str(path / name)
        item = dict(component=component_path, library=owner, kind=kind, variant=variant, artifact=name, install_path=installed)
        if installed in inventory and inventory[installed] != item:
            raise ValueError('ambiguous installed GROUP artifact: ' + installed)
        inventory[installed] = item

    for candidate in components:
        metadata = candidate['metadata']
        library = metadata.get('LIB')
        if not library:
            continue
        if library in libraries:
            raise ValueError('ambiguous GROUP library: ' + library)
        libraries.add(library)
        outputs = shlex.split(metadata['_LIBS'])
        base = 'lib' + metadata.get('LIB_PRIVATE', '') + library
        for variant, suffix in (('regular', '.a'), ('pic', '_pic.a'),
                                ('pie', '_pie.a'), ('nossp_pic', '_nossp_pic.a')):
            artifact = base + suffix
            if artifact in outputs:
                add(metadata['_LIBDIR'], artifact, library, candidate['component'], 'archive', variant)
        shared = metadata.get('SHLIB_NAME')
        if shared and shared in outputs:
            add(metadata['_SHLIBDIR'], shared, library, candidate['component'], 'shared', None)
            # A nested linker script is not an ordinary shared alias.
            link = metadata.get('SHLIB_LINK')
            if link and not metadata.get('SHLIB_LDSCRIPT'):
                add(metadata['_LIBDIR'], link, library, candidate['component'], 'shared', None)
    result = []
    for member in members:
        if member not in inventory:
            raise ValueError('GROUP member lacks a selected configured artifact: ' + member)
        result.append(inventory[member])
    metadata = component['metadata']
    first = result[0]
    if (first['component'] != component['component'] or first['library'] != metadata['LIB'] or first['kind'] != 'shared' or
            first['artifact'] != metadata['SHLIB_NAME']):
        raise ValueError('GROUP must begin with its configured shared object')
    identities = [(item['component'], item['kind'], item['variant']) for item in result]
    if len(identities) != len(set(identities)):
        raise ValueError('GROUP repeats one artifact through different aliases')
    return result
