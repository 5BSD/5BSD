# SPDX-License-Identifier: BSD-2-Clause
"""Resolve installation inputs without consuming ambient generated objects."""
from pathlib import Path
from libmd_environment import digest


def identity(name, src, object_directory, search, generators, catalogues, inputs):
    path = Path(name)
    declared = name if not path.is_absolute() else path.name if path.parent == object_directory else None
    if declared in catalogues:
        return {'catalogue_output': declared, 'catalogue': catalogues[declared]}
    if declared in generators:
        return {'generated_output': declared, 'generator': generators[declared]}
    candidates = [path] if path.is_absolute() else [directory / path for directory in search]
    for candidate in candidates:
        if candidate.is_file():
            candidate = candidate.resolve(strict=True)
            if not candidate.is_relative_to(src):
                raise ValueError('source outside maintained source tree')
            inputs[str(candidate)] = digest(candidate)
            return {'source_origin': str(candidate), 'source_sha256': inputs[str(candidate)]}
    raise ValueError('source missing from maintained search path and declared generators: ' + name)
