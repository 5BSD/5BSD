# SPDX-License-Identifier: BSD-2-Clause
"""Map maintained include flags without dropping or reordering them."""
from pathlib import Path


def rewrite_includes(tokens, source_root, object_root, component=None, generated_directories=None):
    source_root = source_root.resolve(strict=True)
    object_root = object_root.resolve(strict=True)
    generated = {}
    for original, destination in (generated_directories or {}).items():
        original = Path(original).resolve()
        destination = Path(destination)
        if not original.is_relative_to(object_root) or original == object_root:
            raise ValueError('generated include directory must be below object root')
        if destination.is_absolute() or '..' in destination.parts or str(destination) == '.':
            raise ValueError('generated include mapping must be workspace-relative')
        generated[original] = str(destination)
    result, directories = [], []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        prefix = next((flag for flag in ('-isystem', '-iquote', '-idirafter', '-I') if token.startswith(flag)), None)
        split = token == prefix
        if prefix is not None:
            if split:
                i += 1
                if i == len(tokens):
                    raise ValueError('missing '+prefix+' directory')
                value = tokens[i]
            else:
                value = token[len(prefix):]
            path = Path(value)
            if not path.is_absolute():
                path = object_root / path
            # Declared generated directories need not exist in a cold Make tree.
            # Never collect their existing contents as source header inputs.
            path = path.resolve()
            # Compilers ignore nonexistent source include directories. Preserve
            # their position in the search path without reading host/object data.
            missing_source = path.is_relative_to(source_root) and not path.exists()
            if path not in generated and not missing_source:
                path = path.resolve(strict=True)
            if path in generated:
                mapped = generated[path]
            elif path == object_root:
                mapped = '.'
            elif component is not None and path.is_relative_to(component):
                if not path.is_relative_to(source_root):
                    raise ValueError('component include lies outside source root')
                mapped = 'sources/' + str(path.relative_to(source_root))
                directories.append(path)
            elif path.is_relative_to(source_root) and (path.is_dir() or missing_source):
                mapped = 'sources/' + str(path.relative_to(source_root))
                directories.append(path)
            else:
                raise ValueError('include directory lacks declared source/object mapping: '+str(path))
            result.extend([prefix, mapped] if split else [prefix + mapped])
        else:
            if str(source_root) in token or str(object_root) in token:
                raise ValueError('unmapped path option: '+token)
            result.append(token)
        i += 1
    return result, list(dict.fromkeys(directories))
