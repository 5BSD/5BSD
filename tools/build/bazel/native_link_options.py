# SPDX-License-Identifier: BSD-2-Clause
"""Translate configured library directories only through declared native inputs."""
from pathlib import Path


def translate(component, components, tokens, source_root, object_root):
    object_root=Path(object_root).resolve(strict=True)
    source_root=Path(source_root).resolve(strict=True)
    selected={c['component']:c for c in components if c['metadata'].get('LIB')}
    directories=set();pending=list(component['library_dependencies']);seen=set()
    for record in pending:
        for value in record.get('dpadd',[]):
            path=Path(value)
            if path.is_absolute() and '..' not in path.parts and path.is_relative_to(object_root):
                directories.add(path.parent)
        name=record['component']
        if name in seen:continue
        seen.add(name)
        if name not in selected:raise ValueError('native dependency not selected: '+name)
        candidate=selected[name]
        value=candidate['metadata'].get('.OBJDIR')
        if value:
            path=Path(value)
            if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(object_root):
                raise ValueError('dependency object directory outside configured object root')
            directories.add(path)
        pending.extend(candidate.get('library_dependencies',[]))
    result=[];translated=[];index=0
    while index<len(tokens):
        token=tokens[index]
        if token=='-L' or token.startswith('-L'):
            if token=='-L':
                index+=1
                if index==len(tokens):raise ValueError('missing library search directory')
                value=tokens[index]
            else:value=token[2:]
            path=Path(value)
            if not path.is_absolute() or '..' in path.parts or path not in directories:
                raise ValueError('library search path lacks declared native dependency: '+value)
            translated.append(value)
        else:
            linker_tokens=token.split(',')[1:] if token.startswith('-Wl,') else [token]
            if token=='-Xlinker' or any(v=='-L' or v.startswith('-L') or v.startswith('--library-path') for v in linker_tokens):
                raise ValueError('indirect linker search requires explicit support')
            if str(object_root) in token or str(source_root) in token:
                raise ValueError('unmapped linker input: '+token)
            result.append(token)
        index+=1
    return result,translated
