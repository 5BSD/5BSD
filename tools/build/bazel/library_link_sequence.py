# SPDX-License-Identifier: BSD-2-Clause
"""Resolve the final Make library sequence without removing repeated arguments."""
from collections import deque
from pathlib import Path
import shlex
import library_dependencies
import component_labels


def resolve(component, components):
    selected = library_dependencies.component_index(components)
    root_records = component.get('library_dependencies')
    names = component.get('framework_library_names', []) + shlex.split(component['metadata']['LIBADD'])
    if root_records is None or [r['name'] for r in root_records] != names:
        raise ValueError('library dependency order differs from configured framework/LIBADD')
    pending = deque(root_records)
    visited = set()
    aliases = {}
    while pending:
        record = pending.popleft()
        path = record['component']
        if path not in selected:
            raise ValueError('native dependency not selected: '+record['name']+' ('+path+')')
        candidate = selected[path]
        if path not in visited:
            visited.add(path)
            pending.extend(candidate.get('library_dependencies', []))
        artifacts = [Path(value) for value in record.get('dpadd', [])]
        directories = {p.parent for p in artifacts if p.is_absolute() and '..' not in p.parts}
        flags, searches = library_dependencies._link_tokens(record['ldadd'], directories)
        if not flags or any(not flag.startswith('-l') or len(flag)<=2 for flag in flags):
            raise ValueError('link sequence requires declared plain library arguments')
        primary = record
        if len(flags)>1:
            # A compound alias's leading library must be the explicitly named
            # component. Resolve its remaining aliases from that source graph,
            # never from a guessed source-directory/name mapping.
            metadata = candidate['metadata']
            archive = 'lib'+flags[0][2:]+'.a'
            own = 'lib'+metadata.get('LIB_PRIVATE','')+metadata['LIB']+'.a'
            matches = [p for p in artifacts if p.name==archive]
            if searches:
                raise ValueError('compound searched library sequence is not yet represented')
            if archive!=own or archive not in shlex.split(metadata['_LIBS']) or len(matches)!=1:
                raise ValueError('compound alias lacks its configured primary archive identity')
            primary = dict(record, ldadd=[flags[0]], dpadd=[str(matches[0])])
        probe = dict(metadata=dict(LIBADD=record['name'], LDADD=' '.join(primary['ldadd'])),
                     library_dependencies=[primary])
        entry = library_dependencies.resolve_selections(probe, components)[0]
        flag = flags[0]
        if flag in aliases:
            previous=aliases[flag]
            if any(previous[key]!=entry[key] for key in ('component','library','variant')):
                raise ValueError('ambiguous native library alias: '+flag)
            entry=dict(entry,search_directories=sorted(set(previous['search_directories'])|set(entry['search_directories'])))
        aliases[flag] = entry
    expected = set()
    required_searches = set()
    directories = set()
    for record in root_records:
        dirs = {Path(p).parent for p in record.get('dpadd',[]) if Path(p).is_absolute() and '..' not in Path(p).parts}
        flags, searches = library_dependencies._link_tokens(record['ldadd'], dirs)
        expected.update(flags);required_searches.update(searches);directories.update(dirs)
    flags, searches = library_dependencies._link_tokens(shlex.split(component['metadata']['LDADD']), directories)
    if set(flags)!=expected or set(searches)!=required_searches:
        raise ValueError('final library sequence differs from declared aliases/searches')
    if any(flag not in aliases for flag in expected):
        raise ValueError('compound library alias lacks a declared transitive source mapping')
    return [dict(aliases[flag]) for flag in flags]


def artifacts(selections, components):
    selected = library_dependencies.component_index(components)
    result = []
    for entry in selections:
        name, variant = entry['library'], entry['variant']
        candidate = library_dependencies.selection_component(entry, selected)
        if variant!='normal':
            target = name+'_'+variant
        elif library_dependencies.shared_link_target(candidate['metadata'])==name+'_dynamic':
            target = name+('_native_group' if candidate.get('shared_link_script') else '_soname')
        else:
            target = name
        result.append(component_labels.label(entry['component'],target))
    return result
