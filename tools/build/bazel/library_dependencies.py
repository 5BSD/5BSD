# SPDX-License-Identifier: BSD-2-Clause
"""Resolve configured LIBADD aliases to selected native component targets."""
import shlex
import component_labels
from pathlib import Path


def _link_tokens(tokens, directories):
    flags=[]; searches=[]; index=0
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
            searches.append(value)
        else:flags.append(token)
        index+=1
    return flags,searches


def component_index(components):
    """Index libraries by their declared source identity, never their basename."""
    selected = {}
    for candidate in components:
        if not candidate['metadata'].get('LIB'):
            continue
        path = candidate['component']
        if path in selected:
            raise ValueError('ambiguous library component: ' + path)
        selected[path] = candidate
    return selected


def selection_component(entry, selected):
    path = entry['component']
    if path not in selected:
        raise ValueError('native dependency not selected: ' + path)
    candidate = selected[path]
    if candidate['metadata']['LIB'] != entry['library']:
        raise ValueError('library selection name differs from source component: ' + path)
    return candidate


def resolve_selections(component, components):
    metadata=component['metadata']
    names=component.get('framework_library_names',[])+shlex.split(metadata['LIBADD'])
    records=component.get('library_dependencies')
    if records is None:raise ValueError('library dependency mapping missing; regenerate component plan')
    if [r['name'] for r in records]!=names:
        raise ValueError('library dependency order differs from configured framework/LIBADD')
    selected=component_index(components)
    targets={};directories=set()
    for record in records:
        path=record['component']
        if path not in selected:
            raise ValueError('native dependency not selected: '+record['name']+' ('+path+')')
        candidate=selected[path]['metadata']
        artifacts=[Path(v) for v in record.get('dpadd',[])]
        record_dirs={p.parent for p in artifacts if p.is_absolute() and '..' not in p.parts}
        flags,searches=_link_tokens(record['ldadd'],record_dirs)
        if len(flags)!=1 or not flags[0].startswith('-l') or len(flags[0])<=2:
            raise ValueError('dependency requires explicit linker option support: '+record['name'])
        flag=flags[0];archive='lib'+flag[2:]+'.a'
        base='lib'+candidate.get('LIB_PRIVATE','')+candidate['LIB']
        variant='normal'
        for kind in ('pic','pie','nossp_pic'):
            if archive==base+'_'+kind+'.a':
                if archive not in shlex.split(candidate.get('_LIBS','')):
                    raise ValueError('requested archive variant is not configured: '+archive)
                if len(artifacts)!=1 or artifacts[0].name!=archive:
                    raise ValueError('archive variant differs from declared DPADD: '+archive)
                variant=kind
        if searches:
            # A search directory is translated only for the exact archive named
            # by both the configured linker alias and Make dependency inventory.
            if (len(artifacts)!=1 or artifacts[0].name!=archive or
                    archive not in shlex.split(candidate.get('_LIBS',''))):
                raise ValueError('searched archive differs from configured dependency: '+archive)
        entry=dict(component=path,library=candidate['LIB'],variant=variant,search_directories=searches)
        if flag in targets and targets[flag]!=entry:raise ValueError('ambiguous library linker name: '+flag)
        targets[flag]=entry;directories.update(record_dirs)
    flags,searches=_link_tokens(shlex.split(metadata['LDADD']),directories)
    declared_searches={d for entry in targets.values() for d in entry['search_directories']}
    if set(searches)!=declared_searches:
        raise ValueError('LDADD search paths differ from declared dependency options')
    if set(flags)!=set(targets):
        raise ValueError('LDADD contains options outside declared library dependencies or omits a dependency')
    if len(flags)!=len(set(flags)):raise ValueError('repeated libraries require explicit linker sequence support')
    return [targets[flag] for flag in flags]


def resolve(component, components):
    return [entry['library'] for entry in resolve_selections(component,components)]


def component_link_labels(component, components, *, dynamic, sequence=False):
    if sequence:
        from library_link_sequence import resolve as resolve_sequence
        selections=resolve_sequence(component,components)
    else:
        selections=resolve_selections(component,components)
    selected=component_index(components)
    result=[]
    for entry in selections:
        name=entry['library'];variant=entry['variant']
        metadata=selection_component(entry,selected)['metadata']
        target=(name+'_'+variant+'_link' if variant!='normal' else
                shared_link_target(metadata) if dynamic else name)
        result.append(component_labels.label(entry['component'],target))
    return result


def shared_link_target(metadata):
    """Select a declared artifact for a normal dynamic-mode -l dependency.

    Static-only libraries use their regular archive, even if a PIC archive is
    also configured. Do not let Bazel silently substitute a different variant.
    This does not model explicit -Bstatic/-Bdynamic scopes or linker groups.
    """
    name = metadata['LIB']
    if not name:
        raise ValueError('library metadata required for link selection')
    outputs = shlex.split(metadata['_LIBS'])
    shared = metadata['SHLIB_NAME']
    # Make may retain a default SHLIB_NAME for INTERNALLIB or a static-only
    # configuration. The configured output inventory determines what is built.
    if shared and shared in outputs:
        return name + '_dynamic'
    archive = 'lib' + metadata['LIB_PRIVATE'] + name + '.a'
    if archive not in outputs:
        raise ValueError('static dependency lacks configured regular archive')
    return name + '_shared_static'


def shared_link_labels(names, components):
    selected = {}
    for component in components:
        metadata = component['metadata']
        if not metadata['LIB']:
            continue
        selected.setdefault(metadata['LIB'], []).append(component)
    result = []
    for name in names:
        if name not in selected:
            raise ValueError('native library target not selected: ' + name)
        if len(selected[name]) != 1:
            raise ValueError('ambiguous native library target: ' + name)
        result.append(component_labels.label(selected[name][0],shared_link_target(selected[name][0]['metadata'])))
    return result


def program_link_options(component, components, source_root, object_root, *, sequence=False):
    """Lower Make -L directories whose -l inputs are already explicit CcInfo deps.

    Every LDADD must resolve first. Search paths are accepted only for recorded
    dependency artifacts under this object tree. Target runtime selection remains
    the explicit SDK toolchain's responsibility, not a host directory search.
    """
    if sequence:
        from library_link_sequence import resolve as resolve_sequence
        resolve_sequence(component, components)
    else:
        resolve(component, components)
    from native_link_options import translate
    return translate(component,components,shlex.split(component['metadata']['LDFLAGS']),source_root,object_root)


def program_runtime_selections(names, components):
    """Explicit native replacements for compiler-provided program runtimes.

    This does not replace startup objects or infer a runtime from component
    membership. The caller must also bind the selection to runtime checks.
    """
    if not isinstance(names, list) or any(not isinstance(n, str) or not n for n in names):
        raise ValueError('program runtime libraries must be a list of library names')
    if len(set(names)) != len(names):
        raise ValueError('duplicate program runtime library')
    selected = {}
    for component in components:
        name = component['metadata'].get('LIB', '')
        if not name:
            continue
        selected.setdefault(name, []).append(component)
    for name in names:
        if name not in selected:
            raise ValueError('program runtime library not selected: ' + name)
        if len(selected[name]) != 1:
            raise ValueError('ambiguous program runtime library: ' + name)
        shared_link_target(selected[name][0]['metadata'])
    return [dict(component=selected[name][0]['component'], library=name,
                 variant='normal', search_directories=[]) for name in names]


def program_runtime_labels(names, components, link_options):
    selections = program_runtime_selections(names, components)
    modes = [token for flag in link_options
             for token in (flag.split(',')[1:] if flag.startswith('-Wl,') else [flag])]
    if selections and any(flag in ('-static', '--static', '-static-pie', '-Bstatic',
                                   '-nostdlib', '-nodefaultlibs', '-nolibc',
                                   '-shared', '--no-dynamic-linker') for flag in modes):
        raise ValueError('explicit program runtimes currently require ordinary dynamic linkage')
    selected = component_index(components)
    return [component_labels.label(entry['component'],shared_link_target(selection_component(entry, selected)['metadata']))
            for entry in selections]
