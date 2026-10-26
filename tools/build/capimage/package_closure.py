# SPDX-License-Identifier: BSD-2-Clause
"""Check advertised library coverage without consulting the builder's libraries.

This does not replace dependency solving, ELF loading analysis, or authentication.
"""



def require_dependencies(manifests):
    """Require declared package identities within the explicit selected set.

    Dependency versions are build metadata, not exact solver pins. This does
    not approve selected versions, authenticate packages or discover providers.
    """
    packages = {}
    for manifest in manifests:
        if not isinstance(manifest, dict):
            raise ValueError('invalid package manifest in dependency closure')
        name = manifest.get('name')
        if not isinstance(name, str) or not name or name in packages:
            raise ValueError('invalid or duplicate package identity in dependency closure')
        packages[name] = manifest
    for name, manifest in packages.items():
        deps = manifest.get('deps', {})
        if not isinstance(deps, dict):
            raise ValueError('invalid dependency map: ' + name)
        for dependency, expected in deps.items():
            if (not isinstance(dependency, str) or not dependency or
                    not isinstance(expected, dict) or
                    any(not isinstance(expected.get(key), str) or not expected[key]
                        for key in ('origin', 'version'))):
                raise ValueError('invalid dependency identity: ' + name)
        missing = deps.keys() - packages.keys()
        if missing:
            raise ValueError('package set lacks dependencies of ' + name +
                             ': ' + ', '.join(sorted(missing)))
        for dependency, expected in deps.items():
            if packages[dependency].get('origin') != expected['origin']:
                raise ValueError('dependency identity mismatch: ' + name + ': ' + dependency)


def require_shared_libraries(manifests):
    records = list(manifests)
    provided, required = set(), []
    for manifest in records:
        name = manifest.get('name')
        if not isinstance(name, str) or not name:
            raise ValueError('invalid package identity in library closure')
        for field in ('shlibs_provided', 'shlibs_required'):
            values = manifest.get(field, [])
            if (not isinstance(values, list) or
                    any(not isinstance(v, str) or not v or '/' in v or
                        any(ord(c) < 32 for c in v) for v in values) or
                    len(values) != len(set(values))):
                raise ValueError('invalid ' + field + ': ' + name)
            if field == 'shlibs_provided':
                provided.update(values)
            else:
                required.extend((name, value) for value in values)
    missing = sorted((name, value) for name, value in required if value not in provided)
    if missing:
        raise ValueError('package set lacks shared-library providers: ' +
                         '; '.join(name + ': ' + value for name, value in missing))


def require_conflicts_absent(manifests):
    """Reject explicit package-name conflicts in a selected generation."""
    records = list(manifests)
    names = {manifest['name'] for manifest in records}
    for manifest in records:
        conflicts = manifest.get('conflicts', [])
        if (not isinstance(conflicts, list) or
                any(not isinstance(name, str) or not name or
                    any(ord(c) < 32 for c in name) for name in conflicts)):
            raise ValueError('invalid package conflicts: ' + manifest['name'])
        selected = names.intersection(conflicts)
        if selected:
            raise ValueError('selected archives declare package conflicts: ' +
                             manifest['name'] + ': ' + ', '.join(sorted(selected)))


def require_selected_set(manifests):
    records = list(manifests)
    require_dependencies(records)
    require_shared_libraries(records)
    require_conflicts_absent(records)
