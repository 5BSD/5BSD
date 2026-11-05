# SPDX-License-Identifier: BSD-2-Clause
"""Restricted reference selectors and generated-header provenance checks."""
import re
import hashlib
from pathlib import Path
import shlex

_RESERVED = {
    'CC', 'CXX', 'CPP', 'LD', 'AR', 'AS', 'NM', 'OBJCOPY', 'OBJDUMP', 'STRIP',
    'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LDADD', 'LIBADD',
    'TARGET', 'TARGET_ARCH', 'MACHINE', 'MACHINE_ARCH', 'OBJTOP', 'SRCTOP',
    'SYSDIR', 'WORLDTMP', 'DESTDIR', 'METALOG', 'INSTALL', 'INSTALLFLAGS',
    'SRCCONF', 'SRC_ENV_CONF', '__MAKE_CONF', 'MAKEOBJDIR', 'MAKEOBJDIRPREFIX',
    'REFERENCE_OBJROOT', 'PATH', 'HOME', 'CCACHE_DIR',
}


def component_definitions(component, names, *, option_names=(), profile_names=()):
    """Return NAME=1 selectors in component or BOOT_component namespaces.

    This does not expose arbitrary Make assignments. For example, traceroute
    may define TRACEROUTE_NO_IPSEC, but cannot override global configuration,
    compiler/target identity, output paths or the captured profile.
    """
    if not names:
        return {}
    namespace = re.sub('[^A-Z0-9_]', '_', component.name.upper()) + '_'
    if not re.fullmatch('[A-Z][A-Z0-9_]*_', namespace):
        raise ValueError('component has no uppercase option namespace')
    selected = set(option_names) | set(profile_names)
    result = {}
    for name in names:
        if not isinstance(name, str) or not re.fullmatch('[A-Z][A-Z0-9_]*', name):
            raise ValueError('component define requires an uppercase identifier')
        if name in _RESERVED or name.startswith(('MK_', 'WITH_', 'WITHOUT_', 'MAKE_')):
            raise ValueError('component define cannot override global Make configuration: ' + name)
        namespaces = (namespace, 'BOOT_' + namespace)
        if not any(name.startswith(prefix) and name != prefix for prefix in namespaces):
            raise ValueError('component define must use namespace ' + ' or '.join(namespaces))
        if name in result:
            raise ValueError('duplicate component define: ' + name)
        if name in selected:
            raise ValueError('component define collides with an option or captured profile: ' + name)
        result[name] = '1'
    return result


# NO_OBJ descendants deliberately return to .CURDIR; never write recipe logs there.
METADATA_MODE = "meta missing-meta=yes nofilemon curdirok=no"


def validate_metadata_component(query):
    """Reject metadata mode where Make deliberately uses the source directory."""
    states = query(['-V', '${NO_OBJ:Dyes:Uno}',
                    '-V', '${NOOBJ:Dyes:Uno}']).splitlines()
    if len(states) != 2 or any(value not in ('yes', 'no') for value in states):
        raise ValueError('ambiguous Make NO_OBJ/NOOBJ metadata directory policy')
    if 'yes' in states:
        raise ValueError('--make-meta is unsafe for NO_OBJ/NOOBJ components; '
                         'use ordinary reference mode to avoid source recipe logs')


def audit_generated_headers(component_objects, objtop, required=()):
    """Reject stale SDK generated headers even without an explicit local request.

    Source headers and staged SDK public headers retain their normal precedence.
    Identical generated SDK aliases may be recorded; different bytes never pass.
    Explicit requests additionally require local consumption, not equivalence.
    """
    component_objects = Path(component_objects).resolve(strict=True)
    objtop = Path(objtop).resolve(strict=True)
    required = set(required)
    if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*\.h', name) for name in required):
        raise ValueError('generated header requires a simple .h basename')
    local = {p.name: p for p in component_objects.glob('*.h')
             if p.is_file() and not p.is_symlink()}
    if required - local.keys():
        raise ValueError('missing regular local generated header: ' + repr(sorted(required - local.keys())))
    consumed = {name: [] for name in required}
    equivalent = []
    for dependency in component_objects.glob('.depend.*.o'):
        words = shlex.split(dependency.read_text().replace('\\\n', ' '))
        for word in words:
            name = Path(word).name
            if name not in local:
                continue
            actual = (component_objects / word).resolve(strict=True)
            wanted = local[name].resolve(strict=True)
            if actual == wanted:
                if name in consumed:
                    consumed[name].append(str(dependency))
                continue
            if name in required:
                raise ValueError('generated reference header was shadowed: ' + str(actual))
            if actual.is_relative_to(objtop) and not actual.is_relative_to(objtop / 'tmp'):
                expected = hashlib.sha256(wanted.read_bytes()).hexdigest()
                observed = hashlib.sha256(actual.read_bytes()).hexdigest()
                if expected != observed:
                    raise ValueError('stale SDK generated header shadows local output: ' + str(actual))
                equivalent.append({'local': str(wanted), 'actual': str(actual),
                                   'sha256': expected, 'dependency': str(dependency)})
    if any(not paths for paths in consumed.values()):
        raise ValueError('requested local generated header not consumed: ' + repr(consumed))
    return {'required': {
                name: {'path': str(local[name]),
                       'sha256': hashlib.sha256(local[name].read_bytes()).hexdigest(),
                       'dependencies': sorted(set(consumed[name]))}
                for name in sorted(required)},
            'equivalent_external_generated_headers': equivalent}
