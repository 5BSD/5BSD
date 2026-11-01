# SPDX-License-Identifier: BSD-2-Clause
"""Presence-only component selectors for the temporary independent Make oracle."""
import re

_RESERVED = {
    'CC', 'CXX', 'CPP', 'LD', 'AR', 'AS', 'NM', 'OBJCOPY', 'OBJDUMP', 'STRIP',
    'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LDADD', 'LIBADD',
    'TARGET', 'TARGET_ARCH', 'MACHINE', 'MACHINE_ARCH', 'OBJTOP', 'SRCTOP',
    'SYSDIR', 'WORLDTMP', 'DESTDIR', 'METALOG', 'INSTALL', 'INSTALLFLAGS',
    'SRCCONF', 'SRC_ENV_CONF', '__MAKE_CONF', 'MAKEOBJDIR', 'MAKEOBJDIRPREFIX',
    'REFERENCE_OBJROOT', 'PATH', 'HOME', 'CCACHE_DIR',
}


def component_definitions(component, names, *, option_names=(), profile_names=()):
    """Return NAME=1 selectors restricted to the component basename namespace.

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
        if not name.startswith(namespace) or name == namespace:
            raise ValueError('component define must use namespace ' + namespace)
        if name in result:
            raise ValueError('duplicate component define: ' + name)
        if name in selected:
            raise ValueError('component define collides with an option or captured profile: ' + name)
        result[name] = '1'
    return result
