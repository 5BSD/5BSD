# SPDX-License-Identifier: BSD-2-Clause
"""Export explicit static archive source aliases from maintained Make metadata.

STATICOBJ_SOURCE.<object> names the source alias used for compilation;
STATICOBJ_ORIGIN.<object> names its source-tree input. Make's alias rule must
consume those same fields. Objects retain STATICOBJS order and regular-only
membership. ARADD is deliberately outside this source-mapping contract.
"""
from pathlib import Path
import shlex
from libmd_environment import digest
import compile_context


def relative_file(value):
    path = Path(value)
    if not value or path.is_absolute() or '..' in path.parts or str(path) != value:
        raise ValueError('normalized relative static object/source name required')
    return path


def export(src, component, metadata, env, extra, inputs):
    objects = shlex.split(metadata['STATICOBJS'])
    if len(objects) != len(set(objects)) or set(objects) & set(shlex.split(metadata['OBJS'])):
        raise ValueError('duplicate static archive object')
    if not objects:
        return []
    if not metadata['LIB']:
        raise ValueError('static archive objects require a library')
    keys = [prefix + obj for obj in objects for prefix in ('STATICOBJ_SOURCE.', 'STATICOBJ_ORIGIN.')]
    argv = [arg for key in keys for arg in ('-v', key)]
    raw = env.query(argv, component=component, extra=extra)
    rows = raw.splitlines()
    if len(rows) != len(keys):
        raise ValueError('ambiguous static archive source mapping')
    inputs[str(Path(compile_context.__file__).resolve())] = digest(Path(compile_context.__file__))
    records = []
    aliases = set()
    for index, obj in enumerate(objects):
        object_path = relative_file(obj)
        alias, origin = rows[index * 2:index * 2 + 2]
        source_path = relative_file(alias)
        if source_path.suffix not in ('.c', '.cc', '.cpp', '.cxx', '.C') or source_path.with_suffix('.o') != object_path:
            raise ValueError('static object must map explicitly to matching C/C++ source alias')
        if alias in aliases or alias in shlex.split(metadata['SRCS']):
            raise ValueError('static source alias conflicts with another source')
        aliases.add(alias)
        if not origin:
            raise ValueError('static object source origin missing')
        path = (component / origin).resolve(strict=True)
        if not path.is_file() or not path.is_relative_to(src):
            raise ValueError('static object source outside maintained tree')
        sha = digest(path)
        inputs[str(path)] = sha
        context = compile_context.capture(env, component, alias, obj, 'c' if source_path.suffix == '.c' else 'c++', extra=extra)
        records.append(dict(object=obj, source=alias, origin=str(path.relative_to(src)), sha256=sha, variant='regular', compile_context=context))
    if env.query(argv, component=component, extra=extra) != raw:
        raise ValueError('static archive source mapping changed during export')
    return records
