# SPDX-License-Identifier: BSD-2-Clause
"""Map explicitly declared extra variant objects to maintained source inputs."""
from pathlib import Path
import shlex
from libmd_environment import digest


def export(src,component,metadata,query,extra,inputs):
    objects=shlex.split(metadata.get('VARIANT_SOURCE_OBJECTS',''))
    if not objects:return []
    if not metadata['LIB'] or len(objects)!=len(set(objects)):
        raise ValueError('unique extra variant objects require a library')
    inventories={v:set(shlex.split(metadata[k])) for v,k in [('regular','OBJS'),('pic','SOBJS'),('pie','PIEOBJS'),('nossp_pic','NOSSPSOBJS')]}
    suffixes={'regular':'.o','pic':'.pico','pie':'.pieo','nossp_pic':'.nossppico'}
    keys=['VARIANT_SOURCE.'+obj for obj in objects];values=query(component,keys,extra);sources={}
    for obj in objects:
        variants=[v for v,inventory in inventories.items() if obj in inventory]
        if len(variants)!=1:raise ValueError('extra object must belong to exactly one configured variant: '+obj)
        path=Path(values['VARIANT_SOURCE.'+obj])
        if not path.is_absolute():raise ValueError('extra variant source needs an absolute origin')
        path=path.resolve(strict=True)
        if not path.is_relative_to(src) or not path.is_file() or path.suffix not in ('.c','.cc','.cpp','.cxx','.C','.S'):
            raise ValueError('extra variant source outside maintained tree or unsupported')
        name=path.name
        if name in shlex.split(metadata['SRCS']) or obj!=str(Path(name).with_suffix(suffixes[variants[0]])):
            raise ValueError('extra variant source conflicts with SRCS or object name')
        sha=digest(path);inputs[str(path)]=sha
        record=sources.setdefault(name,dict(name=name,path=str(path.relative_to(src)),sha256=sha,objects=[]))
        if record['path']!=str(path.relative_to(src)):raise ValueError('ambiguous extra source basename')
        record['objects'].append(obj)
    if query(component,keys,extra)!=values:raise ValueError('extra variant mapping changed during export')
    return list(sources.values())
