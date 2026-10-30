# SPDX-License-Identifier: BSD-2-Clause
"""Export source aliases declared by the same variables used in Make rules."""
from pathlib import Path
from libmd_environment import digest


def export(src, component, names, query, extra, inputs):
    keys=['SOURCE_ALIAS.'+name for name in names]
    values=query(component,keys,extra) if keys else {}
    result={}
    for name in names:
        value=values['SOURCE_ALIAS.'+name]
        if not value:continue
        alias=Path(name)
        if alias.name!=name or name in ('.','..') or alias.suffix not in ('.c','.cc','.cpp','.cxx','.C','.S'):
            raise ValueError('source alias requires a C/C++/assembly basename: '+name)
        path=Path(value)
        if not path.is_absolute():raise ValueError('source alias requires an explicit absolute origin: '+name)
        path=path.resolve(strict=True)
        if not path.is_relative_to(src) or not path.is_file():
            raise ValueError('source alias origin outside maintained source tree: '+name)
        sha=digest(path);inputs[str(path)]=sha
        result[name]=dict(name=name,resolution='source-alias',path=str(path.relative_to(src)),sha256=sha)
    if keys and query(component,keys,extra)!=values:raise ValueError('source alias inventory changed during export')
    return result
