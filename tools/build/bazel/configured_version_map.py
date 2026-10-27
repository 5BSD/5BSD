# SPDX-License-Identifier: BSD-2-Clause
"""Capture the maintained symbol-map generator and its configured preprocessor."""
from pathlib import Path
import shlex
import shutil
from libmd_environment import digest


def export(src, component, metadata, env, extra, inputs):
    if not metadata['SYMBOL_MAPS']:
        return None
    if not metadata['VERSION_DEF'] or not metadata['VERSION_MAP']:
        raise ValueError('symbol maps require version definitions and output')
    query=['-v','CPP','-v','_vgen','-v','PATH']
    raw=env.query(query,component=component,extra=extra)
    rows=raw.splitlines()
    if len(rows)!=3:raise ValueError('ambiguous version generator configuration')
    cpp=shlex.split(rows[0]);generator=rows[1]
    if not cpp:raise ValueError('missing configured preprocessor')
    executable=shutil.which(cpp[0],path=rows[2])
    if not executable or digest(Path(executable))!=digest(env.compiler):
        raise ValueError('configured preprocessor is not the selected staged Clang')
    inputs[str(Path(executable).resolve())]=digest(Path(executable))
    directories=[component]+[Path(p) if Path(p).is_absolute() else component/p for p in shlex.split(metadata['.PATH'])]
    def source(name):
        for directory in directories:
            p=(directory/name).resolve()
            if p.is_file() and p.is_relative_to(src):
                inputs[str(p)]=digest(p)
                return {'path':str(p.relative_to(src)),'sha256':inputs[str(p)]}
        raise ValueError('version generator input requires declared generation: '+name)
    record={'symbols':[source(p) for p in shlex.split(metadata['SYMBOL_MAPS'])],
            'versions':source(metadata['VERSION_DEF']),'generator':source(generator),
            'cpp_command':cpp,'compiler_resource':env.resource}
    if env.query(query,component=component,extra=extra)!=raw:raise ValueError('version generator configuration changed')
    return record


def cpp_flags(command,objtop,resource):
    # The selected executable is byte-bound to staged Clang by the exporter.
    # Preserve the configured driver flags, remapping only staged SDK locations.
    resource=Path(resource).relative_to(objtop/'tmp')
    result=[]
    for token in command[1:]:
        if token=='--sysroot='+str(objtop/'tmp'):
            result.append('--sysroot=toolchain/sysroot')
        elif token=='-B'+str(objtop/'tmp/usr/bin'):
            result.append('-Btoolchain/bin')
        elif token.startswith('-resource-dir'):
            raise ValueError('custom preprocessor resource directory requires explicit mapping')
        elif str(objtop) in token:
            raise ValueError('unmapped preprocessor object path: '+token)
        else:result.append(token)
    if '--sysroot=toolchain/sysroot' not in result:
        raise ValueError('configured preprocessor lacks selected SDK sysroot')
    return result+['-resource-dir=toolchain/sysroot/'+str(resource)]
