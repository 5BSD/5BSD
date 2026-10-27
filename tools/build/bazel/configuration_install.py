# SPDX-License-Identifier: BSD-2-Clause
"""Export bsd.confs.mk's effective per-file installation contract."""
import shlex
from pathlib import PurePosixPath


def export(metadata, query, add, source_identity):
    if query(['DESTDIR'])['DESTDIR']:
        raise ValueError('configuration policy must be queried without DESTDIR')
    groups=shlex.split(metadata['CONFGROUPS']);observed={}
    for group in groups:
        values=query([group,group+'TAG_ARGS']);files=shlex.split(values[group])
        if len(files)!=len(set(files)):raise ValueError('duplicate configured file')
        entries={}
        for name in files:
            keys=[group+kind+'_'+name for kind in ('OWN','GRP','MODE','NAME','PREFIX')]
            selected=query(keys)
            owner,account,mode,installed,directory=[selected[k] for k in keys]
            if not installed or PurePosixPath(installed).name!=installed or installed in ('.','..'):
                raise ValueError('configuration installed name must be a basename')
            if not directory.startswith('/'):
                raise ValueError('absolute effective configuration destination required')
            if 'config' not in values[group+'TAG_ARGS'].replace(',',' ').split():
                raise ValueError('configuration payload lacks config tag')
            add(directory.rstrip('/')+'/'+installed,'file',owner,account,mode,values[group+'TAG_ARGS'],role='configuration',**source_identity(name))
            entries[name]=selected
        observed[group]=dict(metadata=values,files=entries)
    return observed
