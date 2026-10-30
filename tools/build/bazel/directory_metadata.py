# SPDX-License-Identifier: BSD-2-Clause
"""Shared validation of flattened BSD mtree directory metadata."""
from pathlib import PurePosixPath
import re
import shlex

def absolute(value):
    p = PurePosixPath(value)
    if not p.is_absolute() or '..' in p.parts or any(c.isspace() or c == '\\' for c in value):
        raise ValueError('unsupported directory path: ' + value)
    return str(p)


def normalize(attrs):
    if attrs.get('type') != 'dir' or not attrs.get('uname') or not attrs.get('gname'):
        raise ValueError('named-owner directory policy required')
    if not re.fullmatch('[0-7]{3,4}', attrs.get('mode','')):
        raise ValueError('unsupported directory mode')
    if attrs.get('flags','none') not in ('','none'):
        raise ValueError('directory file flags need explicit graph support')
    return {'type':'dir','uname':attrs['uname'],'gname':attrs['gname'],
            'mode':int(attrs['mode'],8),'tags':sorted(set(filter(None,attrs.get('tags','').split(',')))), 'flags':'none'}


def records(text):
    result=[]
    for line in text.splitlines():
        if not line or line.startswith('#'):continue
        if '\\' in line:raise ValueError('escaped mtree syntax needs explicit support')
        fields=shlex.split(line)
        if fields[0]!='.' and not fields[0].startswith('./'):
            raise ValueError('unsupported flattened mtree path')
        attrs={}
        for word in fields[1:]:
            if '=' not in word:raise ValueError('unsupported mtree attribute: '+word)
            key,value=word.split('=',1)
            if key in attrs:raise ValueError('duplicate mtree attribute')
            attrs[key]=value
        result.append((fields[0],attrs))
    return result
