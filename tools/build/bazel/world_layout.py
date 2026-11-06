# SPDX-License-Identifier: BSD-2-Clause
"""Serialize the complete source distrib-dirs layout without inventing ownership."""
import json
from pathlib import Path
import subprocess
import sys
from archive_policy import accounts
from directory_metadata import records,normalize,absolute
from install_archive import write_archive
from world_package_inventory import package


def merge(flattened, selected, suffixes):
    physical,claims,unselected={},{},[]
    for path,attrs in flattened:
        meta=normalize(attrs,allow_flags=True)
        record=dict(destination=path,type='dir',owner=meta['uname'],group=meta['gname'],
            mode=format(meta['mode'],'04o'),flags=meta['flags'],tags=[])
        if path in physical and physical[path]!=record:
            raise ValueError('conflicting complete mtree directory: '+path)
        physical[path]=record
        tags=meta['tags'];owners=[t[8:] for t in tags if t.startswith('package=')]
        if not owners:
            if tags:raise ValueError('directory tags lack package owner: '+path)
            continue
        if len(owners)!=1:raise ValueError('one mtree package owner required: '+path)
        name=package(dict(record,tags=tags),suffixes)
        if name in selected:
            claims[(name,path)]=dict(record,tags=tags)
        else:
            unselected.append(dict(path=path,package=name,tags=tags))
    return physical,list(claims.values()),unselected


def main():
    request=json.loads(Path(sys.argv[1]).read_text());flattened=[]
    for spec in request['specs']:
        text=subprocess.check_output([request['mtree'],'-C','-K','all','-f',spec['source']],text=True)
        for relative,attrs in records(text):
            prefix=absolute(spec['prefix']).rstrip('/')
            path=absolute(prefix+('/'+relative[2:] if relative!='.' else '') or '/')
            flattened.append((path,attrs))
    catalogue=json.loads(Path(request['catalogue']).read_text())
    physical,claims,unselected=merge(flattened,set(catalogue['packages']),request['suffix_tags'])
    write_archive(dict(records=list(physical.values()),users=accounts(request['passwd'],10),
        groups=accounts(request['group'],4),epoch=request['epoch']),Path(request['archive']))
    Path(request['metadata']).write_text(json.dumps(dict(format=1,directories=claims,physical_directories=list(physical.values())),sort_keys=True,indent=2)+'\n')
    Path(request['report']).write_text(json.dumps(dict(format=1,scope='complete-source-distrib-dirs',specs=request['specs'],physical_directories=physical,claims=claims,unselected_package_claims=unselected),sort_keys=True,indent=2)+'\n')


if __name__=='__main__':
    main()
