# SPDX-License-Identifier: BSD-2-Clause
"""Real jailed library-hints construction from explicitly synthetic packages."""
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile


def require(value, message):
    if not value:
        raise AssertionError(message)


def fixture(base, construction):
    base.mkdir(); root=base/'root'; root.mkdir(mode=0o755)
    closure=json.loads(Path('/tests/library-executable.json').read_text())['files']
    files={p:(Path(p).read_bytes(),0o555) for p in closure}
    files['/ambient.conf']=(b'/search/ambient\n',0o444)
    parents={'/','/policy','/search','/search/one','/search/two','/search/ambient'}
    for name in files:parents.update(str(p) for p in Path(name).parents)
    ordered=sorted(parents-{'/'},key=lambda p:(len(Path(p).parts),p))
    for name in ordered:(root/name.lstrip('/')).mkdir(mode=0o755)
    initial={'format':1,'entries':{'/':dict(type='directory',uid=0,gid=0,mode=0o755,
        flags_set=0,source='explicit library fixture root',replaces=[])}}
    manifest=dict(name='library-fixture',version='1',files={p:{} for p in files},
                  directories={p:{} for p in ordered})
    archive_path=base/'fixture.pkg'
    with tarfile.open(archive_path,'w:gz') as archive:
        data=json.dumps(manifest).encode();header=tarfile.TarInfo('+MANIFEST');header.size=len(data)
        archive.addfile(header,io.BytesIO(data))
        for name in ordered:
            header=tarfile.TarInfo(name);header.type=tarfile.DIRTYPE;header.mode=0o755
            archive.addfile(header)
        for name,(data,mode) in files.items():
            target=root/name.lstrip('/');target.write_bytes(data);target.chmod(mode)
            os.utime(target,(1700000000,1700000000))
            header=tarfile.TarInfo(name);header.mode=mode;header.size=len(data);header.mtime=1700000000
            archive.addfile(header,io.BytesIO(data))
    inventory=construction.pkg.inventory_packages([archive_path])
    policy=dict(format=1,program='/sbin/ldconfig',directories=['/search/one','/search/two'],output='/policy/search.hints')
    return root,inventory,initial,policy


def run(base, construction):
    before=construction.jail_list()
    hashes=[]
    for label,reverse in [('ordered',False),('reversed',True)]:
        work=base/('library-'+label)
        root,inventory,initial,policy=fixture(work,construction)
        if reverse:policy['directories'].reverse()
        for name,value in [('inventory',inventory),('initial',initial),('policy',policy)]:
            (work/(name+'.json')).write_text(json.dumps(value))
        subprocess.run(['/usr/local/bin/python3.12','-I','-S','-B','/tests/construction.py',
            '--root',str(root),'--inventory',str(work/'inventory.json'),'--generated',str(work/'initial.json'),
            '--library-policy',str(work/'policy.json'),'--output',str(work/'report')],check=True)
        report=json.loads((work/'report/construction.json').read_text())
        require(report['result']=='PASS' and len(report['receipts'])==1,'library receipt missing')
        data=(root/'policy/search.hints').read_bytes()
        require(data[128:]==(':'.join(policy['directories'])+'\0').encode(),'search order differs or ambient input included')
        record=report['receipts'][0]['outputs']['/policy/search.hints']
        require(record['uid']==record['gid']==record['flags_set']==0 and record['mode']==0o444,'hints metadata differs')
        hashes.append(record['sha256'])
        require(construction.jail_list()==before,'library construction jail survived')
        print('LIBRARY_CONSTRUCTION '+json.dumps(dict(case=label,output_sha256=record['sha256'],
            policy_sha256=report['library_plan']['policy_sha256'],receipt_sha256=report['receipts'][0]['sha256']),sort_keys=True),flush=True)
    require(hashes[0]!=hashes[1],'directory order did not affect output')
    print('CONSTRUCTION_VM_PASS library_inventory_and_order',flush=True)
    for label in ('undeclared','changed-generator'):
        work=base/('library-'+label)
        root,inventory,initial,policy=fixture(work,construction)
        if label=='undeclared':policy['directories'].append('/missing')
        else:(root/'sbin/ldconfig').write_bytes(b'unapproved replacement')
        try:construction.construct(root,inventory,initial,work/'report',library_policy=policy)
        except ValueError:pass
        else:raise AssertionError('invalid library input approved: '+label)
        require(not (work/'report').exists(),'invalid input reached execution')
        require(not (root/'policy/search.hints').exists(),'invalid input produced hints')
        require(construction.jail_list()==before,'invalid library input created a surviving jail')
        print('CONSTRUCTION_VM_PASS library_'+label+'_rejected',flush=True)
