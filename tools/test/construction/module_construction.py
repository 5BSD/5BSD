# SPDX-License-Identifier: BSD-2-Clause
"""Actual jailed module-hints construction using explicitly synthetic packages."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def fixture(base, construction):
    base.mkdir(); root=base/'root'; root.mkdir()
    files={p:(Path(p).read_bytes(),0o555) for p in json.loads(Path('/tests/module-executable.json').read_text())['files']}
    files['/modules/selected.ko']=(Path('/tests/selected.ko').read_bytes(),0o444)
    files['/modules/linker.hints']=(b'packaged previous hints\n',0o644)
    files['/modules/ambient.dat']=(b'not an ELF module\n',0o444)
    parents={'/','/modules'}
    for path in files: parents.update(str(p) for p in Path(path).parents)
    for path in sorted(parents-{'/'},key=lambda p:(len(Path(p).parts),p)):
        (root/path.lstrip('/')).mkdir(mode=0o755)
    initial={'format':1,'entries':{p:dict(type='directory',uid=0,gid=0,mode=0o755,
        flags_set=0,source='explicit module fixture directory',replaces=[]) for p in parents}}
    archive_path=base/'fixture.pkg'
    manifest={'name':'module-fixture','version':'1','files':{p:{} for p in files}}
    with tarfile.open(archive_path,'w:gz') as archive:
        data=json.dumps(manifest).encode();header=tarfile.TarInfo('+MANIFEST');header.size=len(data)
        archive.addfile(header,io.BytesIO(data))
        for path,(data,mode) in files.items():
            target=root/path.lstrip('/');target.write_bytes(data);target.chmod(mode);os.utime(target,(1700000000,1700000000))
            header=tarfile.TarInfo(path);header.size=len(data);header.mode=mode;header.mtime=1700000000
            archive.addfile(header,io.BytesIO(data))
    inventory=construction.pkg.inventory_packages([archive_path])
    output=dict(name='linker.hints',uid=0,gid=0,mode=0o444,flags_set=0,replace=True)
    policy={'format':1,'program':'/usr/sbin/kldxref','groups':[
        dict(directory='/modules',packages=['module-*'],patterns=['*.ko'],required=True,output=output),
        dict(directory='/absent',packages=['*'],patterns=['*.ko'],required=False,output=dict(output,replace=False))]}
    return root,inventory,initial,policy


def run(base, construction):
    jails=construction.jail_list()
    good=base/'module-policy-good'
    root,inventory,initial,policy=fixture(good,construction)
    for name,data in [('inventory',inventory),('initial',initial),('policy',policy)]:
        (good/(name+'.json')).write_text(json.dumps(data))
    subprocess.run(['/usr/local/bin/python3.12','-I','-S','-B','/tests/construction.py',
        '--root',str(root),'--inventory',str(good/'inventory.json'),'--generated',str(good/'initial.json'),
        '--module-policy',str(good/'policy.json'),'--output',str(good/'report')],check=True)
    report=json.loads((good/'report/construction.json').read_text())
    require(report['result']=='PASS' and len(report['receipts'])==1,'module receipt missing')
    receipt=report['receipts'][0];plan=report['module_plan']
    require(receipt['action']['inputs']==['/modules/selected.ko'],'selection differs from policy')
    require(plan['selections'][1]['inputs']==[],'optional empty group not recorded')
    record=receipt['outputs']['/modules/linker.hints']
    require(record['sha256']==hashlib.sha256((root/'modules/linker.hints').read_bytes()).hexdigest(),'output hash differs')
    require(record['replaces']==[inventory['packages'][0]['archive_sha256']],'replacement owner not bound')
    require(record['uid']==record['gid']==record['flags_set']==0 and record['mode']==0o444,'output metadata differs')
    reference=good/'reference';reference.mkdir()
    (reference/'selected.ko').write_bytes(Path('/tests/selected.ko').read_bytes())
    subprocess.run(['/usr/sbin/kldxref','-o',str(reference/'linker.hints'),str(reference/'selected.ko')],check=True)
    require((root/'modules/linker.hints').read_bytes()==(reference/'linker.hints').read_bytes(),'jailed output differs')
    require(construction.jail_list()==jails,'module construction jail survived')
    print('MODULE_CONSTRUCTION '+json.dumps(dict(policy_sha256=plan['policy_sha256'],
        selection_sha256=plan['selection_sha256'],receipt_sha256=receipt['sha256'],
        fixture_archive_sha256=inventory['packages'][0]['archive_sha256'],
        module_sha256=hashlib.sha256(Path('/tests/selected.ko').read_bytes()).hexdigest(),
        output_sha256=record['sha256']),sort_keys=True),flush=True)
    print('CONSTRUCTION_VM_PASS module_inventory_recipe',flush=True)

    bad=base/'module-policy-invalid'
    root,inventory,initial,policy=fixture(bad,construction)
    policy['groups'][0]['patterns']=['*.ko','*.dat']
    try:
        construction.construct(root,inventory,initial,bad/'report',module_policy=policy)
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError('malformed selected module approved')
    require(not (bad/'report/generated.json').exists(),'failed action produced generated manifest')
    require((root/'modules/linker.hints').read_bytes()==b'packaged previous hints\n','failed action replaced hints')
    require(not list((root/'modules').glob('lhint.*')),'temporary hints survived')
    require(construction.jail_list()==jails,'failed module jail survived')
    print('CONSTRUCTION_VM_PASS module_selected_bad_input_rejected',flush=True)

    changed=base/'module-policy-changed'
    root,inventory,initial,policy=fixture(changed,construction)
    (root/'modules/selected.ko').write_bytes(b'unapproved replacement')
    try:
        construction.construct(root,inventory,initial,changed/'report',module_policy=policy)
    except ValueError:
        pass
    else:
        raise AssertionError('unapproved module replacement accepted')
    require(not (changed/'report').exists(),'changed input reached execution')
    require(construction.jail_list()==jails,'changed input created jail')
    print('CONSTRUCTION_VM_PASS module_changed_payload_rejected',flush=True)
