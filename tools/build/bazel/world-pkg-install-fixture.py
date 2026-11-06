# SPDX-License-Identifier: BSD-2-Clause
"""Build package-derived disk fixtures for the maintained VM runner, unprivileged."""
import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from archive_headers import flag_bits,LIBRARY
from qualification_artifacts import resolve_many,digest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['qualification','plan','output']:
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();q=args.qualification.resolve(strict=True);out=args.output.resolve()
    if out.exists() or not out.is_relative_to('/usr/obj/usr/src'):
        raise ValueError('new standard object-root output required')
    plan=json.loads(args.plan.read_text());assert plan['format']==1
    assert type(plan['epoch']) is int and plan['epoch']>=0
    receipt=json.loads((q/'receipt.json').read_text());assert receipt['status']=='passed'
    manifest=q/receipt['artifacts']['manifest'];assert digest(manifest)==receipt['artifacts']['sha256']
    targets={t['target']['label']:t['outputs'] for t in json.loads(manifest.read_text())['targets']}
    selections=[('//:fresh_world_contributions',f['name']) for f in targets['//:fresh_world_contributions'] if f['name'].endswith('.tar')]
    archive_count=len(selections)
    selections += [('//:world_packages',f['name']) for f in targets['//:world_packages'] if f['name'].endswith('.pkg') or f['name'].endswith('/index.json')]
    selections += [('//:world_package_inventory','/world_package_inventory.json'),('//packages:world_family_manifests','/world_family_manifests.json')]
    resolved=resolve_many(q,selections);items=dict(zip(selections,resolved,strict=True))
    def one(label,suffix):
        found=[p for (l,n),(p,_) in items.items() if l==label and n.endswith(suffix)];assert len(found)==1,(label,suffix);return found[0]
    inventory=json.loads(one('//:world_package_inventory','/world_package_inventory.json').read_text());cat=json.loads(one('//packages:world_family_manifests','/world_family_manifests.json').read_text())
    pkg=Path(plan['pkg']).resolve(strict=True);makefs=Path(plan['makefs']).resolve(strict=True)
    out.mkdir(mode=0o700);stage=out/'target-root';stage.mkdir();inputs=out/'input-root';inputs.mkdir();repo=inputs/'repository';repo.mkdir()
    before={str(p):digest(p) for p in [pkg,makefs,args.plan.resolve(),Path(__file__).resolve(),Path(__file__).with_name('world-pkg-install-check.py'),Path(__file__).with_name('archive_headers.py'),LIBRARY,Path(plan['osversion_header'])]}
    commands=[]
    def run(argv,label):
        done=subprocess.run(list(map(str,argv)),capture_output=True,env={'PATH':'/bin:/usr/bin:/sbin:/usr/sbin','HOME':str(out),'LC_ALL':'C'})
        for kind,data in [('stdout',done.stdout),('stderr',done.stderr)]: (out/(label+'.'+kind)).write_bytes(data)
        commands.append(dict(argv=list(map(str,argv)),status=done.returncode));(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert done.returncode==0,(label,done.stderr.decode()[-1500:]);return done.stdout.decode()
    hashes={}
    for i,(source,binding) in enumerate(resolved[:archive_count]):
        with tarfile.open(source) as stream:
            for member in stream:
                assert not member.name.startswith('/') and '..' not in Path(member.name).parts
                if member.isfile():
                    path='/'+member.name.removeprefix('./');file=stream.extractfile(member);assert path not in hashes;hashes[path]=hashlib.file_digest(file,'sha256').hexdigest()
        run(['/usr/bin/tar','-xpf',source,'--no-same-owner','--no-fflags','-C',stage],'extract-'+str(i))
    users={line.split(':')[0]:int(line.split(':')[2]) for line in (stage/'etc/master.passwd').read_text().splitlines() if line and not line.startswith('#')}
    groups={line.split(':')[0]:int(line.split(':')[2]) for line in (stage/'etc/group').read_text().splitlines() if line and not line.startswith('#')}
    records={r['destination']:r for entries in inventory['packages'].values() for r in entries if r['type']!='dir'}
    construction=inventory['construction'];all_files=dict(records,**construction)
    directories=dict(inventory['shared_directories'])
    for entries in inventory['packages'].values():
        for record in entries:
            if record['type']=='dir':directories.setdefault(record['destination'],record)
    flags={value:flag_bits(value)[0] for value in {r.get('flags','') for r in list(all_files.values())+list(directories.values())}}
    def attributes(record):
        return dict(uid=users[record['owner']],gid=groups[record['group']],mode=int(record['mode'],8),flags=flags[record.get('flags','')])
    lines=[]
    for path,r in sorted(dict(directories,**all_files).items()):
        a=attributes(r);assert not any(c.isspace() for c in path)
        fields=['.'+path if path!='/' else '.','type='+{'symlink':'link','hardlink':'file'}.get(r['type'],r['type']),'uid='+str(a['uid']),'gid='+str(a['gid']),'mode='+r['mode'],'flags='+(r.get('flags','') or 'none'),'time='+str(plan['epoch'])+'.0']
        if r['type']=='symlink':fields.append('link='+r['link'])
        lines.append(' '.join(fields)+'\n')
    metalog=out/'target.METALOG';metalog.write_text(''.join(lines))
    def root(path):
        seen=set()
        while all_files[path]['type']=='hardlink':
            assert path not in seen;seen.add(path);path=all_files[path]['link']
        return path
    expected_files={}
    inode_groups={}
    for name,entries in inventory['packages'].items():
        topology=defaultdict(list)
        for record in entries:
            if record['type']=='dir':continue
            path=record['destination'];a=attributes(record)
            if record['type']=='symlink':a.update(type='symlink',link=record['link'])
            else:
                canonical=root(path);a.update(type='file',sha256=hashes[canonical]);topology[canonical].append(path)
            expected_files[path]=a
        inode_groups[cat['prefix']+'-'+name]=list(topology.values())
    for (label,name),(source,_) in items.items():
        if label=='//:world_packages':shutil.copyfile(source,repo/Path(name).name)
    # The declared index, not a directory glob, defines archive membership.
    index=json.loads((repo/'index.json').read_text());archives={e['name']:e['sha256'] for e in index['packages']}
    for name,sha in archives.items():assert digest(repo/name)==sha
    (repo/'index.json').unlink()
    (out/'pkg.conf').write_text('{}\n');(out/'empty-repos').mkdir()
    common=[pkg,'-C',out/'pkg.conf','-R',out/'empty-repos','-o','PKG_DBDIR='+str(out/'private-db'),'-o','SYSLOG=no','-o','PKG_ENABLE_PLUGINS=no']
    abi=run(common+['-o','ABI_FILE='+str(stage/'usr/bin/uname'),'config','ABI'],'abi').strip()
    versions=re.findall(r'^#define\s+__FreeBSD_version\s+(\d+)\s*$',Path(plan['osversion_header']).read_text(),re.M);assert len(versions)==1
    run(common+['repo','-l',repo],'repository')
    site=plan['site'];config_paths=[path for path,r in records.items() if 'config' in r['tags']];assert site['config'] in config_paths
    assert site['user']['uid'] not in users.values() and site['user']['name'] not in users
    assert site['data'] not in all_files and not any(p.startswith('/.pkg-check') for p in all_files)
    expected=dict(format=1,abi=abi,osversion=versions[0],pkg_sha256=digest(pkg),packages=sorted(cat['prefix']+'-'+n for n in cat['packages']),archives=archives,files=expected_files,directories={p:attributes(r) for p,r in directories.items()},construction={p:attributes(r) for p,r in construction.items()},inode_groups=inode_groups,config_paths=config_paths,site=site)
    (inputs/'expected.json').write_text(json.dumps(expected,sort_keys=True)+'\n')
    run([makefs,'-t','ffs','-B','little','-s',str(plan['target_mib'])+'m','-o','version=2','-F',metalog,out/'target.ufs',stage],'make-target')
    run([makefs,'-t','ffs','-B','little','-s',str(plan['input_mib'])+'m','-o','version=2',out/'input.ufs',inputs],'make-input')
    bootstrap=dict(plan['bootstrap'],archives=[],files=[],guest_driver='//tools/build/bazel/tests/world_pkg_vm:driver',guest_driver_destination='tests/world_pkg_vm_driver',checker=str(Path(__file__).with_name('world-pkg-install-check.py')),checker_inputs={'pkg-static':str(pkg)})
    (out/'bootstrap-plan.json').write_text(json.dumps(bootstrap,indent=2)+'\n')
    run(['/usr/local/bin/python3.12',Path(__file__).with_name('iconv-runtime-fixture.py'),'--qualification',q,'--plan',out/'bootstrap-plan.json','--output',out/'bootstrap'],'bootstrap')
    for name,sha in before.items():assert digest(Path(name))==sha,name
    result=dict(status='prepared',scope='Complete native package/installation corpus and separate explicit VM bootstrap; not installation or normal boot proof',qualification_receipt_sha256=digest(q/'receipt.json'),plan_sha256=digest(args.plan),source_bindings=[binding for _,binding in resolved],inputs_sha256=before,commands=commands,input_disk_sha256=digest(out/'input.ufs'),target_disk_sha256=digest(out/'target.ufs'),expected_sha256=digest(inputs/'expected.json'),packages=len(archives),files=len(expected_files),directories=len(directories),target_mib=plan['target_mib'],input_mib=plan['input_mib'])
    (out/'fixture.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ['source_bindings','inputs_sha256','commands']},indent=2))


if __name__=='__main__':
    main()
