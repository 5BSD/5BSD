# SPDX-License-Identifier: BSD-2-Clause
"""Compare package-local hardlink serialization with pkg over a shared stage."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import tarfile
import tempfile


def run(args):
    spec = importlib.util.spec_from_file_location('world_pkg', args.driver)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    args.output.mkdir(parents=True, exist_ok=False)
    original_cwd = Path.cwd()
    with tempfile.TemporaryDirectory(prefix='world-hardlinks-', dir=args.output) as temporary:
        root = Path(temporary)
        os.chdir(root)
        try:
            Path('payload').write_bytes(b'package hardlink fixture\n')
            stage = root/'shared'
            (stage/'opt/fixture').mkdir(parents=True)
            canonical = stage/'opt/fixture/owner'
            canonical.write_bytes(Path('payload').read_bytes())
            os.link(canonical, stage/'opt/fixture/alias')
            os.link(canonical, stage/'opt/fixture/alias2')
            (root/'repos').mkdir()
            Path('pkg.conf').write_text('{}\n')
            records = {
                'owner': [dict(destination='/opt/fixture/owner', type='file', source='payload', owner='root', group='wheel', mode='0444', tags=['package=owner'])],
                'aliases': [dict(destination='/opt/fixture/'+name, type='hardlink', link='/opt/fixture/owner', owner='root', group='wheel', mode='0444', tags=['package=aliases']) for name in ['alias','alias2']],
            }
            records['aliases'][1]['link']='/opt/fixture/alias'
            # The host target is deliberately non-ELF. Both references must use
            # the declared ELF under the target root without changing link text.
            Path('elf-payload').write_bytes(args.abi_file.read_bytes())
            host_target=root/'outside/image';host_target.parent.mkdir();host_target.write_text('host marker, not ELF\n')
            def elf_record(path):
                return dict(destination=path,type='file',source='elf-payload',owner='root',group='wheel',mode='0444',tags=['package=owner'])
            records['owner'] += [elf_record('/opt/library/image'),elf_record(str(host_target))]
            for path in ['/opt/library/image',str(host_target)]:
                target=stage/path.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(Path('elf-payload').read_bytes())
            for name,link in [('elf-relative','../library/image'),('elf-chain','elf-relative'),('library-dir','../library'),('elf-via-directory','library-dir/image'),('dangling','../missing')]:
                records['aliases'].append(dict(destination='/opt/fixture/'+name,type='symlink',link=link,owner='root',group='wheel',mode='0777',tags=['package=aliases']))
                os.symlink(link,stage/'opt/fixture'/name)
            records['absolute']=[dict(destination='/opt/fixture/elf-absolute',type='symlink',link=str(host_target),owner='root',group='wheel',mode='0777',tags=['package=absolute'])]
            os.symlink(str(host_target),stage/'opt/fixture/elf-absolute')
            records['aliases'].append(dict(destination='/opt/empty/deep',type='dir',owner='root',group='wheel',mode='0755',tags=['package=aliases']))
            (stage/'opt/empty/deep').mkdir(parents=True)
            (stage/'opt/fixture').chmod(0o555)
            dirs = {p: dict(destination=p, type='dir', owner='root', group='wheel', mode='0555' if p=='/opt/fixture' else '0755', tags=[]) for p in ['/','/opt','/opt/fixture','/opt/empty','/opt/empty/deep']}
            for entries in records.values():
                for record in entries:
                    for parent in Path(record['destination']).parents:
                        path=str(parent)
                        dirs.setdefault(path,dict(destination=path,type='dir',owner='root',group='wheel',mode='0755',tags=[]))
            inventory = dict(format=1, scope='world-package-inventory', packages=records, shared_directories=dirs, construction={}, summary=dict(nondirectory_paths=sum(r['type']!='dir' for entries in records.values() for r in entries)))
            catalogue = dict(format=1, scope='world-package-family-set', prefix='Fixture', version='1', families={'owner':{},'aliases':{}}, packages={})
            for name in records:
                manifest = dict(name='Fixture-'+name, version='1', origin='test/'+name, prefix='/', comment='Hardlink fixture', desc='Hardlink fixture', maintainer='test@example.invalid', www='https://example.invalid', licenselogic='single', licenses=['BSD2CLAUSE'])
                Path(name+'.ucl').write_text(json.dumps(manifest))
                catalogue['packages'][name]=dict(metadata_only=False, manifest=name+'.ucl')
            Path('inventory.json').write_text(json.dumps(inventory));Path('catalogue.json').write_text(json.dumps(catalogue))
            gate = dict(status='passed', scope='world-package-metadata-reconciliation', packages=list(records), input_sha256=dict(inventory=module.digest('inventory.json'), catalogue=module.digest('catalogue.json')), manifest_sha256={name:module.digest(name+'.ucl') for name in records})
            Path('gate.json').write_text(json.dumps(gate))
            module.plans(dict(inventory='inventory.json',catalogue='catalogue.json',reconciliation='gate.json',outputs={name:name+'.plan.json' for name in records}))
            common = [str(args.pkg),'-C',str(root/'pkg.conf'),'-R',str(root/'repos'),'-o','PKG_DBDIR='+str(root/'db'),'-o','ABI_FILE='+str(args.abi_file)]
            abi = subprocess.check_output(common+['config','ABI'],text=True).strip()
            osversion=re.findall(r'^#define\s+__FreeBSD_version\s+(\d+)\s*$',args.osversion_header.read_text(),re.M)
            assert len(osversion)==1
            common=common[:-2]  # ABI_FILE is only the ABI query input.
            common+=['-o','OSVERSION='+osversion[0],'-o','ALLOW_BASE_SHLIBS=yes','-o','SHLIB_PROVIDE_PATHS_NATIVE=/lib,/usr/lib']
            assert abi and not any(c.isspace() for c in abi)
            results=[]
            for name,entries in records.items():
                # Normal pkg-create over a shared stage observes cross-package inodes.
                parents={str(p) for r in entries for p in Path(r['destination']).parents if str(p)!='/'}
                lines=[('@dir' if r['type']=='dir' else '@')+'(root,wheel,'+r['mode']+') '+r['destination'] for r in entries]+['@dir(root,wheel,'+dirs[p]['mode']+') '+p for p in sorted(parents)]
                Path(name+'.plist').write_text('\n'.join(lines)+'\n');reference=root/('reference-'+name);reference.mkdir()
                subprocess.run(common+['-o','ABI='+abi,'create','-f','tar','-T','1','-t','0','-r',str(stage),'-o',str(reference),'-M',name+'.ucl','-p',name+'.plist'],check=True)
                native=root/('native-'+name);native.mkdir();request=dict(package=name,plan=name+'.plan.json',manifest=name+'.ucl',sources=['payload','elf-payload'],trees=[],output=str(native/('Fixture-'+name+'-1.pkg')),index=str(native/'index.json'),pkg=str(args.pkg),abi_file=str(args.abi_file),osversion_header=str(args.osversion_header),format='tar',threads=1,epoch=0)
                module.package(request)
                documents=[];payloads=[];topologies=[];attributes=[]
                for package in [reference/('Fixture-'+name+'-1.pkg'),Path(request['output'])]:
                    with tarfile.open(package) as stream:
                        members={m.name.lstrip('./'):m for m in stream.getmembers()};documents.append(json.load(stream.extractfile(members['+MANIFEST'])))
                        attributes.append({k:(v.uid,v.gid,v.uname,v.gname,v.mode) for k,v in members.items() if not k.startswith('+')})
                        payloads.append({k:stream.extractfile(v).read() for k,v in members.items() if not k.startswith('+') and (v.isfile() or v.islnk())})
                        topology={}
                        for k,v in members.items():
                            if v.isfile() and not k.startswith('+'):topology[k]=k
                            elif v.islnk():topology[k]=v.linkname.lstrip('./')
                        groups={}
                        for k,target in topology.items():groups.setdefault(target,set()).add(k)
                        topologies.append({frozenset(g) for g in groups.values()})
                assert documents[0]==documents[1],name
                if name in ['aliases','absolute']:
                    assert documents[0].get('shlibs_required'),(name,'ELF inspection must see declared referents')
                # Inspection referents must never become this package's files.
                assert set(documents[1]['files'])=={r['destination'] for r in entries if r['type']!='dir'},name
                assert payloads[0]==payloads[1] and topologies[0]==topologies[1],name
                assert attributes[0]==attributes[1],(name,'archive attribute encoding')
                results.append(dict(package=name,paths=sorted(payloads[0]),inode_groups=[sorted(g) for g in sorted(topologies[0],key=lambda g:sorted(g))],numeric_owner_encoding=sorted({v[:2] for v in attributes[0].values()})))
            # Metadata-only resolver controls exercise POSIX component order:
            # link/.. is resolved after the link, and .. clamps at target /.
            resolve=module.inspection_paths
            fixture={'/a':dict(type='symlink',link='/real/deep'),'/cycle':dict(type='symlink',link='cycle')}
            assert resolve('/a/../image',fixture)=={'/a','/real/image'}
            assert resolve('/../../missing',fixture)=={'/missing'}
            assert resolve('/dangling',{})=={'/dangling'}
            try:resolve('/cycle',fixture)
            except ValueError as error:assert 'exceeds 40 symlinks' in str(error)
            else:raise AssertionError('cyclic inspection alias accepted')
            # The action's source allowlist remains enforced even for valid metadata.
            request['sources']=[];request['output']=str(args.output/'must-not-exist.pkg')
            try:module.package(request)
            except ValueError as error:assert str(error)=='payload source is not a declared package input'
            else:raise AssertionError('undeclared source accepted')
        finally:
            os.chdir(original_cwd)
            (stage/'opt/fixture').chmod(0o700)
    (args.output/'receipt.json').write_text(json.dumps(dict(status='passed',scope='Real pkg shared-stage versus native package-local hardlink serialization, complete manifests/payloads/inode groups; undeclared source rejection',results=results),indent=2)+'\n')
    print('WORLD_PKG_OWNER_ENCODING='+json.dumps([r['numeric_owner_encoding'] for r in results]))
    print('Shared-stage and native package-local pkg manifests, payloads and inode groups agree')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['driver','pkg','tar','abi-file','osversion-header','output']:parser.add_argument('--'+name,type=Path,required=True)
    run(parser.parse_args())
