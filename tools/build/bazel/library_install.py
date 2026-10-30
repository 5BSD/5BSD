# SPDX-License-Identifier: BSD-2-Clause
"""Map reconciled library installation policy to declared Bazel artifacts."""
import hashlib
import json
from pathlib import Path
import shlex
import shutil


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emit(root, policy_path, compression_receipt, library, artifact_labels=None, namespace="library"):
    labels = artifact_labels or {'static_archive': ':md', 'shared_library': ':md_runtime_install', 'shared_debug': ':md_debug'}
    policy=json.loads(policy_path.read_text())
    if policy['status']!='reconciled':
        raise ValueError('reconciled library installation policy required')
    for key in ('objtop','target','profile_assignments'):
        if policy['build_environment'][key]!=library['build_environment'][key]:
            raise ValueError('library installation profile differs: '+key)
    for key in policy['metadata'].keys() & library['metadata'].keys():
        if policy['metadata'][key] != library['metadata'][key]:
            raise ValueError('installation/build metadata differs: '+key)
    inputs=dict(policy['input_sha256'])
    inputs[str(policy_path)]=digest(policy_path)
    receipt=json.loads(compression_receipt.read_text())
    if receipt['status']!='passed' or set(receipt['tools'])!={'gzip'}:
        raise ValueError('verified static gzip build receipt required')
    tool=receipt['tools']['gzip']
    for key in ('objtop','target','profile_assignments'):
        if tool['environment'][key]!=library['build_environment'][key]:
            raise ValueError('compression tool profile differs: '+key)
    inputs.update(receipt['inputs']);inputs.update(receipt['source_hashes'])
    inputs.update(tool['environment']['input_sha256']);inputs.update(tool['configured_make_include_closure'])
    inputs[str(compression_receipt)]=digest(compression_receipt)
    inputs[tool['binary']]=tool['sha256']
    if not tool['static_elf']:
        raise ValueError('compressor must have a verified static execution closure')
    for path,expected in inputs.items():
        if digest(Path(path))!=expected:raise ValueError('installation input changed: '+path)
    tools=root/'install-tools';tools.mkdir(exist_ok=True)
    shutil.copy2(tool['binary'],tools/'gzip')
    if digest(tools/'gzip')!=tool['sha256']:raise ValueError('compressor changed while staging')
    source_root=Path(library['source_root']).resolve(strict=True)
    def source(record):
        origin=Path(record['source_origin']).resolve(strict=True)
        relative=Path('sources')/origin.relative_to(source_root)
        target=root/relative
        if digest(origin)!=record['source_sha256']:raise ValueError('payload source changed')
        if target.exists():
            if digest(target)!=record['source_sha256']:raise ValueError('payload snapshot differs: '+str(relative))
        else:
            target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(origin,target)
        if digest(target)!=record['source_sha256']:raise ValueError('payload changed while staging')
        return str(relative)
    lines=['load("//:bsd_install.bzl", "bsd_install_link", "bsd_compress")']
    records=[]
    generators={g['output']:g for g in library['generators']}
    for index,(destination,record) in enumerate(sorted(policy['payloads'].items())):
        name=namespace+'_install_record_'+str(index)
        values=dict(name=name,destination=destination,owner=record['uname'],group=record['gname'],mode=format(record['mode'],'04o'),install_tags=record['tags'])
        role=record['role']
        if role in ('shared_symlink','configured_symlink','manual_hardlink','program_hardlink'):
            values['kind']='symlink' if role in ('shared_symlink','configured_symlink') else 'hardlink'
            values['target']=record['link'] if role in ('shared_symlink','configured_symlink') else record['hardlink']
            rule='bsd_install_link'
        else:
            rule='bsd_install_file'
            values['flags']=record.get('flags','')
            if role in ('static_archive','pic_archive','shared_library','shared_debug','program','program_debug'):
                label=labels[role]
            elif role=='shared_link_script':
                if record['script']!=library.get('shared_link_script'):
                    raise ValueError('linker-script configuration differs from installation policy')
                label=labels['shared_link_script']
            elif role=='pkg_config':
                output=record['generated_output']
                if generators.get(output)!=record['generator']:
                    raise ValueError('pkg-config generator differs from library plan')
                label=labels['generated:'+output]
            elif role in ('configuration','file'):
                if 'catalogue_output' in record:
                    output=record['catalogue_output']
                    catalogues={g['name']:g for g in (library.get('nls_generation') or {}).get('outputs',[])}
                    if catalogues.get(output)!=record['catalogue']:
                        raise ValueError('catalogue generator differs from library plan')
                    label=labels['catalogue:'+output]
                elif 'generated_output' in record:
                    output=record['generated_output']
                    if generators.get(output)!=record['generator']:
                        raise ValueError('configuration generator differs from library plan')
                    label=labels['generated:'+output]
                else:label=source(record)
            elif role=='header':label=source(record)
            elif role=='manual':
                if 'generated_output' in record:
                    output=record['generated_output']
                    if generators.get(output)!=record['generator']:
                        raise ValueError('manual generator differs from library plan')
                    label=':gen_'+output
                else:label=source(record)
                compression=shlex.split(record['compression'] or '')
                if compression:
                    if compression!=['gzip','-cn']:
                        raise ValueError('unsupported manual compression policy')
                    compressed=namespace+'_manual_'+str(index)
                    options=dict(name=compressed,src=label,output='compressed/'+namespace+'/'+Path(destination).name,arguments=compression[1:],compressor='install-tools/gzip',redirect='//toolchain:stdout_redirect')
                    lines.append('bsd_compress('+', '.join(k+'='+json.dumps(v) for k,v in options.items())+')')
                    label=':'+compressed
            else:raise ValueError('unmapped library payload role: '+role)
            values['src']=label
        lines.append(rule+'('+', '.join(k+'='+json.dumps(v) for k,v in values.items())+')')
        records.append(':'+name)
    lines.append('bsd_install_manifest(name='+json.dumps(namespace+'_install_manifest')+', entries='+json.dumps(records)+')')
    for path,expected in inputs.items():
        if digest(Path(path))!=expected:raise ValueError('input changed during library graph emission: '+path)
    (root/(namespace+'-install-inputs.json')).write_text(json.dumps(inputs,indent=2)+'\n')
    return lines
