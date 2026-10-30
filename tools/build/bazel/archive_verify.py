# SPDX-License-Identifier: BSD-2-Clause
"""Inspect locally built pkgbase archives against a verified native stage."""
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
from libmd_environment import digest
import stage_verify
import archive_headers



def configuration_entries(manifest, files, metalog, normalize):
    """Require pkg upgrade semantics to match the stage's config tags."""
    configured = manifest.get('config', [])
    if not isinstance(configured, list) or any(not isinstance(p, str) for p in configured):
        raise ValueError('package config inventory must be a list of paths')
    paths = [normalize(p) for p in configured]
    if len(paths) != len(set(paths)):
        raise ValueError('duplicate package config path')
    expected = {name for name in files
                if 'config' in metalog.get('/' + name, {}).get('tags', '').split(',')}
    if set(paths) != expected:
        raise ValueError('package config inventory differs from staged config tags')
    return sorted(paths)


def verify(archives, workspace, manifest_names, output, abi, version, tar=Path('/usr/bin/tar')):
    if output.exists():
        raise ValueError('fresh archive inspection directory required')
    stage=workspace/'bazel-bin/native_stage.root'
    metalog=stage_verify.records(workspace/'bazel-bin/native_stage.METALOG',unique=True)
    entries={}
    for name in manifest_names:
        for entry in json.loads((workspace/'bazel-bin'/(name+'_install_manifest.json')).read_text())['files']:
            destination=entry['destination']
            if destination in entries:raise ValueError('duplicate expected payload')
            entries[destination]=entry
    def safe_name(name):
        if not isinstance(name,str) or not name or name.startswith('//') or '..' in PurePosixPath(name).parts:
            raise ValueError('invalid package member path')
        return name.lstrip('/').rstrip('/')
    records=[];seen=set();names=set();hashes={str(p):digest(p) for p in archives}
    # Validate the complete archive inventory before creating an extraction tree.
    for archive in archives:
        manifest=json.loads(subprocess.check_output([str(tar),'-xOf',str(archive),'+MANIFEST']))
        if manifest.get('abi')!=abi or manifest.get('version')!=version or manifest['name'] in names:
            raise ValueError('archive identity/version/ABI mismatch')
        names.add(manifest['name'])
        files={safe_name(p) for p in manifest.get('files',{})}
        directories={safe_name(p) for p in manifest.get('directories',{})}
        if not files or len(files)!=len(manifest['files']) or files&seen:
            raise ValueError('empty or overlapping package payload')
        configuration_entries(manifest, files, metalog, safe_name)
        seen.update(files)
        listing=subprocess.check_output([str(tar),'-tf',str(archive)],text=True).splitlines()
        members=[safe_name(p) for p in listing]
        if len(members)!=len(set(members)) or set(members)!=files|directories|{'+MANIFEST','+COMPACT_MANIFEST'}:
            raise ValueError('archive members differ from package manifest')
        if any('/'+p not in metalog or metalog['/'+p]['type']!='dir' for p in directories):
            raise ValueError('archive directory absent from staged policy')
        headers=archive_headers.read(archive)
        if [safe_name(h['pathname']) for h in headers]!=members:
            raise ValueError('archive readers disagree on member inventory')
        for header in headers:
            name=safe_name(header['pathname'])
            if name in ('+MANIFEST','+COMPACT_MANIFEST'):continue
            destination='/'+name
            if destination not in metalog:raise ValueError('archive header outside stage')
            expected=metalog[destination]
            if header['uname']!=expected['uname'] or header['gname']!=expected['gname']:
                raise ValueError('archive owner/group differs: '+destination)
            if stat.S_IMODE(header['mode'])!=int(expected['mode'],8):
                raise ValueError('archive header mode differs: '+destination)
            try:
                archive_headers.check_flags(header,expected.get('flags','none'))
            except ValueError as error:
                raise ValueError(str(error)+': '+destination) from error
            if header['hardlink']:
                target='/'+safe_name(header['hardlink'])
                if target not in entries or expected['type']!='file' or not (stage/name).samefile(stage/target.lstrip('/')):
                    raise ValueError('archive hardlink header differs: '+destination)
            elif header['symlink'] is not None:
                if expected['type']!='link' or header['symlink']!=expected['link']:
                    raise ValueError('archive symlink header differs: '+destination)
            elif (expected['type']=='dir' and not stat.S_ISDIR(header['mode'])) or (expected['type']=='file' and not stat.S_ISREG(header['mode'])) or expected['type']=='link':
                raise ValueError('archive header type differs: '+destination)
        records.append({'archive':str(archive),'sha256':hashes[str(archive)],'manifest':manifest})
    if {'/'+p for p in seen}!=set(entries):
        raise ValueError('archive payload coverage differs from native stage')
    output.mkdir();tree=output/'root';tree.mkdir()
    for archive in archives:
        # pkg stores absolute names. bsdtar strips leading slashes without -P.
        subprocess.run([str(tar),'-xpf',str(archive),'--no-same-owner','--no-fflags',
                        '--exclude=+MANIFEST','--exclude=+COMPACT_MANIFEST','-C',str(tree)],check=True,
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    hardlinks=0
    for destination,entry in entries.items():
        file=tree/destination.lstrip('/');source=stage/destination.lstrip('/')
        metadata=metalog[destination];mode=file.lstat().st_mode
        if entry['type']=='symlink':
            if not stat.S_ISLNK(mode) or file.readlink()!=source.readlink():raise ValueError('archive symlink differs: '+destination)
        else:
            if not stat.S_ISREG(mode) or digest(file)!=digest(source):raise ValueError('archive payload bytes differ: '+destination)
            if stat.S_IMODE(mode)!=int(metadata['mode'],8):raise ValueError('archive file mode differs: '+destination)
            if entry['type']=='hardlink':
                if not file.samefile(tree/entry['link'].lstrip('/')):raise ValueError('archive hardlink differs: '+destination)
                hardlinks+=1
    found={'/'+str(p.relative_to(tree)) for p in tree.rglob('*')}
    if found!=set(metalog)-{'/'}:raise ValueError('extracted filesystem coverage differs')
    for destination,metadata in metalog.items():
        if metadata['type']=='dir':
            file=tree/destination.lstrip('/')
            if not file.is_dir() or file.is_symlink():raise ValueError('archive directory type differs')
            # Archive roots have no member; the extraction root is a local container.
            if destination!='/' and stat.S_IMODE(file.stat().st_mode)!=int(metadata['mode'],8):
                raise ValueError('archive directory mode differs: '+destination)
    for name,expected in hashes.items():
        if digest(Path(name))!=expected:raise ValueError('archive changed during inspection')
    result={'status':'passed','payloads':len(entries),'hardlinks':hardlinks,'archives':records,
            'scope':'archive identity, owner/group names, header metadata including file flags, complete extraction coverage, stage byte identity, modes, links and package config registration',
            'limitations':['Archive owner/group names are verified; numeric ID mapping requires installation qualification.',
                           'No package database installation, script execution or dependency solver check.']}
    (output/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
