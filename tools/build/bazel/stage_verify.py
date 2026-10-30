# SPDX-License-Identifier: BSD-2-Clause
"""Verify native stage content and metadata against reconciled Make policy."""
from collections import deque
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

spec = importlib.util.spec_from_file_location('directory_policy', Path(__file__).with_name('libmd-directory-plan.py'))
directory_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(directory_policy)

def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def require(condition, message):
    if not condition: raise ValueError(message)

def records(path, unique=False):
    result = {}
    for name, meta in directory_policy.records(path.read_text()):
        name = '/' if name == '.' else name[1:]
        require('..' not in name.split('/') and '//' not in name, 'invalid METALOG path')
        require(not unique or name not in result, 'duplicate stage METALOG path: '+name)
        result[name] = meta
    return result

def hardlink_roots(entries):
    """Independently validate the manifest's inode graph before inspecting files."""
    roots = {path:path for path, entry in entries.items() if entry['type']=='file'}
    pending = {}
    for path, entry in entries.items():
        if entry['type'] == 'hardlink':
            target = entry['link']
            require(target in entries and entries[target]['type'] in ('file','hardlink'),
                    'hardlink source missing or not regular: '+path)
            pending.setdefault(target, []).append(path)
    queue = deque(roots)
    while queue:
        target = queue.popleft()
        for path in pending.get(target, ()):
            root = roots[target]
            for key in ('owner','group','mode','flags'):
                require(entries[path].get(key,'')==entries[root].get(key,''),
                        'hardlink inode metadata differs: '+path)
            roots[path] = root
            queue.append(path)
    require(all(path in roots for path, entry in entries.items() if entry['type']=='hardlink'),
            'hardlink cycle in payload manifest')
    return roots

def verify(workspace, directory_plan, library_plan=None, test_plan=None, *, metalog=None, tree=None, component_plans=None, manifest_names=None):
    directory = json.loads(directory_plan.read_text())
    require(directory['status']=='reconciled', 'reconciled directory policy required')
    for p,h in directory['input_sha256'].items():
        require(digest(p)==h, 'directory policy input changed: '+p)
    reference_files=set()
    if component_plans is not None:
        require(bool(component_plans) and bool(manifest_names) and len(component_plans)==len(manifest_names), 'component policies and manifests must correspond')
        policies=[json.loads(p.read_text()) for p in component_plans]
        require(all(p['status']=='reconciled' for p in policies),'reconciled component policies required')
        payload_paths=[path for p in policies for path in p['payloads']]
        require(len(payload_paths)==len(set(payload_paths)),'overlapping component payloads')
        selected_plans=component_plans
        reference={}
        for p in policies:
            reference_files.update(path for path,entry in p['payloads'].items() if entry.get('role')=='file')
            source=records(Path(p['reference'])/'METALOG')
            for path in p['payloads']:
                require(path in source,'payload missing from Make reference')
                reference[path]=source[path]
        for path,attrs in directory['directories'].items():
            reference[path]=dict(attrs,mode=format(attrs['mode'],'04o'),tags=','.join(attrs['tags']))
        names=manifest_names
    else:
        library=json.loads(library_plan.read_text());tests=json.loads(test_plan.read_text())
        require(library['status']=='reconciled','reconciled installation policy required')
        reference_files.update(path for path,entry in library['payloads'].items() if entry.get('role')=='file')
        payload_paths=list(library['payloads'])+[x['destination'] for x in tests['files']]
        selected_plans=[library_plan,test_plan]
        reference=records(Path(directory['reference'])/'METALOG')
        names=['library','test']
    for p in selected_plans:
        require(directory['input_sha256'].get(str(p))==digest(p), 'unbound payload policy: '+str(p))
    expected_paths=set(directory['directories'])|set(payload_paths)
    metalog = metalog or workspace/'bazel-bin/native_stage.METALOG'
    tree = tree or workspace/'bazel-bin/native_stage.root'
    actual = records(metalog, unique=True)
    require(set(actual)==expected_paths, 'stage METALOG path coverage differs from policy')
    entries = {}
    for name in names:
        for entry in json.loads((workspace/('bazel-bin/'+name+'_install_manifest.json')).read_text())['files']:
            destination = entry['destination']
            require(destination not in entries, 'duplicate payload destination')
            entries[destination] = entry
    require(set(entries)==expected_paths-set(directory['directories']), 'payload manifest coverage differs from policy')
    for path, meta in actual.items():
        require(path in reference, 'path missing from Make reference: '+path)
        expected = reference[path]
        for key in ('type','uname','gname','mode','flags','tags','link'):
            av,ev=meta.get(key,''),expected.get(key,'')
            if key=='mode':av,ev=int(av,8),int(ev,8)
            elif key=='tags':av,ev=sorted(filter(None,av.split(','))),sorted(filter(None,ev.split(',')))
            elif key=='flags':av,ev=av or 'none',ev or 'none'
            require(av==ev, 'Make metadata mismatch: '+path+' '+key)
    for path in directory['directories']:
        require(stat.S_ISDIR((tree/path.lstrip('/')).lstat().st_mode), 'stage directory is absent or not a directory: '+path)
    roots = hardlink_roots(entries)
    hardlinks=symlinks=0
    for path, entry in entries.items():
        file=tree/path.lstrip('/');st=file.lstat();kind=entry['type']
        if kind=='symlink':
            require(stat.S_ISLNK(st.st_mode) and os.readlink(file)==entry['link'], 'symlink differs: '+path)
            symlinks+=1
        else:
            require(kind in ('file','hardlink') and stat.S_ISREG(st.st_mode), 'unexpected payload type: '+path)
            sha=digest(file)
            require(sha==actual[path].get('sha256'), 'stage digest differs from METALOG: '+path)
            if 'config' in reference[path].get('tags','').split(','):
                require(sha==reference[path].get('sha256'), 'configuration bytes differ from Make reference: '+path)
            if path in reference_files:
                require(sha==reference[path].get('sha256'), 'file-group bytes differ from Make reference: '+path)
            require(str(st.st_size)==actual[path].get('size'), 'stage size differs from METALOG: '+path)
            if kind=='file':
                source=Path(entry['source'])
                require(not source.is_absolute() and '..' not in source.parts, 'invalid declared payload source')
                require(sha==digest(workspace/source), 'stage bytes differ from Bazel output: '+path)
            else:
                require(roots[path] in entries, 'hardlink regular source missing')
                other=(tree/entry['link'].lstrip('/')).lstat()
                require((st.st_dev,st.st_ino)==(other.st_dev,other.st_ino), 'hardlink inode differs: '+path)
                hardlinks+=1
    found={'/'+str(p.relative_to(tree)) for p in tree.rglob('*')}
    require(found==expected_paths-{'/'}, 'filesystem path coverage differs from policy')
    return {'status':'passed','directories':len(directory['directories']),'payloads':len(entries),'hardlinks':hardlinks,'symlinks':symlinks,'metalog_sha256':digest(metalog),'reference_metalog_sha256':digest(Path(directory['reference'])/'METALOG'),'scope':'Make metadata parity, Bazel payload byte identity, actual links and complete selected stage path coverage','limitations':['Package ownership/modes come from METALOG; Bazel output tree physical modes are not installation policy.','Independent Make and Bazel compiled-byte identity is not asserted.','Comparison reuses the hash-bound Make reference; this does not rebuild it.']}
