#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise native staging parity failures against an independent disposable copy."""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile
import stage_verify

p=argparse.ArgumentParser(description=__doc__)
for k in ('workspace','directory-policy','output'):p.add_argument('--'+k,type=Path,required=True)
for k in ('library-policy','test-policy'):p.add_argument('--'+k,type=Path)
p.add_argument('--component-policy',type=Path,action='append')
p.add_argument('--manifest-name',action='append')
a=p.parse_args();results=[]
if a.component_policy:
    if a.library_policy or a.test_policy or not a.manifest_name:
        p.error('component mode requires manifest names and no legacy policy options')
elif not (a.library_policy and a.test_policy) or a.manifest_name:
    p.error('legacy mode requires library and test policies')
def check(**kw):return stage_verify.verify(a.workspace,a.directory_policy,a.library_policy,a.test_policy,component_plans=a.component_policy,manifest_names=a.manifest_name,**kw)
def reject(name,expected,**kw):
    try:check(**kw)
    except ValueError as e:
        if expected not in str(e):raise
        results.append({'case':name,'status':'rejected','diagnostic':str(e)})
    else:raise RuntimeError(name+' unexpectedly passed')
check()
with tempfile.TemporaryDirectory(prefix='native-stage-parity-') as t:
    root=Path(t);original=a.workspace/'bazel-bin/native_stage.METALOG';text=original.read_text();meta=root/'METALOG'
    meta.write_text(text.replace('uname=root','uname=nobody',1));reject('wrong-owner','metadata mismatch',metalog=meta)
    meta.write_text(text+text.splitlines()[0]+'\n');reject('duplicate-record','duplicate stage METALOG',metalog=meta)
    tree=root/'tree';shutil.copytree(a.workspace/'bazel-bin/native_stage.root',tree,symlinks=True)
    for d in [tree,*tree.rglob('*')]:
        if d.is_dir() and not d.is_symlink():d.chmod(0o755)
    entries=[]
    for name in (a.manifest_name or ['library','test']):entries+=json.loads((a.workspace/('bazel-bin/'+name+'_install_manifest.json')).read_text())['files']
    links=[e for e in entries if e['type']=='hardlink']
    for e in links:
        target=tree/e['destination'].lstrip('/');target.unlink();os.link(tree/e['link'].lstrip('/'),target)
    check(tree=tree)
    e=links[0];target=tree/e['destination'].lstrip('/');data=target.read_bytes();target.unlink();target.write_bytes(data)
    reject('broken-hardlink','hardlink inode differs',tree=tree)
    target.unlink();os.link(tree/e['link'].lstrip('/'),target)
    e=next(e for e in entries if e['type']=='file');target=tree/e['destination'].lstrip('/');target.chmod(0o644)
    with target.open('ab') as f:f.write(b'corrupt')
    reject('corrupt-payload','stage digest differs',tree=tree)
a.output.write_text(json.dumps({'status':'passed','checks':results,'positive_copy_verified':True},indent=2)+'\n')
print(a.output)
