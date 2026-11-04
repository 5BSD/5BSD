#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify managed CAS archives and uncached physical staging in fresh build states."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
from execution_log import objects
from qualification_artifacts import resolve

FIXTURE = '//tools/build/bazel/tests/install_materialization:'


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['src', 'frontend', 'qualification', 'inputs', 'output']:
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--tar', required=True, type=Path)
    args = parser.parse_args()
    src=args.src.resolve(strict=True); q=args.qualification.resolve(strict=True)
    out=args.output.resolve(); frontend=args.frontend.resolve(strict=True); tar=args.tar.resolve(strict=True)
    if (args.output.is_symlink() or out.exists() or out==Path('/usr/obj') or
            not out.is_relative_to('/usr/obj') or out.is_relative_to(src) or
            q.is_relative_to(out) or out.is_relative_to(q)):
        parser.error('fresh nonoverlapping evidence output below /usr/obj required')
    receipt=json.loads((q/'receipt.json').read_text()); config=json.loads(args.inputs.read_text())
    if (receipt['status']!='passed' or receipt['target_architecture']!='amd64' or
            receipt['action_cache']['mode']!='disk' or
            receipt['input_sha256'].get(str(args.inputs.resolve()))!=digest(args.inputs)):
        parser.error('passed input-bound native managed-cache qualification required')
    if not {FIXTURE+'archive',FIXTURE+'materialization_test'} <= set(receipt['targets']):
        parser.error('qualification must include the installation fixture and its validator')
    _, archive_binding=resolve(q,FIXTURE+'archive','/archive.tar')
    out.mkdir(mode=0o700)
    bindings={str(p):digest(p) for p in [Path(__file__).resolve(),frontend,tar,args.inputs.resolve(),q/'receipt.json',src/'tools/build/bazel/source_graph.py',src/'tools/build/bazel/bsd_stage.bzl',src/'usr.bin/xinstall/BUILD.bazel',src/'tools/build/bazel/tests/install_materialization/BUILD.bazel',src/'tools/build/bazel/tests/install_materialization/materialization_test.py',src/'tools/build/bazel/tests/install_materialization/payload.txt']}
    token=hashlib.sha256(str(out).encode()).hexdigest()[:16]
    results=[]
    for case,state in [('cold','install-cold-'+token),('restored','install-restored-'+token),('unchanged','install-restored-'+token)]:
        state_path=Path(receipt['build_state'])/'isolated-builds'/state/'bazel-root'
        if case!='unchanged' and state_path.exists():
            raise ValueError('fresh build state already exists: '+str(state_path))
        cfg=copy.deepcopy(config); cfg['targets']=[FIXTURE+'archive',FIXTURE+'materialization_test'];cfg['tests']=[FIXTURE+'materialization_test'];cfg['build-state']=state;cfg['execution-log-format']='json'
        inputs=out/(case+'-inputs.json');inputs.write_text(json.dumps(cfg,indent=2)+'\n')
        phase=out/case
        argv=[str(frontend),'bazel-test','--arch','amd64','--jobs',str(os.cpu_count()),'--bazel-inputs',str(inputs),'--output',str(phase)]
        print('Managed installation cache phase:',case,flush=True)
        subprocess.run(argv,cwd=src,check=True)
        result=json.loads((phase/'receipt.json').read_text())
        assert result['status']=='passed' and result['test_reports']['all_reported_cases_passed']
        assert result['test_reports']['case_counts']=={'passed':1}
        assert result['bazel_output_user_root']==str(state_path)
        assert result['action_cache']['path']==receipt['action_cache']['path']
        archive,b=resolve(phase,FIXTURE+'archive','/archive.tar');assert b['sha256']==archive_binding['sha256']
        with tarfile.open(archive) as stream:
            members={v.name:v for v in stream.getmembers()}
            assert set(members)=={'.','a','b','c','s','z'}
            assert all(v.uid==0 and v.gid==0 and v.mtime==42 for v in members.values())
            assert members['z'].mode==0o440 and members['.'].mode==0o750
            assert all(members[n].islnk() and members[n].linkname=='z' for n in ['a','b','c'])
            assert members['s'].issym() and members['s'].linkname=='z'
        extraction=out/(case+'-extracted');extraction.mkdir()
        subprocess.run([str(tar),'-xpf',str(archive),'--no-same-owner','-C',str(extraction)],check=True)
        assert all((extraction/n).samefile(extraction/'z') for n in ['a','b','c'])
        assert os.readlink(extraction/'s')=='z'
        assert (extraction/'z').read_bytes()==(src/'tools/build/bazel/tests/install_materialization/payload.txt').read_bytes()
        assert (extraction/'z').stat().st_mode & 0o7777==0o440
        assert extraction.stat().st_mode & 0o7777==0o750
        log=phase/'execution.json';assert digest(log)==result['execution_log_sha256']
        actions={'archive':[],'physical':[],'tests':[],'test_reports':[],'compilers':[]}
        for action in objects(log):
            mnemonic=action['mnemonic'];label=action.get('targetLabel','')
            key=('archive' if mnemonic=='BSDInstallArchive' and label==FIXTURE+'archive' else
                 'physical' if mnemonic=='BSDStageInstall' else
                 'tests' if mnemonic=='TestRunner' and label==FIXTURE+'materialization_test' and action['commandArgs'][0].endswith('/tools/test/test-setup.sh') else
                 'test_reports' if mnemonic=='TestRunner' and label==FIXTURE+'materialization_test' and action['commandArgs'][0].endswith('/tools/test/generate-xml.sh') else
                 'compilers' if mnemonic=='CppCompile' else None)
            if key:
                actions[key].append({'target':label,'cache_hit':action.get('cacheHit',False),'exit_code':action.get('exitCode'),'runner':action.get('runner'),'outputs':action['actualOutputs']})
        assert len(actions['tests'])==1 and not actions['tests'][0]['cache_hit'],actions['tests']
        if case in ['cold','restored']:
            assert len(actions['physical'])==1 and not actions['physical'][0]['cache_hit'] and actions['physical'][0]['exit_code']==0,actions['physical']
        if case=='restored':
            assert len(actions['archive'])==1 and actions['archive'][0]['cache_hit'],actions['archive']
            assert actions['compilers'] and all(a['cache_hit'] for a in actions['compilers']),actions['compilers']
        row={'case':case,'qualification_receipt_sha256':digest(phase/'receipt.json'),'archive':b,'execution_log_sha256':digest(log),'actions':actions,'external_extraction':'correct hardlinks, symlink, payload and modes; logical uid/gid checked in archive'}
        results.append(row);(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    for path, expected in bindings.items():
        assert digest(path)==expected,('input changed',path)
    (out/'receipt.json').write_text(json.dumps({'status':'passed','scope':'managed local CAS through maintained build-bsd, native bootstrap installer in separate cold/restored states, exact cached archive bytes, fresh physical hardlinks and external BSD tar extraction; not remote cache, full world/package/publication or performance qualification','input_sha256':bindings,'results':results,'host_installed':False},indent=2)+'\n')
    print(out/'receipt.json',flush=True)


if __name__=='__main__':
    main()
