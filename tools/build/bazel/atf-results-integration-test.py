#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Verify flat/nested ATF artifact identities against private real Kyua evidence."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import atf_results
from libmd_environment import digest

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--workspace',type=Path,required=True)
p.add_argument('--sqlite',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--program',help='Explicit configured test identity; defaults to first in inventory')
a=p.parse_args()
source=a.workspace.resolve(strict=True);out=a.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj') or out==Path('/usr/obj') or source.is_relative_to(out) or out.is_relative_to(source):
    raise ValueError('fresh nonoverlapping output under /usr/obj required')
policies=json.loads((source/'configured-test-policy.json').read_text())
inventory=json.loads((source/'native-test-inventory.json').read_text())
name=a.program or sorted(policies)[0]
if name not in policies:raise ValueError('selected program not in policy inventory')
selected=[c for c in inventory['runtime_checks'] if c['name']==name]
if len(selected)!=1:raise ValueError('one configured runtime check required')
original_check=selected[0]
reference=source/'bazel-testlogs'/atf_results.artifact_path(name)/'test.outputs'
reference_hash=digest(reference/'results.db')
inputs={str(path):digest(path) for path in (Path(__file__),Path(atf_results.__file__),source/'configured-test-policy.json',source/'native-test-inventory.json',a.sqlite.resolve(strict=True))}
checks=[]
for layout in ('flat','nested'):
    work=out/layout;work.mkdir(parents=True)
    check=copy.deepcopy(original_check)
    if layout=='nested':
        check['name']='components/tests/'+name
        check['binary']='components/tests/'+str(atf_results.artifact_path(check['binary']))
        check['libraries']={soname:'components/libraries/'+str(index)+'/'+atf_results.artifact_path(artifact).name
                            for index,(soname,artifact) in enumerate(check['libraries'].items())}
    identity=check['name']
    (work/'configured-test-policy.json').write_text(json.dumps({identity:policies[name]}))
    inventory_path=work/'native-test-inventory.json'
    def write_inventory(value):inventory_path.write_text(json.dumps(dict(runtime_checks=value)))
    write_inventory([check])
    pairs=[(check['binary'],original_check['binary'])]+[(artifact,original_check['libraries'][soname]) for soname,artifact in check['libraries'].items()]
    for artifact,original in pairs:
        destination=work/'bazel-bin'/atf_results.artifact_path(artifact);destination.parent.mkdir(parents=True,exist_ok=True)
        destination.symlink_to((source/'bazel-bin'/atf_results.artifact_path(original)).resolve(strict=True))
    shutil.copyfile(source/'elf-runtime-check.py',work/'elf-runtime-check.py')
    directory=work/'bazel-testlogs'/identity/'test.outputs'
    shutil.copytree(reference,directory);directory.chmod(0o755)
    database=directory/'results.db';database.chmod(0o644);original=database.read_bytes()
    atf_results.verify(work,a.sqlite,out/(layout+'-positive.json'))
    def rejected(label,error):
        try:atf_results.verify(work,a.sqlite,out/(layout+'-'+label+'.json'))
        except ValueError as exc:
            if error not in str(exc):raise
            checks.append(dict(layout=layout,mutation=label,rejected=str(exc)))
        else:raise ValueError('damaged Kyua evidence accepted: '+label)
    mutations=[('missing_result','DELETE FROM test_results WHERE test_case_id=(SELECT min(test_case_id) FROM test_cases)', 'lacks a result'),
               ('missing_case','DELETE FROM test_cases WHERE test_case_id=(SELECT min(test_case_id) FROM test_cases)', 'inventory differ'),
               ('wrong_program',"UPDATE test_programs SET relative_path='other_program'",'program identity differs')]
    for label,sql,error in mutations:
        subprocess.run([str(a.sqlite),'-init','/dev/null','-batch',str(database),sql],check=True,env={'PATH':'/bin:/usr/bin','LC_ALL':'C'})
        rejected(label,error);database.write_bytes(original)
    write_inventory([check,check]);rejected('duplicate_check','duplicate runtime check identity')
    invalid=copy.deepcopy(check);invalid['binary']='../outside'
    write_inventory([invalid]);rejected('escaping_binary','workspace-relative artifact path')
    invalid=copy.deepcopy(check)
    if not invalid['libraries']:raise ValueError('fixture requires checked native libraries')
    invalid['libraries'][next(iter(invalid['libraries']))]='/outside'
    write_inventory([invalid]);rejected('absolute_library','workspace-relative artifact path')
    write_inventory([check]);atf_results.verify(work,a.sqlite,out/(layout+'-restored.json'))
if digest(reference/'results.db')!=reference_hash:raise ValueError('reference results changed')
for path,value in inputs.items():
    if digest(Path(path))!=value:raise ValueError('fixture input changed: '+path)
(out/'receipt.json').write_text(json.dumps(dict(status='passed',scope='real Kyua database audit in flat/nested layouts with negative controls; not new test execution',program=name,checks=checks,reference_database_sha256=reference_hash,input_sha256=inputs),indent=2)+'\n')
print(out/'receipt.json')
