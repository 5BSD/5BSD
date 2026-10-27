#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise ATF runtime policy rejection against explicit qualification inputs."""
import sys,json,copy,importlib.util,argparse
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__)
for name in ('workspace','inventory','output'):parser.add_argument('--'+name,type=Path,required=True)
args=parser.parse_args()
root=args.workspace.resolve(strict=True);out=args.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj'):parser.error('fresh output under /usr/obj required')
out.mkdir()
c=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('runtime',c/'atf_runtime.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
settings=json.loads((root/'test-runtime.json').read_text());plan=json.loads((root/'plan.json').read_text());inventory=args.inventory.resolve(strict=True)
checks=[]
for name in ['boolean-version','outside-sdk','duplicate-library','wrong-profile','changed-tool']:
 config=copy.deepcopy(settings);environment=copy.deepcopy(plan['build_environment'])
 if name=='boolean-version':config['format']=True
 elif name=='outside-sdk':config['libraries']=['/lib/libc.so.7']
 elif name=='duplicate-library':config['libraries'].append(config['libraries'][0])
 elif name=='wrong-profile':environment['target']='not-the-selected-target'
 elif name=='changed-tool':
  receipt=json.loads(Path(config['receipt']).read_text());receipt['tools']['atf-sh']['sha256']='0'*64
  file=out/'bad-receipt.json';file.write_text(json.dumps(receipt));config['receipt']=str(file)
 path=out/(name+'.json');path.write_text(json.dumps(config));workspace=out/name;workspace.mkdir()
 try:module.stage(workspace,inventory,path,Path(plan['source_root']),environment)
 except ValueError as error:
  checks.append({'name':name,'rejected':True,'reason':str(error)})
 else:raise AssertionError(name+' was accepted')
 assert not (workspace/'ATF.BUILD.fragment').exists(), 'failed validation published a test graph'
(out/'receipt.json').write_text(json.dumps(checks,indent=2)+'\n');print('PASS:',len(checks),'runtime rejection checks')
