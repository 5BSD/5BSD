#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check fresh qualification validation without creating a workspace."""
import argparse
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
import native_prepare

p=argparse.ArgumentParser(description=__doc__)
for key in ('inputs','src','objtop','bazel','output'):p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();config=json.loads(a.inputs.read_text());checks=[]
base=SimpleNamespace(src=a.src,objtop=a.objtop,bazel=a.bazel,inputs=a.inputs,output=Path('/usr/obj/usr/src/native-prepare-validation-'+str(os.getpid())))
assert not base.output.exists()
native_prepare.validate(config,base)
for case in ('boolean-format','unknown-key','empty-distdirs','relative-tool','object-root','input-overlap'):
 c=copy.deepcopy(config);args=copy.copy(base)
 if case=='boolean-format':c['format']=True
 elif case=='unknown-key':c['ignored-setting']='no'
 elif case=='empty-distdirs':c['distdirs']=[]
 elif case=='relative-tool':c['execution-tools']='tools.json'
 elif case=='object-root':args.output=Path('/usr/obj')
 elif case=='input-overlap':args.output=Path(config['repository-cache'])/('unexpected-stage-'+str(os.getpid()))
 try:native_prepare.validate(c,args)
 except ValueError as e:checks.append({'case':case,'status':'rejected','diagnostic':str(e)})
 else:raise RuntimeError('invalid preparation accepted: '+case)
 assert not base.output.exists()
a.output.write_text(json.dumps({'status':'passed','checks':checks,'validation_created_workspace':False},indent=2)+'\n')
print(a.output)
