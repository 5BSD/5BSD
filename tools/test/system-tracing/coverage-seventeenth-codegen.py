#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compare no-hooks .text against saved originals with file/line diagnostics normalized.
This is a code-generation check, not a runtime behavior or relocation-equivalence test.
"""
from pathlib import Path
import concurrent.futures,hashlib,importlib.util,json,os,subprocess,sys
O=Path('/usr/obj/5bsd-dtrace-seventeenth-validation'); S=Path('/usr/src'); K=Path('/usr/obj/usr/src/amd64.amd64/sys/GENERIC-NODEBUG')
spec=importlib.util.spec_from_file_location('elf',S/'tools/test/system-tracing/coverage-sixth-objects.py');elf=importlib.util.module_from_spec(spec);spec.loader.exec_module(elf)
rows=[r for r in json.loads((O/'kernel/results.json').read_text()) if r['name'].endswith('-False')]
commands=[r['command'] for r in rows if len(sys.argv)==1 or r['source'] in sys.argv[1:]]
def run(basecmd):
 source=Path(basecmd[basecmd.index('-c')+1]).relative_to(S);objects=[]
 for tag,path in [('before',O/'before'/source),('after',S/source)]:
  cmd=basecmd.copy();at=cmd.index('-c');cmd[at+1]=str(path)
  cmd[at:at]=['-Wno-builtin-macro-redefined','-D__LINE__=0','-D__FILE__="'+source.name+'"','-I'+str((S/source).parent)]
  cmd[-1]=str(O/'kernel'/(source.stem+'-'+tag+'-normalized.o'))
  cwd=next(r['cwd'] for r in rows if r['command']==basecmd)
  r=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True)
  Path(cmd[-1]).with_suffix('.log').write_text(r.stdout+r.stderr)
  assert r.returncode==0,(source,r.stderr)
  objects.append(elf.Object(Path(cmd[-1])))
 data=[o.section_data(o.names['.text']) for o in objects]
 result=dict(source=str(source),identical=data[0]==data[1],bytes=[len(t) for t in data],sha256=[hashlib.sha256(t).hexdigest() for t in data])
 print(source,result['identical'],flush=True);return result
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:results=list(pool.map(run,commands))
if len(sys.argv)>1 and (O/'normalized-codegen-results.json').exists():
 previous={r['source']:r for r in json.loads((O/'normalized-codegen-results.json').read_text())};previous.update({r['source']:r for r in results});results=list(previous.values())
(O/'normalized-codegen-results.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(int(any(not r['identical'] for r in results)))
