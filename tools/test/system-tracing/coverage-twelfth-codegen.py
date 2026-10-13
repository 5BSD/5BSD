#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import json,subprocess,importlib.util,hashlib
O=Path('/usr/obj/5bsd-dtrace-twelfth-validation');S=Path('/usr/src');K=Path('/usr/obj/usr/src/amd64.amd64/sys/GENERIC-NODEBUG')
spec=importlib.util.spec_from_file_location('elf',S/'tools/test/system-tracing/coverage-sixth-objects.py');elf=importlib.util.module_from_spec(spec);spec.loader.exec_module(elf)
basecmd=next(r['command'] for r in json.loads((O/'kernel/results.json').read_text()) if r['name']=='pf-False')
objects=[]
for tag,source in [('before',O/'before/sys/netpfil/pf/pf.c'),('after',S/'sys/netpfil/pf/pf.c')]:
 cmd=basecmd.copy();at=cmd.index('-c');cmd[at+1]=str(source);cmd[at:at]=['-Wno-builtin-macro-redefined','-D__LINE__=0','-D__FILE__="pf.c"'];cmd[-1]=str(O/'kernel'/('pf-'+tag+'-normalized.o'))
 r=subprocess.run(cmd,cwd=K/'modules/usr/src/sys/modules/pf',capture_output=True,text=True);(O/'kernel'/('pf-'+tag+'-normalized.log')).write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
 objects.append(elf.Object(Path(cmd[-1])))
text=[o.section_data(o.names['.text']) for o in objects]
result=dict(test='PF no-hooks code generation with diagnostic file/line macros normalized',identical=text[0]==text[1],bytes=[len(t) for t in text],sha256=[hashlib.sha256(t).hexdigest() for t in text])
(O/'normalized-codegen-results.json').write_text(json.dumps(result,indent=2)+'\n');print(result)
assert result['identical']
