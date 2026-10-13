#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Whole-tree tracing macro census. Evidence is not semantic/live coverage."""
import collections,json,re,subprocess
from pathlib import Path
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-eighth-validation')
roots=['sys','bin','sbin','lib','libexec','usr.bin','usr.sbin','cddl','crypto','contrib','stand','rescue']
paths=subprocess.check_output(['rg','--files',*roots],cwd=S,text=True).splitlines()
call=re.compile(r'\b(?:SDT_PROBE\d*|DTRACE_PROBE\d*|LIN_SDT_PROBE\d*|TRACE_[A-Z_]+|[A-Z][A-Z0-9_]+_PROBE\d*)\s*\(')
groups=collections.defaultdict(lambda:dict(files=0,evidence=[]))
for name in sorted(paths):
 p=Path(name)
 if p.suffix not in ('.c','.cc','.cpp','.h','.S','.d'):continue
 parts=p.parts
 depth=3 if parts[0]=='sys' and len(parts)>3 and parts[1] in ('dev','fs','compat','security','geom') else 2
 group='/'.join(parts[:depth]);record=groups[group];record['files']+=1
 content=(S/p).read_text(errors='replace');content=re.sub(r'/\*.*?\*/','',content,flags=re.S)
 hits=sum(bool(call.search(l)) for l in content.splitlines() if not l.lstrip().startswith('#'))
 if hits:record['evidence'].append(dict(source=name,macro_lines=hits))
result=dict(head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=S,text=True).strip(),method='Known macro syntax only; no claim of build, installation, firing, semantic completeness, or coverage for groups without matching macros. Includes dormant and imported code. FBT/syscall/lockstat providers are not counted.',groups=dict(sorted(groups.items())))
(O/'whole-tree-census.json').write_text(json.dumps(result,indent=2)+'\n')
print(sum(v['files'] for v in groups.values()),'files',len(groups),'groups',sum(len(v['evidence']) for v in groups.values()),'files with macro evidence')
