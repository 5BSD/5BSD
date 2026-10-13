#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check optional build integration and preservation of non-instrumentation C tokens."""
import concurrent.futures,json,os,re,subprocess
from pathlib import Path
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-fourteenth-validation')
inv=json.loads((S/'tools/test/system-tracing/coverage-fourteenth.json').read_text())
# Preserve literals; exclude comments and whitespace only.
lex=re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][A-Za-z_0-9]*|[0-9]+|[^\s]',re.S)
def tokens(s):return [m[0] for m in lex.finditer(s) if not m[0].startswith(('/*','//'))]
records=[]
for c in inv['components']:
 f=c['source'];s=(S/f).read_text();before=(O/'before'/f).read_text()
 s=s.replace('#include "'+c['provider']+'_trace.h"','')
 functions=[r['function'] for r in inv['call_replacements'] if r['source']==f]
 for fn in functions+(['checksum'] if c['provider']=='checksumtool' else []):
  pattern=r'static [^\n]+\ntrace_'+fn+r'\([^{}]*?\)\n\{[^{}]*\}\n'
  s,n=re.subn(pattern,'',s);assert n==1,(f,fn,n)
 if c['provider']=='checksumtool':s=s.replace('trace_checksum(cfncn, fd, &val, &len)','cfncn(fd, &val, &len)')
 for fn in functions:
  # Only rewrite identifier tokens, leaving strings and comments untouched.
  s=lex.sub(lambda m:fn if m[0]=='trace_'+fn else m[0],s)
 assert tokens(s)==tokens(before),(f,'non-instrumentation tokens changed')
 records.append(dict(source=f,status=0))
(O/'source-preservation-results.json').write_text(json.dumps(records,indent=2)+'\n')
def check(job):
 c,mode=job;cmd=['make','-C',str(S/c['directory']),'-m',str(S/'share/mk'),'-V','SRCS','MK_DTRACE='+('no' if mode=='disabled' else 'yes')]
 if mode in ('RESCUE','BOOTSTRAPPING'):cmd+=[mode+'=yes']
 srcs=subprocess.check_output(cmd,text=True).split();present=any(c['provider']+'_provider.'+suffix in srcs for suffix in ('d','h'))
 assert present==(mode=='enabled'),(c,mode,srcs)
 return dict(component=c['directory'],mode=mode,status=0)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
 results=list(pool.map(check,[(c,m) for c in inv['components'] for m in ('enabled','disabled','RESCUE','BOOTSTRAPPING')]))
(O/'integration-results.json').write_text(json.dumps(results,indent=2)+'\n')
print(len(records),'C source token-preservation checks;',len(results),'build integration checks passed')
