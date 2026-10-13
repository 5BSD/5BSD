#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check unchanged base source tokens, Makefile selection, and alternate USB guard."""
from pathlib import Path
import json,re,subprocess
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-fifteenth-validation');records=[]
lex=re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\w+|[^\s]',re.S)
def tokens(s):return [m[0] for m in lex.finditer(s) if not m[0].startswith(('/*','//'))]
for f in ['usr.bin/sockstat/main.c','usr.bin/ipcs/ipc.c','usr.bin/gzip/gzip.c','contrib/libarchive/tar/read.c']:
 old=(O/'before'/f).read_text();new=(S/f).read_text()
 new=re.sub(r'#include "(?:socketsnapshot|ipcsnapshot|gzipstream|archiveop)_trace.h"\n','',new)
 new=re.sub(r'#ifndef WITH_COVERAGE_DTRACE\n(?:#define trace_\w+ \w+\n)+#endif\n','',new)
 new=new.replace('\t\tTRACE_DECODE__ERROR(state, in_tot);\n','')
 ts=tokens(new);ts=[t.removeprefix('trace_') if t in ['trace_cap_sysctlbyname','trace_sysctlbyname','trace_inflate','trace_archive_read_next_header','trace_archive_read_extract2'] else t for t in ts]
 assert tokens(old)==ts,f
 records.append(dict(source=f,test='original source tokens preserved',status=0))
rows=json.loads((O/'base-results.json').read_text())
for component,provider in [('usr.bin/sockstat','socketsnapshot'),('usr.bin/ipcs','ipcsnapshot'),('usr.bin/gzip','gzipstream'),('usr.bin/tar','archiveop')]:
 row=next(r for r in rows if r['component']==component and r['hooks']=='yes')
 for mode,extra in [('on',[]),('off',['MK_DTRACE=no']),('rescue',['RESCUE=1']),('bootstrap',['BOOTSTRAPPING=1'])]:
  cmd=[a for a in row['command'][:-1] if not a.startswith('MK_DTRACE=')]+['MK_DTRACE=yes']
  if mode=='off':cmd=[a for a in cmd if not a.startswith('MK_DTRACE=')]
  cmd+=extra
  src=subprocess.check_output(cmd+['-V','${SRCS}'],text=True).split()
  flags=subprocess.check_output(cmd+['-V','${CFLAGS}'],text=True).split()
  present=any(provider+'_provider.' in a for a in src)
  assert present==(mode=='on') and ('-DWITH_COVERAGE_DTRACE' in flags)==(mode=='on'),(component,mode,src,flags)
  records.append(dict(component=component,mode=mode,test='build selection',status=0))
usb=(S/'sys/dev/usb/usb_hub.c').read_text()
blocks=re.findall(r'#ifndef USB_GLOBAL_INCLUDE_FILE\n.*?\n#endif',usb,re.S);assert len(blocks)==9
fixture=O/'guards/usb-global.c';fixture.write_text('#define USB_GLOBAL_INCLUDE_FILE 1\nint main(void) {\n'+'\n'.join(blocks)+'\nreturn 0; }\n')
subprocess.run(['cc','-Werror',str(fixture),'-o',str(fixture.with_suffix(''))],check=True,capture_output=True)
subprocess.run([str(fixture.with_suffix(''))],check=True)
records.append(dict(test='USB alternate branch excludes probes and arguments',status=0))
(O/'integration-results.json').write_text(json.dumps(records,indent=2)+'\n');print(len(records),'integration checks passed')
