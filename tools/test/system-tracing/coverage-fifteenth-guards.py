#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Fault-inject the real USDT headers; no live tracing or global state changes."""
from pathlib import Path
import json,subprocess
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-fifteenth-validation');T=O/'guards';T.mkdir(exist_ok=True)
inv=json.loads((S/'tools/test/system-tracing/coverage-fifteenth.json').read_text());results=[]
fixtures={
'socketsnapshot':('typedef void cap_channel_t;\nstatic int cap_sysctlbyname(cap_channel_t *c, const char *n, void *o, size_t *l, const void *v, size_t z) { (void)c;(void)n;(void)v;(void)z; assert(errno==EAGAIN); original_calls++; if (result==0 && l) *l=7; (void)o; errno=EINTR; return result; }', [('trace_cap_sysctlbyname(NULL, "fixture", buffer, &length, NULL, 0)',[-1,0])]),
'ipcsnapshot':('static int sysctlbyname(const char *n, void *o, size_t *l, const void *v, size_t z) { (void)n;(void)o;(void)v;(void)z; assert(errno==EAGAIN); original_calls++; if(result==0 && l) *l=7; errno=EINTR; return result; }',[('trace_sysctlbyname("fixture", buffer, &length, NULL, 0)',[-1,0])]),
'gzipstream':('typedef struct { unsigned int avail_in, avail_out; } stream_t; typedef stream_t *z_streamp; static stream_t stream={10,20}; static int inflate(z_streamp s, int f) { (void)s;(void)f;assert(errno==EAGAIN);original_calls++;errno=EINTR;return result; }',[('trace_inflate(&stream, 4)',[-5,-3,0,1])]),
'archiveop':('struct archive; struct archive_entry; static int archive_read_next_header(struct archive *a, struct archive_entry **e) { (void)a;(void)e;assert(errno==EAGAIN);original_calls++;errno=EINTR;return result; } static int archive_read_extract2(struct archive *a, struct archive_entry *e, struct archive *w) { (void)a;(void)e;(void)w;assert(errno==EAGAIN);original_calls++;errno=EINTR;return result; }',[('trace_archive_read_next_header(NULL,NULL)',[-30,-20,0,1]),('trace_archive_read_extract2(NULL,NULL,NULL)',[-30,-20,0])])}
for provider,(stub,operations) in fixtures.items():
 ps=[p for p in inv['probes'] if p['provider']==provider+'*'];d=T/provider;d.mkdir(exist_ok=True)
 fake='';body=''
 for p in ps:
  n=provider.upper()+'_'+p['name'].replace('-','_').upper();macro='TRACE_'+p['name'].replace('-','__').upper()
  fake+=f'#define {n}_ENABLED() (active)\nstatic void {n}('+', '.join(t+' a'+str(i) for i,t in enumerate(p['types']))+') { '+''.join(f'(void)a{i}; ' for i in range(len(p['types'])))+'calls++; errno=EIO; }\n'
  args=', '.join(['++evaluations']+['0']*(len(p['types'])-1))
  body+=f'active=0; calls=0; evaluations=0; errno=EAGAIN; {macro}({args}); assert(calls==0 && evaluations==0 && errno==EAGAIN);\n'
  body+=f'active=1; calls=0; evaluations=0; errno=EAGAIN; {macro}({args}); assert(calls==expected && evaluations==expected && errno==EAGAIN);\n'
 (d/(provider+'_provider.h')).write_text(fake)
 header=S/Path(ps[0]['source']).parent/(provider+'_trace.h')
 text='#include <assert.h>\n#include <errno.h>\n#include <stddef.h>\nstatic int active, calls, evaluations, original_calls, result;\n'+stub+'\n#include "'+str(header)+'"\nint main(void) {\n#ifdef WITH_COVERAGE_DTRACE\nint expected=1;\n#else\nint expected=0;\n#endif\n'+body
 text+='\n#ifdef WITH_COVERAGE_DTRACE\nchar buffer[16];size_t length=sizeof(buffer);(void)length;\n'
 for call,statuses in operations:
  for status in statuses:
   for active in (0,1):
    text+=f'result={status};active={active};calls=0;original_calls=0;errno=EAGAIN;assert({call}==result);assert(errno==EINTR && original_calls==1 && calls=={active*2});\n'
 text+='#endif\nreturn 0; }\n';c=d/'guards.c';c.write_text(text)
 for mode in ('yes','no'):
  exe=d/('guards-'+mode);cmd=['cc','-Werror','-I'+str(d)]
  if mode=='yes':cmd+=['-DWITH_COVERAGE_DTRACE']
  subprocess.run(cmd+[str(c),'-o',str(exe)],check=True,capture_output=True)
  subprocess.run([str(exe)],check=True,capture_output=True);results.append(dict(provider=provider,mode=mode,status=0))
(O/'user-guard-results.json').write_text(json.dumps(results,indent=2)+'\n');print('8 guard/errno fixtures passed')
