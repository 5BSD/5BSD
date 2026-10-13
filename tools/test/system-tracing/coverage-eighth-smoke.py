#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Guard/errno fault injection, local libfetch I/O, and utility behavior checks."""
import collections,json,os,subprocess,tempfile
from pathlib import Path
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-eighth-validation');T=O/'smoke';T.mkdir(exist_ok=True)
root=Path('/usr/obj/usr/src/amd64.amd64/tmp')
inv=json.loads((S/'tools/test/system-tracing/coverage-eighth.json').read_text())
results=[]
def run(cmd,**kw):
 r=subprocess.run([str(a) for a in cmd],capture_output=True,text=True,timeout=30,**kw)
 assert r.returncode==0,(cmd,r.stdout,r.stderr)
 return r
# Compile real trace headers against a fake provider that corrupts errno.
# The fake backend tests wrapper semantics, not live DTrace firing.
providers=collections.defaultdict(list)
for p in inv['probes']:
 if p['kind']=='user':providers[p['provider'].rstrip('*')].append(p)
for provider,ps in providers.items():
 d=T/provider;d.mkdir(exist_ok=True)
 hdr='';body=''
 for p in ps:
  raw=provider.upper()+'_'+p['name'].replace('-','_').upper()
  macro='TRACE_'+provider.upper()+'_'+p['name'].replace('-','__').upper()
  signature=', '.join(t+' a'+str(i) for i,t in enumerate(p['types']))
  hdr+=f'#define {raw}_ENABLED() (active)\nstatic void {raw}({signature}) {{ '+''.join(f'(void)a{i}; ' for i in range(len(p['types'])))+'calls++; errno=EIO; }\n'
  args=', '.join(['++evaluations']+['0']*(len(p['types'])-1))
  body+=f'active=0; calls=0; evaluations=0; errno=EAGAIN; {macro}({args}); assert(calls==0 && evaluations==0 && errno==EAGAIN);\n'
  body+=f'active=1; calls=0; evaluations=0; errno=EAGAIN; {macro}({args}); assert(calls==expected && evaluations==expected && errno==EAGAIN);\n'
 (d/(provider+'_provider.h')).write_text(hdr)
 header=S/Path(ps[0]['source']).parent/(provider+'_trace.h')
 text='#include <assert.h>\n#include <errno.h>\n#include <stdint.h>\n#include <stddef.h>\nstatic int active, calls, evaluations;\n'
 if provider=='fetchio':text+='const unsigned char __bsd_dof_anchor_fetchio_provider __attribute__((visibility("hidden"))) = 0;\n'
 text+=f'#include "{header}"\nint main(void) {{\n#ifdef WITH_COVERAGE_DTRACE\nint expected=1;\n#else\nint expected=0;\n#endif\n'+body+'return 0; }\n'
 c=d/'guard.c';c.write_text(text)
 for mode in ('yes','no'):
  exe=d/('guard-'+mode);cmd=['cc','-Werror','-I'+str(d)]
  if mode=='yes':cmd+=['-DWITH_COVERAGE_DTRACE']
  run(cmd+[c,'-o',exe]);run([exe]);results.append(dict(test='guard/errno',provider=provider,mode=mode,status=0))
for mode in ('yes','no'):
 env=os.environ.copy();env['LD_LIBRARY_PATH']=str(root/'lib')+':'+str(root/'usr/lib')
 exe=T/('fetch-'+mode)
 run(['cc','--sysroot='+str(root),'-DWITH_SSL','-I'+str(S/'lib/libfetch'),S/'tools/test/system-tracing/coverage-eighth-fetch.c',O/'base'/('lib_libfetch-'+mode)/'libfetch.a','-lssl','-lcrypto','-o',exe])
 run([exe],env=env);results.append(dict(test='fetch socketpair timeout/interruption/read/write/EOF',mode=mode,status=0))
 with tempfile.TemporaryDirectory(dir=T,prefix='utility-'+mode+'-') as work, tempfile.TemporaryDirectory(dir='/tmp',prefix='dtrace8-move-') as external:
  wd=Path(work);ext=Path(external)
  def utility(name,*args,ok=True):
   component='usr.bin_truncate' if name=='truncate' else 'bin_'+name
   binary=O/'base'/(component+'-'+mode)/name
   r=subprocess.run([str(binary),*[str(a) for a in args]],env=env,cwd=wd,capture_output=True,timeout=15)
   assert (r.returncode==0)==ok,(name,args,r.stdout,r.stderr)
  (wd/'input').write_bytes(b'payload')
  for conv in ('fsync','fdatasync'):
   utility('dd','if=input','of=output','conv='+conv);assert (wd/'output').read_bytes()==b'payload'
  utility('dd','if=input','conv=fsync',ok=False)
  utility('mkdir','-p','-m','700','a/b');assert (wd/'a/b').is_dir()
  utility('mkdir','a/b',ok=False)
  utility('chmod','600','input');assert (wd/'input').stat().st_mode&0o777==0o600
  utility('chmod','600','missing',ok=False)
  utility('truncate','-s','4096','output');assert (wd/'output').stat().st_size==4096
  utility('cp','input','copy');assert (wd/'copy').read_bytes()==b'payload'
  utility('rm','copy');assert not (wd/'copy').exists()
  utility('rm','missing',ok=False)
  utility('mv','input','renamed');assert (wd/'renamed').read_bytes()==b'payload'
  # A different existing filesystem exercises mv's parent-side cp/rm waits.
  if wd.stat().st_dev != ext.stat().st_dev:
   (wd/'tree').mkdir();(wd/'tree/file').write_bytes(b'tree-data')
   utility('mv',wd/'tree',ext/'tree');assert not (wd/'tree').exists();assert (ext/'tree/file').read_bytes()==b'tree-data'
   results.append(dict(test='mv cross-filesystem directory child waits',mode=mode,status=0))
  else:results.append(dict(test='mv cross-filesystem directory child waits',mode=mode,skipped='same filesystem',status=0))
  results.append(dict(test='utility success/error/durability behavior',mode=mode,status=0))
(T/'results.json').write_text(json.dumps(results,indent=2)+'\n')
print(len(results),'smoke checks passed')
