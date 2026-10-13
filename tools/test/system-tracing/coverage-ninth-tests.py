#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run base utility ATF suites against this round's built binaries, no install."""
from pathlib import Path
import json,os,subprocess,tempfile
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-ninth-validation');T=O/'tests';T.mkdir(exist_ok=True)
components=['bin/ln','bin/rmdir','bin/chflags','usr.bin/lockf','usr.bin/renice']
results=[]
for mode in ('yes','no'):
 bindir=T/('bin-'+mode);bindir.mkdir(exist_ok=True)
 for c in components:
  name=c.split('/')[-1];target=O/'base'/(c.replace('/','_')+'-'+mode)/name
  names=[name]
  if name=='ln':
   alias=target.parent/'link'
   if not alias.exists():alias.symlink_to(target)
   names.append('link')
  for n in names:
   p=bindir/n
   if p.is_symlink():p.unlink()
   executable=target if n==name else alias
   p.write_text('#!/bin/sh\nLD_LIBRARY_PATH=/usr/obj/usr/src/amd64.amd64/tmp/lib:/usr/obj/usr/src/amd64.amd64/tmp/usr/lib exec '+str(executable)+' "$@"\n')
   p.chmod(0o755)
 env=os.environ.copy();env['PATH']=str(bindir)+':'+env['PATH'];env['LC_ALL']='C'
 for component in components:
  src=S/component/'tests';out=T/(component.replace('/','_')+'-'+mode);out.mkdir(exist_ok=True)
  # These are existing shell ATF suites; build their launcher scripts normally.
  cmd=['make','-C',str(src),'-m',str(S/'share/mk'),'-j'+str(os.cpu_count()),'SRCTOP='+str(S),'MAKEOBJDIR='+str(out),'all']
  with (out/'build.log').open('w') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  results.append(dict(component=component,mode=mode,stage='build',status=r.returncode))
  if r.returncode:print((out/'build.log').read_text()[-2000:]);continue
  names=subprocess.check_output(['make','-C',str(src),'-m',str(S/'share/mk'),'-V','ATF_TESTS_SH'],text=True).split()
  for name in names:
   binary=out/name
   listing=subprocess.run([str(binary),'-l'],env=env,capture_output=True,text=True)
   assert listing.returncode==0,listing.stderr
   for block in listing.stdout.split('\n\n'):
    meta=dict(line.split(': ',1) for line in block.splitlines() if ': ' in line)
    if 'ident' not in meta:continue
    case=meta['ident']
    if meta.get('require.user')=='root':
     results.append(dict(component=component,mode=mode,name=name,case=case,status=0,result='skipped: root/mount fixture outside isolated user tests'));continue
    wd=Path(tempfile.mkdtemp(prefix=name+'-'+case+'-',dir=out))
    cmd=[str(binary),'-s',str(out),'-r',str(wd/'result'),case]
    with (wd/'output').open('w') as log:r=subprocess.run(cmd,cwd=wd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=120)
    result=(wd/'result').read_text() if (wd/'result').exists() else 'no result'
    results.append(dict(component=component,mode=mode,name=name,case=case,directory=str(wd),status=r.returncode,result=result))
    print(mode,name,case,result.strip(),flush=True)
    (T/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(T/'results.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(int(any(r['status'] or ('case' in r and not r['result'].startswith(('passed','skipped:','expected_failure:'))) for r in results)))
