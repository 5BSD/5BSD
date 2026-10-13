#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual base binaries on disposable fixtures, with tracing on/off."""
import gzip,io,json,os,subprocess,tarfile,tempfile
from pathlib import Path
O=Path('/usr/obj/5bsd-dtrace-fifteenth-validation');R='/usr/obj/usr/src/amd64.amd64/tmp';env=dict(os.environ,LD_LIBRARY_PATH=R+'/lib:'+R+'/usr/lib');results=[]
def run(mode,tool,args,data=None,cwd=None):
 binary=O/'base'/('usr.bin_'+('tar' if tool=='bsdtar' else tool)+'-'+mode)/tool
 r=subprocess.run([str(binary),*args],input=data,cwd=cwd,env=env,capture_output=True,timeout=30)
 return r
payload=(b'probe fixture\x00\xff\n'*4096)
with tempfile.TemporaryDirectory(prefix='dtrace15-') as tmp:
 root=Path(tmp);packed=gzip.compress(payload,mtime=0);bad=bytearray(packed);bad[-8]^=0x40
 for mode in ('yes','no'):
  for label,blob,expected in [('valid',packed,payload),('concatenated',packed+packed,payload*2),('empty',gzip.compress(b'',mtime=0),b'')]:
   r=run(mode,'gzip',['-dc'],blob);assert r.returncode==0 and r.stdout==expected,(mode,label,r.stderr)
   results.append(dict(tool='gzip',mode=mode,test=label,status=0))
  for label,blob in [('crc-error',bytes(bad)),('truncated',packed[:-6]),('bad-header',b'not a gzip file')]:
   r=run(mode,'gzip',['-dc'],blob);assert r.returncode!=0,(mode,label)
   results.append(dict(tool='gzip',mode=mode,test=label,status=0))
  r=run(mode,'gzip',['-c'],payload);assert r.returncode==0 and gzip.decompress(r.stdout)==payload
  results.append(dict(tool='gzip',mode=mode,test='compression-unchanged',status=0))
 archive=root/'fixture.tar'
 with tarfile.open(archive,'w') as tf:
  info=tarfile.TarInfo('fixture');info.size=len(payload);tf.addfile(info,io.BytesIO(payload))
 corrupted=root/'bad.tar';blob=bytearray(archive.read_bytes());blob[0]^=0xff;corrupted.write_bytes(blob)
 for mode in ('yes','no'):
  dest=root/mode;dest.mkdir()
  r=run(mode,'bsdtar',['-tf',str(archive)]);assert r.returncode==0 and r.stdout==b'fixture\n',(mode,r.stderr)
  results.append(dict(tool='tar',mode=mode,test='list',status=0))
  r=run(mode,'bsdtar',['-xf',str(archive)],cwd=dest);assert r.returncode==0 and (dest/'fixture').read_bytes()==payload,(mode,r.stderr)
  results.append(dict(tool='tar',mode=mode,test='extract',status=0))
  for label,args in [('invalid-header',['-tf',str(corrupted)]),('missing',['-tf',str(root/'missing')])]:
   r=run(mode,'bsdtar',args);assert r.returncode!=0,(mode,label)
   results.append(dict(tool='tar',mode=mode,test=label,status=0))
  for tool,args in [('sockstat',['-46']),('sockstat',['-u']),('sockstat',['-46l']),('ipcs',['-a']),('ipcs',['-m']),('ipcs',['-q']),('ipcs',['-s'])]:
   r=run(mode,tool,args);assert r.returncode==0,(mode,tool,args,r.stderr)
   results.append(dict(tool=tool,mode=mode,test=' '.join(args),status=0))
(O/'smoke-results.json').write_text(json.dumps(results,indent=2)+'\n');print(len(results),'behavior checks passed')
