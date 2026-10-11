#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess,threading,http.server,socket,os,json,time
W=Path('/usr/obj/5bsd-dtrace-third-validation/userspace');D=W/'smoke';D.mkdir(exist_ok=True);S=Path(__file__).resolve().parent;results=[]
def run(label,cmd,env=None,expect=0):
 r=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
 (D/(label+'.log')).write_text(r.stdout);ok=r.returncode==expect
 print(label,'PASS' if ok else 'FAIL',flush=True);results.append(dict(name=label,status=r.returncode,expected=expect,passed=ok,command=list(map(str,cmd))));return ok
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  if self.path=='/ok':self.send_response(200);self.send_header('Content-Length','4');self.end_headers();self.wfile.write(b'data')
  else:self.send_error(404)
server=http.server.HTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
refused=socket.socket();refused.bind(('127.0.0.1',0))
for mode in os.environ.get('PROBE_MODES','hooks nohooks').split():
 for name,build,lib,deps in [('archive','lib_libarchive','archive',['-lz','-lbz2','-llzma','-lbsdxml','-lprivatezstd','-lcrypto']),('fetch','lib_libfetch','fetch',['-lssl','-lcrypto']),('threads','lib_libthr','thr',[])]:
  obj=W/(build+'-'+mode)/'obj';exe=D/(name+'-'+mode)
  if run('compile-'+name+'-'+mode,['cc','-Wall','-Wextra','-Werror',str(S/(name+'.c')),'-o',str(exe),'-L'+str(obj),'-Wl,-rpath,'+str(obj),'-l'+lib,*deps]):
   args=[str(exe)]
   if name=='fetch':args += [str(server.server_port),str(refused.getsockname()[1])]
   env=dict(os.environ)
   for k in list(env):
    if 'proxy' in k.lower():del env[k]
   if name=='threads':env['LD_LIBRARY_PATH']=str(W/('lib_libc-'+mode)/'obj')+':'+str(obj)+':/usr/obj/usr/src/amd64.amd64/tmp/lib'
   run(name+'-'+mode,args,env)
  if name=='archive':
   exe=D/('archive-static-'+mode)
   if run('compile-archive-static-'+mode,['cc',str(S/'archive.c'),str(obj/'libarchive.a'),*deps,'-o',str(exe)]):
    run('archive-static-'+mode,[str(exe)])
    r=subprocess.run(['readelf','-S',str(exe)],capture_output=True,text=True);assert ('.SUNW_dof' in r.stdout)==(mode=='hooks'),r.stdout
 # Exercise local log rotation/compression without daemon signalling.
 log=D/('rotation-'+mode);log.write_text('trace test\n')
 conf=D/('newsyslog-'+mode+'.conf');conf.write_text(str(log)+' 600 2 * * JN\n')
 exe=W/('usr.sbin_newsyslog-'+mode)/'obj/newsyslog'
 run('rotation-'+mode,[str(exe),'-r','-F','-f',str(conf)])
 assert (D/('rotation-'+mode+'.0.bz2')).exists()
server.shutdown();refused.close()
(D/'results.json').write_text(json.dumps(results,indent=2)+'\n')

raise SystemExit(int(any(not r["passed"] for r in results)))
