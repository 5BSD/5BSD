from pathlib import Path
import json,subprocess,shlex,os,concurrent.futures
S=Path('/usr/src');O=Path('/usr/obj/5bsd-dtrace-seventh-validation');inv=json.loads((S/'tools/test/system-tracing/coverage-seventh.json').read_text());T=O/'tap';T.mkdir(exist_ok=True)
groups=[('lib/libmesh','lib_libmesh-no','MESH_WITH_PROBE_TAP'),('usr.sbin/bluetooth/BSDBluetooth','usr.sbin_bluetooth_BSDBluetooth-no','WITH_PROBE_TAP'),('usr.sbin/bluetooth/meshd','usr.sbin_bluetooth_meshd-no','MESHD_WITH_PROBE_TAP')];jobs=[]
for prefix,directory,flag in groups:
 cwd=O/'base'/directory
 cmd=['make','-C',str(S/prefix),'-m',str(S/'share/mk'),'SRCTOP='+str(S),'MAKEOBJDIR='+str(cwd),'MK_DTRACE=no','-V','${CFLAGS}']
 flags=shlex.split(subprocess.check_output(cmd,text=True))
 for source in inv['sources']:
  if source.startswith(prefix+'/') and source.endswith('.c'):
   command=['cc',*flags,'-D'+flag,'-I'+str(S/'usr.sbin/bluetooth/BSDBluetooth'),'-Werror','-c',str(S/source),'-o',str(T/(Path(source).stem+'.o'))]
   jobs.append((source,command,cwd))
def run(job):
 source,command,cwd=job;r=subprocess.run(command,cwd=cwd,capture_output=True,text=True)
 (T/(Path(source).stem+'.log')).write_text(r.stdout+r.stderr)
 if r.returncode:print(source,r.stderr[-1200:],flush=True)
 return dict(source=source,command=command,status=r.returncode)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:results=list(pool.map(run,jobs))
(O/'tap-results.json').write_text(json.dumps(results,indent=2)+'\n');print(len(results),'tap backend objects;',sum(r['status']!=0 for r in results),'failures')
raise SystemExit(int(any(r['status'] for r in results)))
