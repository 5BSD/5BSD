#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Build and exercise real dtraced connection code; never start the daemon."""
from pathlib import Path
import concurrent.futures,json,os,shutil,subprocess,sys,shlex
root=Path(__file__).resolve().parents[1]
if len(sys.argv)!=2:raise SystemExit('usage: run.py /usr/obj/<empty-validation-directory>')
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):raise SystemExit('Use the standard /usr/obj object root')
out.mkdir(parents=True,exist_ok=True)
if any(out.iterdir()):raise SystemExit('Validation directory must be empty')
subprocess.run([sys.executable,str(root/'tests/verify.py')],check=True)
work=out/'patched';shutil.copytree(root/'upstream',work)
for name in (root/'patches/series').read_text().splitlines():
 if name and not name.startswith('#'):
  subprocess.run(['git','apply','--check',str(root/'patches'/name)],cwd=work,check=True)
  subprocess.run(['git','apply',str(root/'patches'/name)],cwd=work,check=True)
cases=['identifier','close-reuse','send-short','send-eintr','recv-eintr','recv-eof','ack-error','peer-closed','release-underflow']
for tag,src in [('baseline',root/'upstream'),('patched',work)]:
 d=src/'usr.sbin/dtraced'
 cmd=['c++','-std=c++17','-Wall','-Wextra','-pthread','-I'+str(d),str(root/'tests/connection.cc'),str(d/'dtraced_connection.cc'),'-Wl,--wrap=send,--wrap=recv','-o',str(out/(tag+'-test'))]
 if tag=='patched':cmd+=['-DPATCHED','-Werror']
 r=subprocess.run(cmd,capture_output=True,text=True);(out/(tag+'-build.log')).write_text(shlex.join(cmd)+'\n'+r.stdout+r.stderr);assert r.returncode==0,r.stderr
jobs=[(tag,c) for tag in ['baseline','patched'] for c in cases]+[('patched','reap-gates'),('patched','one-response')]
def run(job):
 tag,case=job;r=subprocess.run([str(out/(tag+'-test')),case],capture_output=True,text=True,timeout=10)
 return dict(variant=tag,case=case,status=r.returncode,output=r.stdout+r.stderr)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:results=list(pool.map(run,jobs))
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
for r in results:print(r['variant'],r['case'],r['status'])
assert all(r['status']==0 for r in results if r['variant']=='patched')
assert all(r['status']!=0 for r in results if r['variant']=='baseline')
print('PASS: 9 upstream regressions reproduced; 11 patched component checks passed')

# Compile every daemon translation unit and link, without running the daemon.
def compile_daemon(p):
 obj=out/(p.stem+'.o')
 cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-gcc-compat','-pthread','-I'+str(work/'sys/dev/dttransport'),'-c',str(p),'-o',str(obj)]
 r=subprocess.run(cmd,capture_output=True,text=True);(out/(p.stem+'-compile.log')).write_text(shlex.join(cmd)+'\n'+r.stdout+r.stderr)
 return dict(source=p.name,status=r.returncode,object=str(obj))
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
 builds=list(pool.map(compile_daemon,(work/'usr.sbin/dtraced').glob('*.cc')))
(out/'daemon-build-results.json').write_text(json.dumps(builds,indent=2)+'\n')
assert all(r['status']==0 for r in builds),builds
cmd=['c++','-pthread',*[r['object'] for r in builds],'-lcrypto','-lutil','-o',str(out/'dtraced')]
r=subprocess.run(cmd,capture_output=True,text=True);(out/'daemon-link.log').write_text(shlex.join(cmd)+'\n'+r.stdout+r.stderr);assert r.returncode==0,r.stderr
cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(work/'usr.sbin/dtraced'),str(root/'tests/protocol.cc'),'-o',str(out/'protocol-test')]
subprocess.run(cmd,check=True);subprocess.run([str(out/'protocol-test')],check=True,timeout=10)
print('PASS daemon compile/link and sanitized malformed cleanup-frame tests')

d=work/'usr.sbin/dtraced'
cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-gcc-compat','-fsanitize=address,undefined','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-pthread','-I'+str(d),str(root/'tests/job-lifetime.cc'),str(d/'dtraced_connection.cc'),str(d/'dtraced_job.cc'),*[r['object'] for r in builds if r['source'] not in ('dtraced.cc','dtraced_connection.cc','dtraced_job.cc')],'-lcrypto','-lutil','-o',str(out/'job-lifetime-test')]
r=subprocess.run(cmd,capture_output=True,text=True);(out/'job-lifetime-build.log').write_text(shlex.join(cmd)+'\n'+r.stdout+r.stderr);assert r.returncode==0,r.stderr
subprocess.run([str(out/'job-lifetime-test')],check=True,timeout=10)
print('PASS sanitized real-job ownership and reference lifetime checks')
