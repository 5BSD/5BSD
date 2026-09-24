from pathlib import Path
import subprocess,os,time,json,re
import argparse
p=argparse.ArgumentParser(description='Run Linux64 UNIX socket diagnostic tests in a disposable QEMU VM.')
p.add_argument('--image',required=True)
p.add_argument('--output',required=True)
p.add_argument('--cpus',default='4')
a=p.parse_args()
b=Path(a.output);b.mkdir(parents=True,exist_ok=True);log=b/'console.log'
env=dict(os.environ,LD_LIBRARY_PATH='/home/koryheard/qemu-root/usr/local/lib',LD_PRELOAD='/home/koryheard/vm/libfreesized.so')
cmd=['/tmp/linuxulator-gate-20260919/linuxgate-vm-executor','-L','/home/koryheard/qemu-root/usr/local/share/qemu','-accel','tcg,thread=multi','-m','1536','-smp',a.cpus,'-nic','user,model=virtio-net-pci,restrict=on','-display','none','-monitor','none','-serial','stdio','-no-reboot','-machine','q35','-cpu','max','-drive',f'file={Path(a.image).resolve()},format=raw,if=virtio,snapshot=on']
with log.open('wb') as f:
 p=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT,env=env)
 deadline=time.monotonic()+3600
 while p.poll() is None:
  s=log.read_text(errors='replace')
  if time.monotonic()>deadline or re.search(r'panic:|Fatal trap|lock order reversal|non-sleepable locks held',s):p.kill();p.wait();break
  time.sleep(2)
s=log.read_text(errors='replace').replace('\r','')
rows=re.findall(r'^UNIX_DIAG_RESULT (host|vnet|shared) ([1-3]) (0|65534) (1|2|5) (path|abstract|pair) (0)$',s,re.M)
expected = {(scope, str(n), str(uid), str(t), mode, '0') for scope, rounds in [('host',range(1,4)),('vnet',[1]),('shared',[1])] for n in rounds
    for uid in [0,65534] for t in [1,2,5] for mode in ['path','abstract','pair']}
passed = (p.returncode == 0 and len(rows) == len(expected) and set(rows) == expected
    and s.count('UNIX_DIAG_PASS') == len(expected) + 2
    and 'UNIX_DIAG_VISIBLE_PASS' in s and 'UNIX_DIAG_VISIBILITY_PASS' in s and 'UNIX_DIAG_DONE' in s
    and s.count('UNIX_DIAG_CHURN_PASS') == 18
    and 'UNIX_DIAG_EXIT 0' in s and 'Powering system off' in s
    and 'all pools are healthy' in s
    and not re.search(r'panic:|Fatal trap|lock order reversal|non-sleepable locks held|UNIX_DIAG line',s))
result=dict(passed=passed,command=cmd,rows=rows,exit_code=p.returncode)
(b/'results.json').write_text(json.dumps(result,indent=2)+'\n')
print('UNIX socket diagnostics:', 'PASS' if passed else 'FAIL')
raise SystemExit(0 if passed else 1)
