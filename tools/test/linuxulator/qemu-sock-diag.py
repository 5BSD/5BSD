from pathlib import Path
import subprocess,os,time,json,re
import argparse
p=argparse.ArgumentParser(description='Run Linux64 SOCK_DIAG tests in a disposable QEMU VM.')
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
rows=re.findall(r'^DIAG_RESULT (host|vnet|shared) (\d+) (\d+) ([46]) (tcp|udp|tcp-connected) (0)$',s,re.M)
expected={(scope,str(r),str(uid),f,p,'0') for scope,rounds in [('host',range(1,4)),('vnet',[1])] for r in rounds for uid in [0,65534] for f in ['4','6'] for p in ['tcp','udp','tcp-connected']}
expected |= {('shared','1',str(uid),'4',proto,'0') for uid in [0,65534] for proto in ['tcp','udp','tcp-connected']}
passed=(p.returncode==0 and len(rows)==len(expected) and set(rows)==expected
    and 'DIAG_VISIBILITY_PASS' in s and 'DIAG_DONE' in s and 'DIAG_EXIT 0' in s
    and 'Powering system off' in s and 'all pools are healthy' in s
    and not re.search(r'panic:|Fatal trap|lock order reversal|non-sleepable locks held|DIAG line',s))
(b/'results.json').write_text(json.dumps(dict(passed=passed,rows=rows,command=cmd,exit_code=p.returncode),indent=2)+'\n')
print('SOCK_DIAG',passed,len(rows))
raise SystemExit(0 if passed else 1)
