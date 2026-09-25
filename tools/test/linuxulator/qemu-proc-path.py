from pathlib import Path
import subprocess,os,time,json,re
import argparse
p=argparse.ArgumentParser(description='Run Linux64 proc descriptor paths tests in a disposable QEMU VM.')
p.add_argument('--image',required=True)
p.add_argument('--output',required=True)
p.add_argument('--cpus',default='4')
p.add_argument('--cache-off',action='store_true')
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
rows=re.findall(r'^PROC_PATH_RESULT (on|off) (zfs|tmpfs|nullfs) (root|unprivileged) (\w+) (\d+)$',s,re.M)
expected={(cache, fs, user, case, '0') for cache in (['on','off'] if a.cache_off else ['on']) for fs in ['zfs','tmpfs','nullfs'] for user in ['root','unprivileged'] for case in
    'mountroot simple hardlink opath rename unlink recreate procfd ancestor_rename crossrename rename_race ancestor_race replace_parent_race ancestor_removed deep_removed removed_then_rename opath_events opath_dot_events opath_search directory dot dotdot opath_directory'.split()}
passed=(p.returncode == 0 and len(rows) == len(expected) and set(rows) == expected
    and s.count('PROC_PATH_PASS ') == len(expected) and 'PROC_PATH_DONE' in s
    and 'PROC_PATH_COUNTS 0 0 0 0' in s and 'PROC_PATH_EXIT 0' in s and 'Powering system off' in s
    and 'all pools are healthy' in s
    and not re.search(r'panic:|Fatal trap|lock order reversal|non-sleepable locks held',s))
result=dict(passed=passed,command=cmd,rows=rows,exit_code=p.returncode)
(b/'results.json').write_text(json.dumps(result,indent=2)+'\n')
print('Linux proc descriptor paths:', 'PASS' if passed else 'FAIL')
raise SystemExit(0 if passed else 1)
