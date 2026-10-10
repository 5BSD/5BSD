from pathlib import Path
import subprocess,os,time,json,re
import argparse
p=argparse.ArgumentParser(description='Run Linux64 parent-path notification tests in a disposable QEMU VM.')
p.add_argument('--image',required=True)
p.add_argument('--output',required=True)
p.add_argument('--cpus',default='4')
p.add_argument('--qemu',default='/usr/local/bin/qemu-system-x86_64')
p.add_argument('--firmware-dir',default='/usr/local/share/qemu')
p.add_argument('--manifest',required=True,help='JSON guest path to SHA256 mapping')
a=p.parse_args()
b=Path(a.output);b.mkdir(parents=True,exist_ok=False);log=b/'console.log'
hashes=json.loads(Path(a.manifest).read_text())
(b/'manifest.json').write_text(json.dumps(hashes,indent=2)+'\n')
env=dict(os.environ)
cmd=[a.qemu,'-L',a.firmware_dir,'-accel','tcg,thread=multi','-m','1536','-smp',a.cpus,'-nic','none','-display','none','-monitor','none','-serial','stdio','-no-reboot','-machine','q35','-cpu','max','-drive',f'file={Path(a.image).resolve()},format=raw,if=virtio,snapshot=on']
with log.open('wb') as f:
 p=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT,env=env)
 deadline=time.monotonic()+3600
 while p.poll() is None:
  s=log.read_text(errors='replace')
  if time.monotonic()>deadline or re.search(r'panic:|Fatal trap|lock order reversal|non-sleepable locks held',s):p.kill();p.wait();break
  time.sleep(2)
s=log.read_text(errors='replace').replace('\r','')
rows=re.findall(r'^PARENT_RESULT (zfs|tmpfs|nullfs) (root|unprivileged) (\w+) (\d+)$',s,re.M)
expected={(fs, user, case, '0') for fs in ['zfs','tmpfs','nullfs'] for user in ['root','unprivileged'] for case in
    ['hardlinks','rename','crossrename','unlink','exclude','recreate','overwrite','dup','procfd','procfddeleted','failedopen','createlate','fork','mapclose','unlinklast','excludelast','procfdlast','renamechurn','unlinkrace','excluderace','dual']}
hashes_ok=bool(hashes) and all(s.splitlines().count(
    f'SHA256 (/{path.lstrip("/")}) = {digest}') == 1
    for path,digest in hashes.items())
passed=(p.returncode == 0 and len(rows) == len(expected) and set(rows) == expected
    and hashes_ok and s.splitlines().count('PARENT_BEGIN') == 1
    and re.search(r'^linuxgate\s+/\s+zfs\s',s,re.M) is not None
    and re.search(r'^tmpfs\s+/tmp\s+tmpfs\s',s,re.M) is not None
    and re.search(r'^/parent-lower\s+/tmp\s+nullfs\s',s,re.M) is not None
    and s.count('PARENT_PASS ') == len(expected) and 'PARENT_DONE' in s
    and 'PARENT_WATCHES 0 0' in s and 'PARENT_PATHS 0 0' in s and 'PARENT_EXIT 0' in s
    and 'Powering system off' in s and 'All buffers synced.' in s
    and 'all pools are healthy' in s
    and not re.search(r'panic:|Fatal trap|lock order reversal|non-sleepable locks held',s))
result=dict(passed=passed,command=cmd,rows=rows,exit_code=p.returncode,
    hashes_ok=hashes_ok)
(b/'results.json').write_text(json.dumps(result,indent=2)+'\n')
print('Linux parent-path notifications:', 'PASS' if passed else 'FAIL')
raise SystemExit(0 if passed else 1)
