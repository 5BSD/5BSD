from pathlib import Path
import subprocess,os,time,json,re
import argparse
p=argparse.ArgumentParser(description='Run native FUSE protocol tests in a disposable QEMU VM.')
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
rows=re.findall(r'^FUSE_PROTOCOL_END (\S+) (\d+)$',s,re.M)
expected = set("access allow_other bad_server bmap cache copy_file_range create default_permissions default_permissions_privileged destroy dev_fuse_poll fallocate fifo flush forget fsync fsyncdir getattr interrupt io ioctl last_local_modify link locks lookup lseek mkdir mknod mount nfs notify open openfile opendir pre-init read readdir readlink release releasedir rename rmdir setattr statfs symlink unlink write xattr".split())
passed_cases = re.findall(r'^\[       OK \] (.+?) \(',s,re.M)
disabled = re.findall(r'^\[ DISABLED \] (.+)$',s,re.M)
passed = (p.returncode == 0 and len(rows) == len(expected) and
          {name for name,rc in rows} == expected and
          all(rc == '0' for name,rc in rows) and len(passed_cases) == 843 and
          'FUSE_PROTOCOL_DONE' in s and 'Powering system off' in s and
          'all pools are healthy' in s and
          not re.search(r'panic:|Fatal trap|lock order reversal|non-sleepable locks held|\[  FAILED  \]|\[  SKIPPED \]',s))
result=dict(passed=passed,command=cmd,rows=rows,passed_case_count=len(passed_cases),
            disabled=disabled,complete='FUSE_PROTOCOL_DONE' in s,exit_code=p.returncode)
(b/'results.json').write_text(json.dumps(result,indent=2)+'\n')
print('FUSE protocol:', 'PASS' if passed else 'FAIL', len(passed_cases), 'active cases')
raise SystemExit(0 if passed else 1)
