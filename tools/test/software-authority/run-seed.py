"""Run a disposable software-authority VM using explicitly selected inputs."""
from pathlib import Path
import subprocess, os, time, json, socket, hashlib, argparse
from qmp_shutdown import ShutdownEvidence
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work',type=Path,required=True)
parser.add_argument('--qemu',default='qemu-system-x86_64')
parser.add_argument('--qemu-data',type=Path)
parser.add_argument('--cpus',type=int,default=os.cpu_count() or 1)
parser.add_argument('--timeout',type=int,default=3600)
args=parser.parse_args()
if not __debug__:parser.error('do not disable evidence assertions with Python -O')
if args.cpus <= 0 or args.timeout <= 0:parser.error('cpus and timeout must be positive')
w=args.work.resolve(strict=True);r=w/'root'
subprocess.run([args.qemu,'--version'],check=True,stdout=subprocess.DEVNULL)
target=w/'real-zfs.img'
with target.open('xb') as f:f.truncate(32*1024**3)
log=w/'seed-serial.log'
cmd=[args.qemu,'-accel','tcg,thread=multi','-machine','q35','-cpu','max','-m','8192','-smp',str(args.cpus),'-drive',f'file={w}/seed.img,format=raw,if=none,id=seedroot,snapshot=on','-device','virtio-blk-pci,drive=seedroot,bootindex=1','-drive',f'file={target},format=raw,if=none,id=target','-device','virtio-blk-pci,drive=target,serial=context-zfs-target,bootindex=2','-nic','none','-display','none','-monitor','none','-chardev',f'socket,id=serial,path={w}/serial.sock,server=on,wait=off,logfile={log}','-serial','chardev:serial']
qmpdir=w/'seed-qmp';qmpdir.mkdir()
shutdown=ShutdownEvidence(qmpdir)
cmd += shutdown.arguments
if args.qemu_data:cmd += ['-L',str(args.qemu_data.resolve())]
(w/'seed-command.json').write_text(json.dumps(cmd,indent=2)+'\n')
p=subprocess.Popen(cmd)
shutdown.start(p);started=time.monotonic();deadline=started+args.timeout;ok=False;forced=False
try:
 while p.poll() is None and time.monotonic()<deadline:
  s=log.read_text(errors='replace') if log.exists() else ''
  if any(x in s for x in ['panic:','Fatal trap','lock order reversal','SEED_FAILED']):break
  if 'REAL_ZFS_SEED_PASS' in s.splitlines():ok=True
  time.sleep(1)
finally:
 if p.poll() is None:
  forced=True
  p.terminate()
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:p.kill();p.wait()
shutdown_evidence=shutdown.finish()
s=log.read_text(errors='replace') if log.exists() else ''
ok = shutdown_evidence['guest_poweroff'] and 'REAL_ZFS_SEED_PASS' in s.splitlines() and p.returncode == 0 and not forced and 'Powering system off' in s and not any(x in s for x in ['SEED_FAILED','panic:','Fatal trap','lock order reversal','could not quiesce init'])
(w/'seed-result.json').write_text(json.dumps({'shutdown_evidence':shutdown_evidence,'result':'PASS' if ok else 'FAIL','qemu_exit':p.returncode,'forced':forced,'elapsed_seconds':time.monotonic()-started,'timeout_seconds':args.timeout,'clean_poweroff':'Powering system off' in s,'serial_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'scope':'create and populate real ZFS root inside isolated QEMU'},indent=2)+'\n')
print('REAL_ZFS_SEED_PASS' if ok else 'REAL_ZFS_SEED_FAIL');raise SystemExit(0 if ok else 1)
