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
build=json.loads((w/'build.json').read_text())
fresh=build.get('stage','').startswith('fresh clean world/kernel installation')
assert fresh, 'fresh staged input required'
seed=json.loads((w/'seed-result.json').read_text())
assert seed['result']=='PASS' and seed['shutdown_evidence']['guest_poweroff']
log=w/'software-serial.log'
if log.exists(): log.rename(str(log)+'.'+str(time.time_ns()))
cmd=[args.qemu,'-accel','tcg,thread=multi','-machine','q35','-cpu','max','-m','8192','-smp',str(args.cpus),'-drive',f'file={w}/real-zfs.img,format=raw,if=virtio,snapshot=on','-nic','none','-display','none','-monitor','none','-chardev',f'socket,id=serial,path={w}/serial.sock,server=on,wait=off,logfile={log}','-serial','chardev:serial']
qmpdir=w/'integration-qmp';qmpdir.mkdir()
shutdown=ShutdownEvidence(qmpdir)
cmd += shutdown.arguments
if args.qemu_data:cmd += ['-L',str(args.qemu_data.resolve())]
(w/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
p=subprocess.Popen(cmd)
shutdown.start(p)
forced=False;diagnosed=False;started=time.monotonic();deadline=started+args.timeout
try:
 while p.poll() is None and time.monotonic()<deadline:
  s=log.read_text(errors='replace') if log.exists() else ''
  if any(x in s for x in ['panic:','Fatal trap','lock order reversal']):break
  if 'SOFTWARE_APPLICATION_FAIL' in s.splitlines() and not diagnosed:
   time.sleep(2)
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
    c.settimeout(5)
    c.connect(str(w/'serial.sock'))
    c.sendall(b'cat /var/log/capability.log; echo SOFTWARE_DIAGNOSTICS_COMPLETE; /usr/sbin/capsulectl poweroff\n')
   diagnosed=True
  time.sleep(1)
finally:
 if p.poll() is None:
  forced=True;p.terminate()
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:p.kill();p.wait()
shutdown_evidence=shutdown.finish()
s=log.read_text(errors='replace') if log.exists() else ''
markers=['SOFTWARE_APPLICATION_DISCOVERY_PASS','SOFTWARE_APPLICATION_DTRACE_PASS','SOFTWARE_APPLICATION_SERVICES_PASS','SOFTWARE_STOCK_LOGIN_PASS','SOFTWARE_SSH_password_PASS','SOFTWARE_SSH_keyboard-interactive_PASS','SOFTWARE_SSH_KEYS_WITH_AND_WITHOUT_PAM_PASS','SOFTWARE_STOCK_UNIX_PASS','SOFTWARE_CLIENT_REGRESSIONS_PASS','SOFTWARE_MANIFEST_REGRESSIONS_PASS','SOFTWARE_CORE_DENIAL_PASS','SOFTWARE_APPLICATION_PASS']
if fresh:
 markers.extend(['SOFTWARE_SU_PASSWORD_TRANSITIONS_PASS','SOFTWARE_HOSTILE_USER_AGENT_PASS'])
if (w/'root/root/software-context-guest.sh').exists():
 markers.extend(['SOFTWARE_PROCESS_CONTEXT_PASS','PROCESS_CONTEXT_KERNEL_PASS','PROCESS_CONTEXT_EDGE_PASS','PROCESS_CONTEXT_IPC_PASS'])
if not fresh and (w/'root/root/software-user-agent-guest.sh').exists():
 markers.append('SOFTWARE_HOSTILE_USER_AGENT_PASS')
if (w/'root/root/software-retired-package-guest.sh').exists():
 markers.append('SOFTWARE_RETIRED_PACKAGE_PASS')
if fresh or (w/'root/root/software-reload-guest.sh').exists():
 markers.extend(['SOFTWARE_POLICY_RELOAD_PASS','SOFTWARE_CACHED_REVOCATION_PASS'])
if fresh or (w/'root/root/software-managed-guest.sh').exists():
 markers.append('SOFTWARE_MANAGED_CONTROL_PASS')
if fresh or (w/'root/root/software-trace-guest.sh').exists():
 markers.append('SOFTWARE_TRACE_PROVIDER_PASS')
if fresh or (w/'root/root/software-be-guest.sh').exists():
 markers.extend(['SOFTWARE_BE_PREPARED','SOFTWARE_BE_CANDIDATE_PASS','SOFTWARE_BE_ROLLBACK_PASS'])
if fresh:
 markers.extend(['SOFTWARE_BE_CANDIDATE_DTRACE_PASS','SOFTWARE_BE_ROLLBACK_DTRACE_PASS'])
ok=shutdown_evidence['guest_poweroff'] and all(m in s.splitlines() for m in markers) and p.returncode==0 and not forced and 'Powering system off' in s and not any(x in s for x in ['SOFTWARE_APPLICATION_FAIL','panic:','Fatal trap','lock order reversal','system: release gates'])
scope=('fresh clean world/kernel installation' if fresh else 'development installation') + ': software discovery, stock login/su/SSH, provider and operation allow/deny, DTrace, reload/revocation and boot environments; not BSDInstall acceptance'
(w/'software-result.json').write_text(json.dumps({
 'shutdown_evidence':shutdown_evidence,
 'result':'PASS' if ok else 'FAIL','exit':p.returncode,'forced':forced,
 'scope':scope,'required_markers':markers,'timeout_seconds':args.timeout,'elapsed_seconds':time.monotonic()-started,
 'missing_markers':[m for m in markers if m not in s.splitlines()],
 'serial_log':str(log),'serial_sha256':hashlib.sha256(log.read_bytes()).hexdigest() if log.exists() else None,
 'build_manifest_sha256':hashlib.sha256((w/'build.json').read_bytes()).hexdigest(),
 'kernel_sha256':build.get('kernel_sha256'),
},indent=2)+'\n')
print('SOFTWARE_QEMU_PASS' if ok else 'SOFTWARE_QEMU_FAIL',flush=True)
raise SystemExit(0 if ok else 1)
