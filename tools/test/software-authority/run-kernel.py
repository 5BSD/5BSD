#!/usr/bin/env python3
"""Boot software-authority kernel fixtures in a disposable amd64 QEMU guest."""
from pathlib import Path
import argparse, subprocess, shutil, os, time, json, hashlib, re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, required=True, help='NO_ROOT installworld/distribution/installkernel staging root')
parser.add_argument('--objtop', type=Path, required=True, help='matching amd64.amd64 object directory')
parser.add_argument('--kernconf', default='GENERIC-NODEBUG')
parser.add_argument('--workdir', type=Path, required=True, help='new disposable output directory')
parser.add_argument('--qemu', default='qemu-system-x86_64')
parser.add_argument('--qemu-data', type=Path)
parser.add_argument('--timeout', type=int, default=600)
parser.add_argument('--cpus', type=int, default=os.cpu_count() or 1)
args = parser.parse_args()
if args.timeout <= 0 or args.cpus <= 0:
    parser.error('timeout and cpus must be positive')
if not re.fullmatch(r'[A-Za-z0-9_-]+', args.kernconf):
    parser.error('invalid kernel configuration name')
clean=args.root.resolve(); obj=args.objtop.resolve(); w=args.workdir.resolve()
kernel=obj/'sys'/args.kernconf/'kernel'
helpers=obj/'tests/sys/mac_capability'
required=[kernel, clean/'boot/kernel/kernel', clean/'boot/pmbr', clean/'boot/gptboot',
          clean/'libexec/ld-elf.so.1', clean/'lib/libc.so.7', clean/'lib/libsys.so.7']
required += [helpers/name for name in ['authority_boot_helper', 'authority_loader_helper', 'authority-inject.so']]
for path in required:
    if not path.is_file():
        parser.error('missing build input: '+str(path))
# Check emulator and kernel identity before creating any output.
subprocess.run([args.qemu, '--version'], check=True, stdout=subprocess.DEVNULL)
if subprocess.check_output(['config','-x',str(kernel)]) != subprocess.check_output(['config','-x',str(clean/'boot/kernel/kernel')]):
    parser.error('staged and object kernel configuration mismatch')
w.mkdir(parents=True, exist_ok=False)
r=w/'root'; r.mkdir()
boot=clean/'boot'
shutil.copytree(boot,r/'boot',ignore=shutil.ignore_patterns('kernel','modules','dtb','firmware','loader.conf','loader.conf.local','loader.conf.d','zfs'))
shutil.copy2(boot/'defaults/loader.conf',r/'boot/defaults/loader.conf')
(r/'boot/kernel').mkdir(); (r/'dev').mkdir(); (r/'sbin').mkdir(); (r/'etc').mkdir()
shutil.copy2(kernel,r/'boot/kernel/kernel');shutil.copy2(obj/'tests/sys/mac_capability/authority_boot_helper',r/'sbin/authority-test');shutil.copy2(obj/'tests/sys/mac_capability/authority_boot_helper',r/'sbin/authority-other')
# Dynamic-loader attribution fixture, exclusively using the newly built runtime.
(r/'lib').mkdir(); (r/'libexec').mkdir()
shutil.copy2(obj/'tests/sys/mac_capability/authority_loader_helper',r/'sbin/authority-loader')
shutil.copy2(obj/'tests/sys/mac_capability/authority-inject.so',r/'lib/authority-inject.so')
shutil.copyfile(clean/'libexec/ld-elf.so.1',r/'libexec/ld-elf.so.1')
shutil.copyfile(clean/'lib/libc.so.7',r/'lib/libc.so.7')
shutil.copyfile(clean/'lib/libsys.so.7',r/'lib/libsys.so.7')
(r/'boot/loader.conf').write_text('console="comconsole"\nautoboot_delay="1"\ninit_path="/sbin/authority-test"\nvfs.root.mountfrom="ufs:/dev/vtbd0p2"\nvfs.root.mountfrom.options="rw"\n')
(r/'boot.config').write_text('-h\n')
metalog=['#mtree 2.0','. type=dir uid=0 gid=0 mode=0755']
for p in sorted(r.rglob('*')):
 name='./'+str(p.relative_to(r))
 if p.is_symlink():metalog.append(name+' type=link uid=0 gid=0 link='+os.readlink(p))
 elif p.is_dir():metalog.append(name+' type=dir uid=0 gid=0 mode=0755')
 else:metalog.append(name+' type=file uid=0 gid=0 mode=0555')
(w/'METALOG').write_text('\n'.join(metalog)+'\n')
subprocess.run(['makefs','-t','ffs','-s','256m','-F',str(w/'METALOG'),'-o','version=2',str(w/'root.ufs'),str(r)],check=True)
subprocess.run(['mkimg','-s','gpt','-f','raw','-b',str(r/'boot/pmbr'),'-p','freebsd-boot:='+str(r/'boot/gptboot'),'-p','freebsd-ufs:='+str(w/'root.ufs'),'-o',str(w/'guest.img')],check=True)
log=w/'serial.log'
cmd=[args.qemu,'-accel','tcg,thread=multi','-machine','q35','-cpu','max','-m','4096','-smp',str(args.cpus),'-drive',f'file={w}/guest.img,format=raw,if=virtio,snapshot=on','-nic','none','-display','none','-monitor','none','-serial','file:'+str(log)]
if args.qemu_data:
 cmd += ['-L',str(args.qemu_data.resolve())]
(w/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
p=subprocess.Popen(cmd)
forced_termination=False
deadline=time.monotonic()+args.timeout
try:
 while p.poll() is None and time.monotonic()<deadline:
  s=log.read_text(errors='replace') if log.exists() else ''
  if any(x in s for x in ['panic:','Fatal trap','lock order reversal','mountroot>']):break
  time.sleep(1)
finally:
 if p.poll() is None:
  forced_termination=True
  p.terminate()
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:p.kill();p.wait()
s=log.read_text(errors='replace');ok='PASS authority-system-mixed-sysctl-claims' in s and 'PASS authority-prison-transition-invalidates-authority' in s and 'AUTHORITY_KERNEL_VM_PASS' in s and 'AUTHORITY_FAIL' not in s and p.returncode==0 and not forced_termination and 'All buffers synced.' in s and 'Powering system off' in s and not any(x in s for x in ['panic:','Fatal trap','lock order reversal'])
(w/'result.json').write_text(json.dumps({'result':'PASS' if ok else 'FAIL','kernel_sha256':hashlib.sha256(kernel.read_bytes()).hexdigest(),'objtop':str(obj),'staged_root':str(clean),'kernconf':args.kernconf,'serial_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'test_sha256':hashlib.sha256((r/'sbin/authority-test').read_bytes()).hexdigest(),'qemu_exit':p.returncode,'forced_termination':forced_termination,'clean_poweroff':'Powering system off' in s,'scope':'isolated kernel fixture only; not integrated login or installer verification'},indent=2)+'\n')
print(w); print('\n'.join(s.splitlines()[-30:]));raise SystemExit(0 if ok else 1)
