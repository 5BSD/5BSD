#!/usr/local/bin/python3.12
"""Run native libservice maturity tests in a disposable, networkless VM."""
import argparse, hashlib, json, os, shutil, subprocess, time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--root',type=Path,required=True)
p.add_argument('--objtop',type=Path,required=True)
p.add_argument('--work',type=Path,required=True)
p.add_argument('--qemu',required=True)
p.add_argument('--qemu-data',type=Path,required=True)
p.add_argument('--kernconf',default='GENERIC-NODEBUG')
p.add_argument('--timeout',type=int,default=240)
a=p.parse_args()
if a.timeout<=0: p.error('timeout must be positive')
root=a.root.resolve(); obj=a.objtop.resolve(); work=a.work.resolve()
if not work.is_relative_to('/usr/obj'): p.error('VM staging must be under /usr/obj')
kernel=obj/'sys'/a.kernconf/'kernel'
helper=obj/'tools/test/daemon-runtime/runtime_init'
test=obj/'lib/libservice/tests/libservice_api_test'
def digest(path): return hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
for f in [kernel,root/'boot/kernel/kernel',root/'boot/pmbr',root/'boot/gptboot',root/'boot/defaults/loader.conf',helper,test]:
 if not f.is_file(): p.error('missing '+str(f))
if digest(kernel)!=digest(root/'boot/kernel/kernel'): p.error('staged and object kernels differ')
if subprocess.check_output(['config','-x',str(kernel)])!=subprocess.check_output(['config','-x',str(root/'boot/kernel/kernel')]): p.error('kernel configurations differ')
for f in [helper,test]:
 if 'statically linked' not in subprocess.check_output(['file',str(f)],text=True): p.error('fixture must be static: '+str(f))
subprocess.run([a.qemu,'--version'],check=True,stdout=subprocess.DEVNULL)
hashes={str(f):digest(f) for f in [kernel,helper,test]}
work.mkdir(parents=True,exist_ok=False); stage=work/'root'; stage.mkdir()
shutil.copytree(root/'boot',stage/'boot',ignore=shutil.ignore_patterns('kernel','modules','dtb','firmware','loader.conf','loader.conf.local','loader.conf.d','zfs'))
shutil.copy2(root/'boot/defaults/loader.conf',stage/'boot/defaults/loader.conf')
for d in ['boot/kernel','dev','sbin','etc','root','tests','tmp']: (stage/d).mkdir(parents=True,exist_ok=True)
shutil.copyfile(kernel,stage/'boot/kernel/kernel'); shutil.copyfile(helper,stage/'sbin/runtime-init'); shutil.copyfile(test,stage/'tests/libservice_api_test')
for source,dest in [(kernel,stage/'boot/kernel/kernel'),(helper,stage/'sbin/runtime-init'),(test,stage/'tests/libservice_api_test')]:
 if digest(dest)!=hashes[str(source)] or digest(source)!=hashes[str(source)]: p.error('input changed during staging: '+str(source))
(stage/'etc/passwd').write_text('root:*:0:0:Charlie &:/root:/bin/sh\n')
(stage/'boot/loader.conf').write_text('console="comconsole"\nautoboot_delay="1"\ncapability_plane="NO"\ninit_path="/sbin/runtime-init"\nvfs.root.mountfrom="ufs:/dev/vtbd0p2"\nvfs.root.mountfrom.options="rw"\n')
(stage/'boot.config').write_text('-h\n')
entries=['#mtree 2.0','. type=dir uid=0 gid=0 mode=0755']
for f in sorted(stage.rglob('*')):
 name='./'+str(f.relative_to(stage))
 if f.is_symlink(): entries.append(name+' type=link uid=0 gid=0 link='+os.readlink(f))
 elif f.is_dir(): entries.append(name+' type=dir uid=0 gid=0 mode='+('1777' if f.name=='tmp' else '0755'))
 else: entries.append(name+' type=file uid=0 gid=0 mode=0555')
(work/'METALOG').write_text('\n'.join(entries)+'\n')
subprocess.run(['makefs','-t','ffs','-s','256m','-F',str(work/'METALOG'),'-o','version=2',str(work/'root.ufs'),str(stage)],check=True)
subprocess.run(['mkimg','-s','gpt','-f','raw','-b',str(stage/'boot/pmbr'),'-p','freebsd-boot:='+str(stage/'boot/gptboot'),'-p','freebsd-ufs:='+str(work/'root.ufs'),'-o',str(work/'guest.img')],check=True)
log=work/'serial.log'
cmd=[a.qemu,'-L',str(a.qemu_data),'-accel','tcg,thread=multi','-machine','q35','-cpu','max','-m','1024','-smp','2','-drive',f'file={work}/guest.img,format=raw,if=virtio,snapshot=on','-nic','none','-display','none','-monitor','none','-serial','file:'+str(log)]
provenance={'kernel_sha256':hashes[str(kernel)],'fixture_sha256':hashes[str(helper)],'test_sha256':hashes[str(test)],'objtop':str(obj),'staged_root':str(root),'command':cmd,'scope':'isolated native libservice tests, not integrated daemon/installer acceptance'}
(work/'inputs.json').write_text(json.dumps(provenance,indent=2)+'\n')
proc=subprocess.Popen(cmd); deadline=time.monotonic()+a.timeout; forced=False
try:
 while proc.poll() is None and time.monotonic()<deadline:
  text=log.read_text(errors='replace') if log.exists() else ''
  if any(x in text for x in ['panic:','Fatal trap','lock order reversal','mountroot>']): break
  time.sleep(1)
finally:
 if proc.poll() is None:
  forced=True; proc.terminate()
  try: proc.wait(timeout=10)
  except subprocess.TimeoutExpired: proc.kill(); proc.wait()
text=log.read_text(errors='replace') if log.exists() else ''
expected=['service_budget_wire','service_session_payload_and_attachment_lifecycle','service_session_close_cancels_event']
passed=all(text.count('RUNTIME_CASE_PASS '+case)==1 for case in expected)
passed=passed and 'RUNTIME_VM_PASS' in text and 'RUNTIME_VM_FAIL' not in text and 'RUNTIME_CASE_FAIL' not in text
passed=passed and not forced and proc.returncode==0 and 'Powering system off' in text and not any(x in text for x in ['panic:','Fatal trap','lock order reversal'])
provenance.update(result='PASS' if passed else 'FAIL',forced_termination=forced,qemu_exit=proc.returncode,serial_sha256=digest(log) if log.exists() else None)
(work/'result.json').write_text(json.dumps(provenance,indent=2)+'\n')
print('\n'.join(text.splitlines()[-45:]));print(work)
raise SystemExit(0 if passed else 1)
