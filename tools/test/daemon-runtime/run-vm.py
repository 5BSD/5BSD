#!/usr/local/bin/python3.12
"""Run native libservice maturity tests in a disposable, networkless VM."""
import argparse, hashlib, json, os, re, shutil, subprocess, time
from pathlib import Path
from atf_metadata import parse_listing, cases_completed, apply_case_budgets, parse_runtime_description
from serial_timeline import SerialTimeline
from disk_copy import check_source, copy_source
from host_resources import HostMonitor
from scratch_disk import policy as scratch_policy, create as scratch_create, DiskMonitor
from workspace_disk import requirement as workspace_requirement, check_space as workspace_space, create as workspace_create
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--root',type=Path,required=True)
p.add_argument('--objtop',type=Path,required=True)
p.add_argument('--fixture-objtop',type=Path,help='private static test tree under /usr/obj; defaults to objtop')
p.add_argument('--work',type=Path,required=True)
p.add_argument('--qemu',required=True)
p.add_argument('--qemu-data',type=Path,required=True)
p.add_argument('--kernconf',default='GENERIC-NODEBUG')
p.add_argument('--client-ownership',action='store_true')
p.add_argument('--oes-factory',action='store_true')
p.add_argument('--oes-admission',action='store_true',help='run real Capsule/SwitchBoard with OES test bundles')
p.add_argument('--zfs',action='store_true',help='stage matching ZFS module and world tools for actual dataset tests; not BIP qualification')
p.add_argument('--scratch-disk-mib',type=int,default=0,help='new private virtio scratch disk, exposed to tests as /dev/vtbd1')
p.add_argument('--scratch-host-max-allocated-mib',type=int,default=0,help='explicit sampled host allocation cap for independent private scratch disk')
p.add_argument('--scratch-host-reserve-mib',type=int,default=1024,help='minimum sampled host free-space reserve with a scratch disk')
p.add_argument('--host-max-rss-mib',type=int,default=0,help='QEMU process RSS budget; required with a workspace disk, 0 observes without a limit')
p.add_argument('--workspace-disk-mib',type=int,default=0,help='new private build workspace disk at /dev/vtbd3; requires input and output disks')
p.add_argument('--workspace-host-reserve-mib',type=int,default=1024,help='host free-space reserve beyond planned private disks')
p.add_argument('--output-disk-mib',type=int,default=0,help='new private writable output disk beside a read-only input, exposed as /dev/vtbd2')
p.add_argument('--input-disk',type=Path,help='explicit regular disk image attached read-only for independent artifact verification')
p.add_argument('--input-disk-sha256',help='required expected SHA256 for --input-disk; content binding, not authentication')
p.add_argument('--output-disk-source',type=Path,help='offline source copied into private output.img; never attached writable')
p.add_argument('--output-disk-source-sha256',help='required source SHA256 for an initialized output disk')
p.add_argument('--retain-disk-writes',action='store_true',help='retain writes to the newly created private guest.img for offline inspection; not system acceptance')
p.add_argument('--root-mib',type=int,default=256,help='fixture root filesystem size in MiB')
p.add_argument('--resource-profile',choices=['fixture','bazel-builder'],default='fixture',help='fixture: up to 2 GiB/4 vCPUs; bazel-builder: up to 24 GiB/8 vCPUs')
p.add_argument('--memory-mib',type=int,default=1024,help='guest RAM in MiB within the selected resource profile')
p.add_argument('--log-store',action='store_true')
p.add_argument('--log-storage',action='store_true')
p.add_argument('--cleanup-lifecycle',action='store_true',help='stage private cleanup/unload kernel fixture')
p.add_argument('--log-provider',action='store_true')
p.add_argument('--extra-root',type=Path,help='explicit additive fixture tree; no staged-file replacements')
p.add_argument('--atf-suite',action='append',default=[],help='static ATF binary relative to objtop; repeatable')
p.add_argument('--atf-case',action='append',default=[],help='static ATF binary relative to objtop followed by :case; repeatable')
p.add_argument('--atf-case-budget',action='append',default=[],help='explicit selected source:case=seconds harness deadline; declared ATF timeout remains recorded')
p.add_argument('--timeout',type=int,default=240)
p.add_argument('--cpus',type=int,default=4,help='guest vCPUs within selected resource profile (default 4)')
p.add_argument('--tcg-thread',choices=['multi','single'],default='multi',help='diagnostic TCG threading mode')
p.add_argument('--eventtimer',choices=['LAPIC','i8254','HPET'],help='guest event timer override for diagnosis')
a=p.parse_args()
if not 64 <= a.root_mib <= 16384: p.error('root-mib must be between 64 and 16384')
if a.oes_admission: a.oes_factory=True
if a.timeout<=0: p.error('timeout must be positive')
if a.output_disk_mib and (a.input_disk is None or not 16 <= a.output_disk_mib <= 16384): p.error('output disk requires a read-only input and capacity 16..16384 MiB')
if (a.input_disk is None) != (a.input_disk_sha256 is None): p.error('input disk requires both path and expected SHA256')
if a.input_disk is not None and (a.scratch_disk_mib or re.fullmatch(r'[0-9a-f]{64}', a.input_disk_sha256) is None): p.error('input disk requires a lowercase SHA256 and cannot share the scratch disk slot')
if (a.output_disk_source is None) != (a.output_disk_source_sha256 is None): p.error('output source requires both path and SHA256')
if a.output_disk_source is not None and not a.output_disk_mib: p.error('output source requires explicit output capacity and read-only input')
max_memory_mib,max_cpus=(24576,8) if a.resource_profile=='bazel-builder' else (2048,4)
if not 512 <= a.memory_mib <= max_memory_mib: p.error(f'guest RAM must be between 512 and {max_memory_mib} MiB')
if not 1 <= a.cpus <= max_cpus: p.error(f'guest CPUs must be between 1 and {max_cpus}')
if not 0 <= a.host_max_rss_mib <= 65536: p.error('host RSS budget must be 0..65536 MiB')
if a.workspace_disk_mib and not a.host_max_rss_mib: p.error('workspace builds require an explicit --host-max-rss-mib budget')
root=a.root.resolve(); obj=a.objtop.resolve(); work=a.work.resolve()
try:
 scratch_budget=scratch_policy(a.scratch_disk_mib,a.scratch_host_max_allocated_mib,a.scratch_host_reserve_mib,work,require_budget=not a.zfs)
 workspace_required=workspace_requirement(a.workspace_disk_mib,a.input_disk is not None,a.output_disk_mib,a.root_mib,a.workspace_host_reserve_mib)
 workspace_budget=workspace_space(work,workspace_required)
except (OSError,ValueError) as error: p.error(str(error))
fixtures=(a.fixture_objtop or obj).resolve()
if not fixtures.is_relative_to('/usr/obj/usr/src'): p.error('fixtures must use standard /usr/obj/usr/src staging')
if not work.is_relative_to('/usr/obj'): p.error('VM staging must be under /usr/obj')
kernel=obj/'sys'/a.kernconf/'kernel'
helper=fixtures/'tools/test/daemon-runtime/runtime_init'
test=fixtures/'lib/libservice/tests/libservice_api_test'
fs_test=fixtures/'usr.sbin/BSDFilesystem/tests/namespace_test'
def digest(path): return hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
input_disk=None
if a.input_disk is not None:
 if a.input_disk.is_symlink() or not a.input_disk.is_file(): p.error('input disk must be a regular nonsymlink file')
 input_disk=a.input_disk.resolve(strict=True)
 if digest(input_disk)!=a.input_disk_sha256: p.error('input disk SHA256 differs')
output_source=None
if a.output_disk_source is not None:
 try: output_source=check_source(a.output_disk_source,a.output_disk_source_sha256,a.output_disk_mib*1024*1024)
 except (OSError,ValueError) as error: p.error(str(error))
for f in [kernel,root/'boot/kernel/kernel',root/'boot/pmbr',root/'boot/gptboot',root/'boot/defaults/loader.conf',helper,test,fs_test]:
 if not f.is_file(): p.error('missing '+str(f))
if digest(kernel)!=digest(root/'boot/kernel/kernel'): p.error('staged and object kernels differ')
if subprocess.check_output(['config','-x',str(kernel)])!=subprocess.check_output(['config','-x',str(root/'boot/kernel/kernel')]): p.error('kernel configurations differ')
for f in [helper,test,fs_test]:
 if 'statically linked' not in subprocess.check_output(['file',str(f)],text=True): p.error('fixture must be static: '+str(f))
try:
 helper_before=digest(helper)
 description=subprocess.run([str(helper),'--describe'],capture_output=True,text=True,timeout=10,check=True)
 helper_description=parse_runtime_description(description.stdout)
 if digest(helper)!=helper_before: p.error('runtime helper changed during preflight')
except (subprocess.SubprocessError, ValueError) as error:
 p.error('runtime helper contract unavailable; rebuild selected fixture: '+str(error))
subprocess.run([a.qemu,'--version'],check=True,stdout=subprocess.DEVNULL)
hashes={str(f):digest(f) for f in [kernel,helper,test,fs_test]}
if hashes[str(helper)]!=helper_before: p.error('runtime helper changed after preflight')
work.mkdir(mode=0o700,parents=True,exist_ok=False); stage=work/'root'; stage.mkdir()
shutil.copytree(root/'boot',stage/'boot',ignore=shutil.ignore_patterns('kernel','modules','dtb','firmware','loader.conf','loader.conf.local','loader.conf.d','zfs'))
shutil.copy2(root/'boot/defaults/loader.conf',stage/'boot/defaults/loader.conf')
for d in ['boot/kernel','dev','sbin','etc','root','tests','tmp']: (stage/d).mkdir(parents=True,exist_ok=True)
shutil.copyfile(kernel,stage/'boot/kernel/kernel'); shutil.copyfile(helper,stage/'sbin/runtime-init'); shutil.copyfile(test,stage/'tests/libservice_api_test')
for source,dest in [(kernel,stage/'boot/kernel/kernel'),(helper,stage/'sbin/runtime-init'),(test,stage/'tests/libservice_api_test')]:
 if digest(dest)!=hashes[str(source)] or digest(source)!=hashes[str(source)]: p.error('input changed during staging: '+str(source))
shutil.copyfile(fs_test,stage/'tests/namespace_test')
if digest(stage/'tests/namespace_test')!=hashes[str(fs_test)] or digest(fs_test)!=hashes[str(fs_test)]: p.error('filesystem test changed during staging')
extra_cases=[]; extra_hashes={}; zfs_shared={}
if a.zfs:
 from zfs_fixture import stage_zfs
 zfs_hashes=stage_zfs(root, kernel.parent, stage)
 extra_hashes.update(zfs_hashes)
 zfs_shared={str(Path(name).relative_to(root)): value for name,value in zfs_hashes.items() if Path(name).is_relative_to(root)}
if a.cleanup_lifecycle:
 source=obj/'tools/test/daemon-runtime/cleanup-fixture/mac_capability_test_cleanup.ko'
 before=digest(source); dest=stage/'boot/kernel/mac_capability_test_cleanup.ko'
 shutil.copyfile(source,dest)
 if digest(source)!=before or digest(dest)!=before: p.error('cleanup fixture changed during staging')
 extra_hashes['cleanup_fixture_module']=before
if a.client_ownership:
 for library,program in [('auditcmp','client_lifecycle_test'),('cryptocmp','client_protocol_test'),('tracecmp','client_lifecycle_test'),('logcmp','client_lifecycle_test')]:
  source=fixtures/'lib'/('lib'+library)/'tests'/program
  if 'statically linked' not in subprocess.check_output(['file',str(source)],text=True): p.error('ownership fixture must be static: '+str(source))
  alias=library+'_'+program; before=digest(source)
  shutil.copyfile(source,stage/'tests'/alias)
  if digest(stage/'tests'/alias)!=before or digest(source)!=before: p.error('ownership input changed')
  extra_hashes[alias]=before
  listing=subprocess.check_output([str(source),'-l'],text=True)
  cases=[line.split(': ',1)[1] for line in listing.splitlines() if line.startswith('ident: ')]
  if not cases: p.error('no ownership cases: '+str(source))
  extra_cases.extend(('/tests/'+alias,case) for case in cases)
 (stage/'tests/extra-cases').write_text(''.join(program+' '+case+'\n' for program,case in extra_cases))
if a.oes_factory:
 source=fixtures/'usr.sbin/BSDFilesystem/tests/oes_factory_test'
 module=obj/'sys'/a.kernconf/'modules/usr/src/sys/modules/oes/oes.ko'
 if 'statically linked' not in subprocess.check_output(['file',str(source)],text=True): p.error('OES test must be static')
 for src,dst,key in [(source,stage/'tests/oes_factory_test','oes_factory_test'),(module,stage/'boot/kernel/oes.ko','oes_module')]:
  before=digest(src); shutil.copyfile(src,dst)
  if digest(src)!=before or digest(dst)!=before: p.error('OES input changed during staging')
  extra_hashes[key]=before
 extra_cases.extend(('/tests/namespace_test',case) for case in ['oes_endpoint_isolation','oes_device_alias'])
 extra_cases.extend([('/tests/oes_factory_test','invalid_root'),('/tests/oes_factory_test','notify_only_in_capmode')])
 handoff=fixtures/'usr.sbin/BSDFilesystem/tests/oes_handoff_test'
 if 'statically linked' not in subprocess.check_output(['file',str(handoff)],text=True): p.error('handoff test must be static')
 before=digest(handoff);shutil.copyfile(handoff,stage/'tests/oes_handoff_test')
 if digest(handoff)!=before or digest(stage/'tests/oes_handoff_test')!=before: p.error('handoff input changed')
 extra_hashes['oes_handoff_test']=before
 extra_cases.extend(('/tests/oes_handoff_test',case) for case in ['real_handoff','nonroot_handoff','malformed_request','idle_timeout'])
 (stage/'tests/extra-cases').write_text(''.join(program+' '+case+'\n' for program,case in extra_cases))
if a.log_store:
 source=fixtures/'usr.sbin/BSDLog/tests/store_test'
 if 'statically linked' not in subprocess.check_output(['file',str(source)],text=True): p.error('log store test must be static')
 before=digest(source);shutil.copyfile(source,stage/'tests/log_store_test')
 if digest(source)!=before or digest(stage/'tests/log_store_test')!=before: p.error('log store input changed')
 extra_hashes['log_store_test']=before
 listing=subprocess.check_output([str(source),'-l'],text=True)
 cases=[line.split(': ',1)[1] for line in listing.splitlines() if line.startswith('ident: ')]
 if not cases: p.error('no log store cases')
 extra_cases.extend(('/tests/log_store_test',case) for case in cases)
 (stage/'tests/extra-cases').write_text(''.join(program+' '+case+'\n' for program,case in extra_cases))
if a.log_storage:
 for name in ['storage_test','storage_barrier_test']:
  source=fixtures/'usr.sbin/BSDLog/tests'/name
  if 'statically linked' not in subprocess.check_output(['file',str(source)],text=True): p.error('storage test must be static')
  alias='log_'+name; before=digest(source);shutil.copyfile(source,stage/'tests'/alias)
  if digest(source)!=before or digest(stage/'tests'/alias)!=before: p.error('storage input changed')
  extra_hashes[alias]=before
  listing=subprocess.check_output([str(source),'-l'],text=True)
  cases=[line.split(': ',1)[1] for line in listing.splitlines() if line.startswith('ident: ')]
  if not cases: p.error('no storage cases')
  extra_cases.extend(('/tests/'+alias,case) for case in cases)
 (stage/'tests/extra-cases').write_text(''.join(program+' '+case+'\n' for program,case in extra_cases))
if a.log_provider:
 source=fixtures/'usr.sbin/BSDLog/tests/provider_test'
 if 'statically linked' not in subprocess.check_output(['file',str(source)],text=True): p.error('log provider test must be static')
 before=digest(source);shutil.copyfile(source,stage/'tests/log_provider_test')
 if digest(source)!=before or digest(stage/'tests/log_provider_test')!=before: p.error('log provider input changed')
 extra_hashes['log_provider_test']=before
 listing=subprocess.check_output([str(source),'-l'],text=True)
 cases=[line.split(': ',1)[1] for line in listing.splitlines() if line.startswith('ident: ')]
 if not cases: p.error('no log provider cases')
 extra_cases.extend(('/tests/log_provider_test',case) for case in cases)
 (stage/'tests/extra-cases').write_text(''.join(program+' '+case+'\n' for program,case in extra_cases))
selected_suites=[]
selections=[(relative,None) for relative in a.atf_suite]
for selection in a.atf_case:
 relative, separator, case=selection.rpartition(':')
 if not separator or not relative or not case: p.error('ATF case must be relative/path:case')
 selections.append((relative,case))
for number, (relative,selected_case) in enumerate(selections):
 path=Path(relative)
 if path.is_absolute() or '..' in path.parts: p.error('ATF suite must be relative to objtop')
 source=(fixtures/path).resolve()
 if not source.is_relative_to(fixtures) or not source.is_file(): p.error('invalid ATF suite: '+relative)
 if 'statically linked' not in subprocess.check_output(['file',str(source)],text=True): p.error('ATF suite must be static: '+relative)
 alias='atf_suite_'+str(number); before=digest(source)
 shutil.copyfile(source,stage/'tests'/alias)
 listing=subprocess.check_output([str(source),'-l'],text=True,timeout=10)
 if digest(source)!=before or digest(stage/'tests'/alias)!=before: p.error('ATF suite changed: '+relative)
 cases=[line.split(': ',1)[1] for line in listing.splitlines() if line.startswith('ident: ')]
 if not cases or len(cases)!=len(set(cases)) or any(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,126}',case) is None for case in cases): p.error('invalid ATF case listing: '+relative)
 if selected_case is not None:
  if selected_case not in cases: p.error('unknown ATF case: '+relative+':'+selected_case)
  cases=[selected_case]
 extra_hashes[alias]=before
 selected_suites.append({'source':relative,'alias':alias,'cases':cases,'sha256':before})
 extra_cases.extend(('/tests/'+alias,case) for case in cases)
if selections:
 (stage/'tests/extra-cases').write_text(''.join(program+' '+case+'\n' for program,case in extra_cases))
if input_disk is not None:
 (stage/'tests/input-device').write_text('/dev/vtbd1\n')
if a.scratch_disk_mib:
 (stage/'tests/scratch-device').write_text('/dev/vtbd1\n')
 scratch_create(work/'scratch.img',a.scratch_disk_mib*1024*1024)
if a.output_disk_mib:
 if output_source is not None:
  copy_source(output_source,a.output_disk_source_sha256,a.output_disk_mib*1024*1024,work/'output.img')
 else:
  with (work/'output.img').open('xb') as disk:
   os.fchmod(disk.fileno(),0o600)
   disk.truncate(a.output_disk_mib*1024*1024)
 (stage/'tests/output-device').write_text('/dev/vtbd2\n')
if a.workspace_disk_mib:
 workspace_space(work,workspace_required-a.output_disk_mib*1024*1024)
 workspace_create(work/'workspace.img',a.workspace_disk_mib)
 (stage/'tests/workspace-device').write_text('/dev/vtbd3\n')
# An explicit account payload supplies its own text and database files.
if not (a.extra_root and (a.extra_root/'etc/passwd').exists()):
 (stage/'etc/passwd').write_text('root:*:0:0:Charlie &:/root:/bin/sh\n')
if a.oes_admission:
 from oes_admission import stage_admission
 admission_hashes, admission_cases=stage_admission(stage,fixtures)
 extra_hashes.update(admission_hashes); extra_cases.extend(admission_cases)
 (stage/'tests/extra-cases').write_text(''.join(program+' '+case+'\n' for program,case in extra_cases))

# Honor each selected test's own cleanup and time limit. The same records are
# consumed by the guest and retained with its input provenance.
case_metadata=[]
all_cases=[('/tests/libservice_api_test',case) for case in
 ['service_budget_wire','service_session_payload_and_attachment_lifecycle','service_session_close_cancels_event']]
all_cases += [('/tests/namespace_test','delivery_hardening_failure')] + extra_cases
listings={}
for program,case in all_cases:
 if program not in listings:
  (stage/program.lstrip('/')).chmod(0o500)
  listings[program]=parse_listing(subprocess.check_output([str(stage/program.lstrip('/')),'-l'],text=True,timeout=10))
 if case not in listings[program]: p.error('case absent from metadata: '+program+':'+case)
 metadata=listings[program][case]
 case_metadata.append(dict(program=program,case=case,**metadata))
try:
 case_metadata=apply_case_budgets(case_metadata,selected_suites,a.atf_case_budget,a.timeout)
except ValueError as error:
 p.error(str(error))
if any(m['timeout'] > helper_description['maximum_case_timeout'] for m in case_metadata):
 p.error('selected case budget exceeds runtime helper contract; rebuild selected fixture')
(stage/'tests/case-metadata').write_text(''.join(
 f"{m['program']} {m['case']} {m['timeout']} {int(m['cleanup'])}\n" for m in case_metadata))

(stage/'boot/loader.conf').write_text('console="comconsole"\nautoboot_delay="1"\ncapability_plane="NO"\ninit_path="/sbin/runtime-init"\nvfs.root.mountfrom="ufs:/dev/vtbd0p2"\nvfs.root.mountfrom.options="rw"\n')
if a.oes_admission:
 with (stage/'boot/loader.conf').open('a') as f: f.write('capability_plane="YES"\n')
if a.eventtimer:
 with (stage/'boot/loader.conf').open('a') as f: f.write('kern.eventtimer.timer="'+a.eventtimer+'"\n')
if a.zfs:
 with (stage/'boot/loader.conf').open('a') as f: f.write('zfs_load="YES"\n')
if a.oes_factory:
 with (stage/'boot/loader.conf').open('a') as f: f.write('oes_load="YES"\n')
(stage/'boot.config').write_text('-h\n')
extra_root = None
if a.extra_root:
 from extra_root import stage_extra_root
 extra_root = stage_extra_root(a.extra_root, stage, shared_files=zfs_shared)
from extra_root import mtree_escape
entries=['#mtree 2.0','. type=dir uid=0 gid=0 mode=0755']
for f in sorted(stage.rglob('*')):
 name=mtree_escape('./'+str(f.relative_to(stage)))
 if f.is_symlink(): entries.append(name+' type=link uid=0 gid=0 link='+mtree_escape(os.readlink(f)))
 elif f.is_dir(): entries.append(name+' type=dir uid=0 gid=0 mode='+('1777' if f.name=='tmp' else '0755'))
 else:
  mode = (extra_root or {}).get('file_modes', {}).get(str(f.relative_to(stage)), 0o555)
  entries.append(name+' type=file uid=0 gid=0 mode='+format(mode, '04o'))
(work/'METALOG').write_text('\n'.join(entries)+'\n')
subprocess.run(['makefs','-t','ffs','-s',str(a.root_mib)+'m','-F',str(work/'METALOG'),'-o','version=2',str(work/'root.ufs'),str(stage)],check=True)
subprocess.run(['mkimg','-s','gpt','-f','raw','-b',str(stage/'boot/pmbr'),'-p','freebsd-boot:='+str(stage/'boot/gptboot'),'-p','freebsd-ufs:='+str(work/'root.ufs'),'-o',str(work/'guest.img')],check=True)
log=work/'serial.log'
disk_mode='off' if a.retain_disk_writes else 'on'
cmd=[a.qemu,'-L',str(a.qemu_data),'-accel','tcg,thread='+a.tcg_thread,'-machine','q35','-cpu','max','-m',str(a.memory_mib),'-smp',str(a.cpus),'-drive',f'file={work}/guest.img,format=raw,if=none,id=fixture_root,snapshot={disk_mode}','-device','virtio-blk-pci,drive=fixture_root,bootindex=0','-boot','strict=on','-nic','none','-display','none','-monitor','none','-serial','file:'+str(log)]
if input_disk is not None:
 if digest(input_disk)!=a.input_disk_sha256: p.error('input disk changed during staging')
 cmd.extend(['-blockdev',json.dumps({'driver':'raw','node-name':'artifact_input','read-only':True,'file':{'driver':'file','filename':str(input_disk)}}),'-device','virtio-blk-pci,drive=artifact_input'])
if a.scratch_disk_mib:
 cmd.extend(['-drive',f'file={work}/scratch.img,format=raw,if=virtio'])
if a.output_disk_mib:
 cmd.extend(['-blockdev',json.dumps({'driver':'raw','node-name':'artifact_output','file':{'driver':'file','filename':str(work/'output.img')}}),'-device','virtio-blk-pci,drive=artifact_output'])
if a.workspace_disk_mib:
 cmd.extend(['-blockdev',json.dumps({'driver':'raw','node-name':'build_workspace','file':{'driver':'file','filename':str(work/'workspace.img')}}),'-device','virtio-blk-pci,drive=build_workspace'])
provenance={'resource_profile':a.resource_profile,'output_disk_mib':a.output_disk_mib,'output_disk':str(work/'output.img') if a.output_disk_mib else None,'input_disk':str(input_disk) if input_disk else None,'input_disk_sha256':a.input_disk_sha256,'input_disk_readonly':input_disk is not None,'retain_disk_writes':a.retain_disk_writes,'extra_root':extra_root,'oes_admission':a.oes_admission,'guest_cpus':a.cpus,'guest_memory_mib':a.memory_mib,'root_mib':a.root_mib,'zfs_fixture':a.zfs,'scratch_disk_mib':a.scratch_disk_mib,'case_metadata':case_metadata,'runtime_helper_contract':helper_description,'requested_eventtimer':a.eventtimer,'tcg_thread':a.tcg_thread,'host_loadavg_start':os.getloadavg(),'host_logical_cpus':os.cpu_count(),'kernel_sha256':hashes[str(kernel)],'fixture_sha256':hashes[str(helper)],'test_sha256':hashes[str(test)],'filesystem_test_sha256':hashes[str(fs_test)],'ownership_test_hashes':extra_hashes,'objtop':str(obj),'fixture_objtop':str(fixtures),'staged_root':str(root),'command':cmd,'selected_atf_suites':selected_suites,'scope':'isolated native daemon/library fixtures; not integrated bundle or installer acceptance'}
if a.oes_admission:
 provenance['scope']='native fixtures followed by PID1 Capsule/SwitchBoard OES admission and live coalition reload/removal; OES-only provider, not installed ZFS/installer acceptance'
provenance.update(workspace_disk_mib=a.workspace_disk_mib,workspace_disk=str(work/'workspace.img') if a.workspace_disk_mib else None,workspace_host_budget=workspace_budget,workspace_host_reserve_mib=a.workspace_host_reserve_mib)
provenance.update(scratch_host_budget=scratch_budget)
provenance.update(output_disk_source=str(output_source) if output_source else None,output_disk_source_sha256=a.output_disk_source_sha256)
(work/'inputs.json').write_text(json.dumps(provenance,indent=2)+'\n')
started=time.monotonic(); timeline=SerialTimeline()
monitor=HostMonitor(work/'host-resources.jsonl',a.host_max_rss_mib)
disk_monitor=DiskMonitor(work/'scratch.img',scratch_budget,work/'scratch-resources.jsonl') if scratch_budget else None
proc=subprocess.Popen(cmd); deadline=started+a.timeout; forced=False
try:
 while proc.poll() is None and time.monotonic()<deadline:
  try:
   observed=monitor.observe(proc.pid,time.monotonic()-started)
   if disk_monitor: disk_monitor.observe(time.monotonic()-started)
   if not observed and proc.poll() is None: raise ValueError('live QEMU process missing from resource observation')
  except (OSError,ValueError,subprocess.SubprocessError) as error:
   provenance['host_resource_error']=str(error)
   break
  text=log.read_text(errors='replace') if log.exists() else ''
  timeline.observe(text, time.monotonic()-started)
  if any(x in text for x in ['panic:','Fatal trap','lock order reversal','mountroot>']): break
  if a.oes_admission and any(x in text for x in ['invalid pkgbase default service identity', 'protected authority issuer unavailable']):
   provenance['admission_startup_failure']='required service identity or PID1 authority issuer unavailable'
   break
  time.sleep(1)
finally:
 if proc.poll() is None:
  forced=True; proc.terminate()
  try: proc.wait(timeout=10)
  except subprocess.TimeoutExpired: proc.kill(); proc.wait()
provenance['host_resources']=monitor.close()
if disk_monitor: provenance['scratch_resources']=disk_monitor.close()
text=log.read_text(errors='replace') if log.exists() else ''
timeline.observe(text, time.monotonic()-started)
provenance['serial_timeline']=dict(scope='host-observed complete serial lines; polling and buffering delay included', events=timeline.events)
provenance['vm_elapsed_seconds']=round(time.monotonic()-started,3)
lines=text.splitlines()
passed=cases_completed(text,case_metadata) and 'host_resource_error' not in provenance
passed=passed and lines.count('RUNTIME_VM_PASS')==1 and 'RUNTIME_VM_FAIL' not in text and 'RUNTIME_CASE_FAIL' not in text
if a.oes_admission:
 passed=passed and lines.count('COALITION_LIFECYCLE_PASS')==1 and 'COALITION_LIFECYCLE_FAIL' not in text and lines.count('OES_ADMISSION_PASS')==1 and 'OES_ADMISSION_FAIL' not in text and lines.count('RUNTIME_FIXTURES_PASS')==1
passed=passed and not forced and proc.returncode==0 and 'Powering system off' in text and not any(x in text for x in ['panic:','Fatal trap','lock order reversal'])
if input_disk is not None:
 provenance['input_disk_final_sha256']=digest(input_disk)
 if provenance['input_disk_final_sha256']!=a.input_disk_sha256: passed=False
if output_source is not None:
 try:
  check_source(output_source,a.output_disk_source_sha256,a.output_disk_mib*1024*1024)
  provenance['output_disk_source_unchanged']=True
 except (OSError,ValueError) as error:
  provenance.update(output_disk_source_unchanged=False,output_disk_source_error=str(error)); passed=False
provenance.update(result='PASS' if passed else 'FAIL',forced_termination=forced,qemu_exit=proc.returncode,serial_sha256=digest(log) if log.exists() else None)
if a.output_disk_mib:
 provenance['output_disk_sha256']=digest(work/'output.img')
 provenance['output_disk_scope']='private VM output, including failed/partial state; not an accepted generation'
if a.workspace_disk_mib:
 provenance['workspace_disk_sha256']=digest(work/'workspace.img')
 provenance['workspace_disk_scope']='private build workspace, including partial/failed output; not an accepted generation'
if a.retain_disk_writes:
 provenance['retained_guest_disk_sha256']=digest(work/'guest.img')
 provenance['retained_guest_disk_scope']='private fixture disk, including failed/partial state; not an accepted system generation'
(work/'result.json').write_text(json.dumps(provenance,indent=2)+'\n')
print('\n'.join(text.splitlines()[-45:]));print(work)
raise SystemExit(0 if passed else 1)
