"""Build a disposable seed image from a clean staged root and explicit test fixtures."""
from pathlib import Path
import shutil, os, subprocess, time, hashlib, json, argparse
parser=argparse.ArgumentParser(description=__doc__)
for name in ['build','root','objtop','source','work','retired-packages']:
 parser.add_argument('--'+name,type=Path,required=True)
args=parser.parse_args()
if not __debug__:parser.error('do not disable evidence assertions with Python -O')
plan=Path(__file__).resolve().parent
work=args.build.resolve(strict=True); base=args.root.resolve(strict=True)
obj=args.objtop.resolve(strict=True); srcroot=args.source.resolve(strict=True)
assert (work/'fixture-phase').read_text().strip()=='CLEAN_ROOT_FIXTURES_PASS'
assert subprocess.check_output(['git','-C',str(srcroot),'rev-parse','HEAD'],text=True).strip()==(work/'source-head').read_text().strip()
assert subprocess.check_output(['git','-C',str(srcroot),'status','--porcelain'])==b''
w=args.work.resolve(); r=w/'root'; w.mkdir(exist_ok=False)
shutil.copytree(base,r,copy_function=os.link,symlinks=True)
records={}
replacements={}
installed_files={}
installed_links={}
for line in (r/'METALOG').read_text().splitlines():
 if line.startswith('./') or line.startswith('. '):records[line.split()[0]]=line

def put(name,source):
 p=r/name
 p.parent.mkdir(parents=True,exist_ok=True)
 if p.exists() or p.is_symlink():p.unlink()
 shutil.copy2(source,p)
 replacements[name]={"source":str(source),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
 records['./'+name]='./'+name+' type=file uid=0 gid=0 mode=0555'

assert subprocess.check_output(['config','-x',str(r/'boot/kernel/kernel')]) == (work/'built-kernel.conf').read_bytes()
assert not (r/'Capabilities/System/Auth.cap').exists()
assert not (r/'usr/bin/anoint').exists()
old=[p.name for p in (r/'boot/kernel').glob('*.ko') if not p.is_symlink()]
# Ordinary command paths point to the registered executable, not a copy.
def command_link(command, target):
 p=r/command
 if p.exists() or p.is_symlink():p.unlink()
 p.symlink_to('/'+target)
 records['./'+command]='./'+command+' type=link uid=0 gid=0 link=/'+target
for prog,bundle in [('switchboardctl','SwitchBoardControl'),('capsulectl','CapsuleControl')]:
 prefix='Capabilities/System/'+bundle+'.cap/'
 unit=prefix+'Units/'+prog+'.unit/'
 # Exercise installworld's actual files and symlink; never repair them here.
 for name in [prefix+'Bundle.ucl',unit+'Unit.ucl',unit+'bin/'+prog]:
  assert (base/name).is_file() and not (base/name).is_symlink(), name
  installed_files[name]=hashlib.sha256((base/name).read_bytes()).hexdigest()
 command='usr/sbin/'+prog
 assert (base/command).is_symlink(), command
 assert os.readlink(base/command)=='/'+unit+'bin/'+prog, command
 installed_links[command]=os.readlink(base/command)
for prog,command,image,attrs in [
 ('trace-allow','usr/bin/trace-allow',work/'trace-consumer-fixture',['system.trace.client']),
 ('trace-deny','usr/bin/trace-deny',work/'trace-consumer-fixture',['system.trace.client']),
 ('revocation-probe','usr/bin/revocation-probe',obj/'tests/sys/mac_capability/authority_session_helper',['system.switchboard.admin']),
 ('reload-control','usr/bin/reload-control',obj/'usr.sbin/switchboardctl/switchboardctl',['system.switchboard.admin']),
 ('application-probe','usr/bin/application-probe',obj/'tests/sys/mac_capability/authority_session_helper',['system.switchboard.admin']),
 ('dtrace','usr/sbin/dtrace',base/'usr/sbin/dtrace',['system.trace.client'])]:
 prefix='Capabilities/System/Fixture-'+prog+'.cap/'
 unit=prefix+'Units/'+prog+'.unit/'
 bundle=w/(prog+'-Bundle.ucl')
 bundle.write_text('schema="org.5bsd.capability-bundle"; bundle_id="system.Fixture-'+prog+'"; version="1.0.0"; sequence=1; author="5BSD"; publisher="org.5bsd.base"; units=["'+prog+'"];\n')
 policy=w/(prog+'-Unit.ucl')
 policy.write_text('program="'+prog+'"; activation { exec=true; } attributes='+json.dumps(attrs)+';\n')
 put(prefix+'Bundle.ucl',bundle);put(unit+'Unit.ucl',policy);put(unit+'bin/'+prog,image)
 command_link(command,unit+'bin/'+prog)
put('usr/bin/authority-session-check',obj/'tests/sys/mac_capability/authority_session_helper')
# Add these managed clients only after normal boot, through the guest reload test.
for expectation in ['allow','deny']:
 name='managed-'+expectation
 prefix='root/managed-fixtures/Fixture-'+name+'.cap/'
 unit=prefix+'Units/'+name+'.unit/'
 bundle=w/(name+'-Bundle.ucl')
 bundle.write_text('schema="org.5bsd.capability-bundle"; bundle_id="system.Fixture-'+name+'"; version="1.0.0"; sequence=1; author="5BSD"; publisher="org.5bsd.base"; units=["'+name+'"];\n')
 policy=w/(name+'-Unit.ucl')
 policy.write_text('program="'+name+'"; activation { boot=true; } ambient=true; protocol="unix"; user="root"; group="wheel"; restart="never"; attributes='+json.dumps(['system.switchboard.admin'] if expectation=='allow' else [])+'; arguments='+json.dumps(['managed-control',expectation,'/tmp/'+name+'-result'])+';\n')
 put(prefix+'Bundle.ucl',bundle);put(unit+'Unit.ucl',policy)
 put(unit+'bin/'+name,obj/'tests/sys/mac_capability/authority_session_helper')
put('root/software-managed-guest.sh',plan/'software-managed-guest.sh')
put('root/software-user-agent-guest.sh',plan/'software-user-agent-guest.sh')
put('root/software-retired-package-guest.sh',plan/'software-retired-package-guest.sh')
put('root/retired-package-fixtures/pkg-static',Path('/usr/local/sbin/pkg-static'))
retired=args.retired_packages.resolve(strict=True)
archives=sorted(retired.glob('5BSD-bsdauth*.pkg'))
assert len(archives)==4, archives
for archive in archives:
 put('root/retired-package-fixtures/'+archive.name,archive)

empty=w/'empty';empty.write_text('')
put('etc/rc.local',empty)
put('home/policyuser/.profile',empty)
records['./home/policyuser/.profile']='./home/policyuser/.profile type=file uid=2001 gid=2001 mode=0444'
for name in ['Capabilities/Config/switchboard/boot-authority.ucl',
             'Capabilities/Config/bsdfilesystem.ucl','usr/sbin/policyctl']:
 assert (base/name).is_file() and not (base/name).is_symlink(), name
 installed_files[name]=hashlib.sha256((base/name).read_bytes()).hexdigest()
trace_policy=w/'bsdtrace.allow'
trace_policy.write_text('system.Fixture-trace-allow/trace-allow\n')
put('Capabilities/System/Trace.cap/Units/bsdtrace.unit/Config/bsdtrace.allow',trace_policy)
put('root/software-trace-guest.sh',plan/'software-trace-guest.sh')
fresh_guest=w/'fresh-application-guest.sh'
fresh_guest.write_text((plan/'software-application-guest.sh').read_text().replace('kldstat -m dtrace\n','kldstat -m dtrace\nsh /root/software-trace-guest.sh\n'))
context_guest=w/'software-context-guest.sh'
context_guest.write_text('''#!/bin/sh
set -eu
[ "$(hostname)" = auth-policy-vm ]
for pair in process_context_helper:PROCESS_CONTEXT_KERNEL_PASS process_context_edge_helper:PROCESS_CONTEXT_EDGE_PASS process_context_ipc_helper:PROCESS_CONTEXT_IPC_PASS; do
 helper=${pair%:*}
 marker=${pair#*:}
 output=/tmp/$helper.output
 if ! timeout -k 5 120 /root/software-tests/$helper > "$output" 2>&1; then
  cat "$output"
  exit 1
 fi
 cat "$output"
 grep -qx "$marker" "$output"
done
echo SOFTWARE_PROCESS_CONTEXT_PASS
''')
put('root/software-context-guest.sh',context_guest)
for name in ['process_context_helper','process_context_edge_helper','process_context_ipc_helper']:
 put('root/software-tests/'+name,obj/'tests/sys/mac_capability'/name)
guest_text=fresh_guest.read_text()
assert 'sh /root/software-regressions-guest.sh' in guest_text
fresh_guest.write_text(guest_text.replace('sh /root/software-regressions-guest.sh', 'sh /root/software-context-guest.sh\nsh /root/software-regressions-guest.sh'))
put('root/software-application-guest.sh',fresh_guest)
put('root/software-unix-guest.sh',plan/'software-unix-guest.sh')
put('root/software-regressions-guest.sh',plan/'software-regressions-guest.sh')
put('root/software-reload-guest.sh',plan/'software-reload-guest.sh')
put('root/software-be-guest.sh',plan/'software-be-guest.sh')
for name in ['libservice_api_test','service_ambient_test','software_identity_test']:
 put('root/software-tests/'+name,obj/'lib/libservice/tests'/name)
for name in ['anoint_test','domain_test']:
 put('root/software-tests/'+name,obj/'usr.sbin/switchboard/tests'/name)
seed_script=w/'seed-zfs-guest.sh'
seed_script.write_text((base/'root/seed-zfs-guest.sh').read_text().replace('shutdown -p now','/usr/sbin/capsulectl poweroff'))
put('root/seed-zfs-guest.sh',seed_script)
profile=w/'integration-profile'
profile.write_text('if [ "$(tty)" = /dev/ttyu0 ]; then\n sh /root/software-application-guest.sh\nfi\n')
put('root/integration-profile',profile)
# Disposable VM credentials only; ensure password tests exercise PAM proof.
pw=(r/'etc/master.passwd').read_text().splitlines()
testhash=pw[0].split(':')[1]
for i,line in enumerate(pw):
 fields=line.split(':')
 if fields[0]=='policyuser': fields[1]=testhash; pw[i]=':'.join(fields)
mp=w/'master.passwd';mp.write_text('\n'.join(pw)+'\n');put('etc/master.passwd',mp)
records['./etc/master.passwd']='./etc/master.passwd type=file uid=0 gid=0 mode=0600'
for name in ['pwd.db','spwd.db','passwd']:
 (r/'etc'/name).unlink(missing_ok=True)
subprocess.run(['pwd_mkdb','-p','-d',str(r/'etc'),str(r/'etc/master.passwd')],check=True)
for name in ['pwd.db','spwd.db','passwd']:
 records['./etc/'+name]='./etc/'+name+' type=file uid=0 gid=0 mode='+('0600' if name=='spwd.db' else '0644')
group=w/'group';group.write_text((r/'etc/group').read_text().replace('wheel:*:0:root','wheel:*:0:root,policyuser'));put('etc/group',group)
# kldxref writes a new hints file; don't modify the hard-linked baseline.
hints=r/'boot/kernel/linker.hints'
if hints.exists():hints.unlink()
subprocess.run(['kldxref',str(r/'boot/kernel')],check=True)
records['./boot/kernel/linker.hints']='./boot/kernel/linker.hints type=file uid=0 gid=0 mode=0644'
# Fresh clean-world VM; BSDInstall acceptance remains a separate test.
# New bundle directories must be root-owned inside the image too.
for directory in r.rglob('*'):
 if directory.is_dir() and not directory.is_symlink():
  name='./'+str(directory.relative_to(r))
  records.setdefault(name,name+' type=dir uid=0 gid=0 mode=0755')
# NO_ROOT install's debug-directory entries omit ownership. makefs otherwise
# takes the staging user's real uid/gid. Supply the root-install defaults only
# for absent directory fields; retain every explicitly installed owner/group.
for name,record in list(records.items()):
 fields=record.split()
 if 'type=dir' not in fields:continue
 if not any(field.startswith(('uid=','uname=')) for field in fields):record+=' uid=0'
 if not any(field.startswith(('gid=','gname=')) for field in fields):record+=' gid=0'
 records[name]=record
for name,digest in installed_files.items():
 assert name not in replacements, name
 assert hashlib.sha256((r/name).read_bytes()).hexdigest()==digest, name
for name,target in installed_links.items():
 assert (r/name).is_symlink() and os.readlink(r/name)==target, name
(w/'preserved-installed-files.json').write_text(json.dumps({'files':installed_files,'links':installed_links},indent=2)+'\n')
meta=w/'METALOG';meta.write_text('#mtree 2.0\n'+'\n'.join(records[k] for k in sorted(records,key=lambda n:(n.count('/'),n)))+'\n')
subprocess.run(['makefs','-t','ffs','-s','6g','-F',str(meta),'-o','version=2',str(w/'seed.ufs'),str(r)],check=True)
subprocess.run(['mkimg','-s','gpt','-f','raw','-b',str(r/'boot/pmbr'),'-p','freebsd-boot:='+str(r/'boot/gptboot'),'-p','freebsd-ufs:='+str(w/'seed.ufs'),'-o',str(w/'seed.img')],check=True)
(w/'build.json').write_text(json.dumps({'stage':'fresh clean world/kernel installation plus newly built test fixtures; not BSDInstall acceptance','kernel_sha256':hashlib.sha256((r/'boot/kernel/kernel').read_bytes()).hexdigest(),'source':subprocess.check_output(['git','-C',str(srcroot),'rev-parse','HEAD'],text=True).strip(),'modules':len(old)},indent=2)+'\n')
(w/'replacement-files.json').write_text(json.dumps(replacements,indent=2)+'\n')
(w/'source.patch').write_bytes(subprocess.check_output(['git','-C',str(srcroot),'diff','--binary','HEAD']))
print(w)
