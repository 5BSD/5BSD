"""Prepare disposable account and console fixtures in a clean NO_ROOT staging root."""
from pathlib import Path
import subprocess, argparse, hashlib, json
parser=argparse.ArgumentParser(description=__doc__)
for name in ['build','root','objtop','source']:
 parser.add_argument('--'+name,type=Path,required=True)
args=parser.parse_args()
if not __debug__:parser.error('do not disable evidence assertions with Python -O')
work=args.build.resolve(strict=True); r=args.root.resolve(strict=True)
obj=args.objtop.resolve(strict=True); src=args.source.resolve(strict=True)
plan=Path(__file__).resolve().parent
assert r != Path('/') and (r/'METALOG').is_file()
assert r == work/'root', 'only the disposable build staging root may be modified'
assert (work/'stage-phase').read_text().strip()=='CLEAN_KERNEL_VM_PASS'
assert not (work/'fixture-phase').exists(), 'fixtures already prepared'
assert subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()==(work/'source-head').read_text().strip()
assert subprocess.check_output(['git','-C',str(src),'status','--porcelain'])==b''
lines=(r/'METALOG').read_text().splitlines()
def put(name,data,mode=0o644,uid=0,gid=0):
 p=r/name;p.parent.mkdir(parents=True,exist_ok=True)
 if p.exists() or p.is_symlink():p.unlink()
 p.write_bytes(data);p.chmod(mode)
 lines.append(f'./{name} type=file uid={uid} gid={gid} mode={mode:04o}')
put('etc/rc.conf',b'hostname="auth-policy-vm"\nzfs_enable="YES"\nsshd_enable="NO"\nsendmail_enable="NONE"\ndevmatch_enable="NO"\n')
put('etc/ttys',b'ttyu0 "/usr/libexec/getty policy" vt100 on secure\n')
put('etc/gettytab',(r/'etc/gettytab').read_bytes()+b'\npolicy|Policy VM console:\\\n\t:al=root:tc=3wire:\n')
put('etc/fstab',b'/dev/vtbd0p2 / ufs rw 1 1\ntmpfs /Capabilities/Run tmpfs rw,mode=0700 0 0\n')
put('boot/loader.conf',b'console="comconsole"\nautoboot_delay="1"\nzfs_load="YES"\ninit_path="/sbin/capsule"\ndtraceall_load="YES"\n')
put('boot/loader.conf.local',b'vfs.root.mountfrom="ufs:/dev/vtbd0p2"\n')
hashvalue=subprocess.check_output(['openssl','passwd','-6','-stdin'],input=b'policy-vm-only\n').decode().strip()
passwd=(r/'etc/master.passwd').read_text().splitlines()
assert not any(x.startswith('policyuser:') for x in passwd)
for i,line in enumerate(passwd):
 if line.startswith('root:'):
  fields=line.split(':');fields[1]=hashvalue;passwd[i]=':'.join(fields)
passwd.append(f'policyuser:{hashvalue}:2001:2001::0:0:Policy test user:/home/policyuser:/bin/sh')
put('etc/master.passwd',('\n'.join(passwd)+'\n').encode(),0o600)
put('etc/group',(r/'etc/group').read_bytes()+b'policyuser:*:2001:\n')
subprocess.run(['pwd_mkdb','-p','-d',str(r/'etc'),str(r/'etc/master.passwd')],check=True)
for n in ['pwd.db','spwd.db','passwd']:
 lines.append('./etc/'+n+' type=file uid=0 gid=0 mode='+('0600' if n=='spwd.db' else '0644'))
(r/'home/policyuser').mkdir(parents=True)
lines.append('./home/policyuser type=dir uid=2001 gid=2001 mode=0755')
put('home/policyuser/.profile',b'',0o644,2001,2001)
put('root/.profile',b'case "$-" in *i*) ;; *) return ;; esac\nif ! sh /root/seed-zfs-guest.sh; then echo SEED_FAILED; fi\nexec sleep 3600\n')
# root's login shell is zsh (etc/master.passwd), which reads .zprofile instead.
put('root/.zprofile',b"emulate sh -c '. /root/.profile'\n")
put('root/seed-zfs-guest.sh',(plan/'seed-zfs-guest.sh').read_bytes(),0o555)
# This terminal driver is fixture code, compiled anew against the clean sysroot.
helper=work/'pty-askpass-fixture'
subprocess.run(['cc','--sysroot='+str(obj/'tmp'),str(plan/'pty-askpass-fixture.c'),'-lutil','-o',str(helper)],check=True)
put('usr/bin/policy-askpass',helper.read_bytes(),0o555)
trace_helper=work/'trace-consumer-fixture'
subprocess.run(['cc','--sysroot='+str(obj/'tmp'),'-I'+str(src/'lib/libtracecmp'),'-I'+str(src/'sys'),'-I'+str(src/'sys/cddl/compat/opensolaris'),'-I'+str(src/'sys/cddl/contrib/opensolaris/uts/common'),'-I'+str(src/'cddl/contrib/opensolaris/lib/libdtrace/common'),str(plan/'trace-consumer-fixture.c'),'-L'+str(obj/'lib/libtracecmp'),'-ltracecmp','-o',str(trace_helper)],check=True)
(r/'METALOG').write_text('\n'.join(lines)+'\n')
(work/'fixture-phase').write_text('CLEAN_ROOT_FIXTURES_PASS\n')
(work/'fixture-sources.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(plan.iterdir()) if p.is_file() and p.suffix in ('.py','.sh','.c')},indent=2)+'\n')
