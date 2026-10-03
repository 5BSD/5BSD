#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Stage a disposable guest from local pkgbase archives, never host credentials.

Build objects live in /usr/obj inside the VM. Host output is image staging only.
The output directory must be new; existing images/evidence are never overwritten.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--source', type=Path, default=Path('/usr/src'))
parser.add_argument('--repository', type=Path,
                    default=Path('/usr/obj/usr/src/repo/FreeBSD:16:amd64/latest'))
args = parser.parse_args()
work = args.output.resolve()
work.mkdir(parents=True, exist_ok=False)
root = work / 'root'
root.mkdir()
packages = sorted(args.repository.glob('5BSD-*.pkg'))
if not packages:
    raise SystemExit('No pkgbase archives at the requested repository')
metadata = {}
with (work / 'extract.log').open('w') as log:
    for package in packages:
        if any(part in package.name for part in ('-dbg-', '-tests-', '-src-', '-doc-')):
            continue
        if package.name.startswith('pkg-'):
            continue
        manifest = json.loads(subprocess.check_output(['tar', '-xOf', str(package), '+MANIFEST']))
        for category in ['files', 'directories']:
            for name, entry in manifest.get(category, {}).items():
                if isinstance(entry, dict):
                    metadata[name.lstrip('/')] = entry
        subprocess.run(['tar', '-xpf', str(package), '-C', str(root),
                        '--no-same-owner', '--no-fflags', '--exclude', '+*'],
                       check=True, stdout=log, stderr=log)
print('Base packages extracted', flush=True)
# Copy the working sources, excluding VCS data and generated artifacts.
shutil.copytree(args.source, root / 'usr/src', dirs_exist_ok=True,
                ignore=shutil.ignore_patterns('.git', '*.o', '*.pieo', '__pycache__'))
print('Working source staged', flush=True)

def write(name, text, mode=0o644):
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)

for directory in ['dev', 'tmp', 'root', 'var/run', 'var/log', 'var/db',
                  'var/empty', 'var/tmp', 'var/audit', 'usr/obj',
                  'home/policyuser', 'home/otheruser', 'Capabilities/Run']:
    (root / directory).mkdir(parents=True, exist_ok=True)
accounts = (args.source / 'etc/master.passwd').read_text()
accounts += 'policyuser:*:2001:2001::0:0:Policy test:/home/policyuser:/bin/sh\n'
accounts += 'otheruser:*:2002:2001::0:0:Other test:/home/otheruser:/bin/sh\n'
write('etc/master.passwd', accounts, 0o600)
write('etc/group', (args.source / 'etc/group').read_text() + 'policytest:*:2001:policyuser,otheruser\n')
subprocess.run(['pwd_mkdb', '-p', '-d', str(root / 'etc'), str(root / 'etc/master.passwd')], check=True)
write('etc/rc.conf', 'hostname="auth-policy-vm"\nzfs_enable="YES"\nsshd_enable="NO"\nsendmail_enable="NONE"\ndevmatch_enable="NO"\n')
write('etc/fstab', 'tmpfs /Capabilities/Run tmpfs rw,mode=0700 0 0\n')
write('etc/sysctl.conf', 'debug.debugger_on_panic=0\n')
write('boot/loader.conf', 'console="comconsole"\nautoboot_delay="1"\nzfs_load="YES"\nvfs.root.mountfrom="ufs:/dev/vtbd0p2"\ninit_path="/sbin/capsule"\n')
# Test-only auto-login; QEMU is launched without networking.
write('etc/ttys', 'ttyu0 "/usr/libexec/getty policy" vt100 on secure\n')
with (root / 'etc/gettytab').open('a') as f:
    f.write('\npolicy|Policy VM console:\\\n\t:al=root:tc=3wire:\n')
write('root/.profile', '''
if [ ! -f /root/policy-build-passed ]; then
    sh /usr/src/tools/test/management-policy/guest-build.sh > /root/build.log 2>&1
    result=$?
    cat /root/build.log
    [ "$result" -eq 0 ] || echo POLICY_BUILD_FAIL
elif [ ! -f /root/policy-integration-passed ]; then
    if sh /usr/src/tools/test/management-policy/guest-test.sh; then
        touch /root/policy-integration-passed
        sysrc -f /boot/loader.conf switchboard_management_policy=NO
        shutdown -r now
    else
        echo POLICY_VM_FAIL
    fi
else
    if sh /usr/src/tools/test/management-policy/legacy-test.sh; then
        echo POLICY_GUEST_COMPLETE
    else
        echo POLICY_VM_FAIL
    fi
fi
''')
# Root remains the explicit compatibility principal. Test users receive no admin
# anointment and share a UNIX group; only their assigned attributes differ.
write('Capabilities/Config/principal-policy.ucl', '''principals {
    admin { uids=[0]; anointments=["*"]; admin_rights=true; }
    user { uids=[2001]; anointments=["system.trace.client"];
           may_elevate=["system.notify.system"]; admin_rights=false; }
    default { anointments=[]; }
}
''')
policy = '''version=1;
subjects=[
 {uid=2001;attributes={deployment=lab;subsystem=network;};},
 {uid=2002;attributes={deployment=other;subsystem=network;};}
];
targets=[
 {label="test.policy.network/worker";attributes={deployment=lab;subsystem=network;};},
 {label="test.policy.storage/worker";attributes={deployment=lab;subsystem=storage;};}
];
rules=[
 {id=maintenance;effect=allow;operations=[start,stop];target={class=system;};
  equal=[{subject=deployment;target=deployment;},{subject=subsystem;target=subsystem;}];},
 {id=root-revocation-fixture;effect=allow;operations=[start,stop];subject={uid="0";};
  target={label="test.policy.network/worker";};},
 {id=core-cannot-be-overridden;effect=allow;operations=[start,stop];target={class=core;};}
];
'''
write('Capabilities/Config/switchboard/management-policy.ucl', policy)
write('root/policy.allow', policy)
for user in ['policyuser', 'otheruser']:
    write('home/' + user + '/.profile', """if [ "${POLICY_TEST_LOGIN:-}" = 1 ]; then
    /bin/sh /usr/src/tools/test/management-policy/session-test.sh
    result=$?
    [ "$result" -eq 0 ] && echo PASSWORD_LOGIN_PASS
    exit "$result"
fi
""")

for name in ['network', 'storage']:
    base = f'Capabilities/System/Policy-{name}.cap'
    write(base + '/Bundle.ucl', f'''schema="org.5bsd.capability-bundle";
bundle_id="test.policy.{name}";version="1.0.0";sequence=1;
author="VM test";publisher="org.test";units=["worker"];
''', 0o444)
    write(base + '/Units/worker.unit/Unit.ucl',
          'activation {boot=true;} control="system"; restart="never";\n', 0o444)
    # A valid ELF placeholder for the first boot, replaced by the built fixture.
    target = root / base / 'Units/worker.unit/bin/worker'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / 'usr/bin/true', target)
    target.chmod(0o555)
# mkfs metadata gives the image correct ownership without host root privileges.
users = {line.split(':')[0]: int(line.split(':')[2])
         for line in accounts.splitlines() if line and not line.startswith('#')}
groups = {line.split(':')[0]: int(line.split(':')[2])
          for line in (root / 'etc/group').read_text().splitlines()
          if line and not line.startswith('#')}

def escape(s):
    return ''.join('\\%03o' % ord(c) if c.isspace() or c in '#\\' else c for c in s)
with (work / 'METALOG').open('w') as f:
    f.write('#mtree\n. type=dir uid=0 gid=0 mode=0755\n')
    for p in sorted(root.rglob('*')):
        rel = str(p.relative_to(root))
        st = p.lstat()
        mode = stat.S_IMODE(st.st_mode)
        entry = metadata.get(rel, {})
        uid = users.get(entry.get('uname', 'root'), 0)
        gid = groups.get(entry.get('gname', 'wheel'), 0)
        if 'perm' in entry:
            mode = int(entry['perm'], 8)
        if rel in ('tmp', 'var/tmp'):
            mode = 0o1777
        if rel == 'Capabilities/Run':
            mode = 0o700
        if rel.startswith('home/policyuser'):
            uid = gid = 2001
        if rel.startswith('home/otheruser'):
            uid, gid = 2002, 2001
        line = f'./{escape(rel)} uid={uid} gid={gid} mode={mode:o}'
        if p.is_symlink():
            f.write(line + ' type=link link=' + escape(os.readlink(p)) + '\n')
        elif p.is_dir():
            f.write(line + ' type=dir\n')
        elif p.is_file():
            f.write(line + ' type=file\n')
subprocess.run(['makefs', '-t', 'ffs', '-B', 'little', '-s', '16g',
                '-o', 'version=2', '-F', str(work / 'METALOG'),
                str(work / 'root.ufs'), str(root)], check=True)
subprocess.run(['mkimg', '-s', 'gpt', '-f', 'raw', '-b', str(root / 'boot/pmbr'),
                '-p', 'freebsd-boot:=' + str(root / 'boot/gptboot'),
                '-p', 'freebsd-ufs:=' + str(work / 'root.ufs'),
                '-o', str(work / 'guest.img')], check=True)
print('VM image ready:', work / 'guest.img', flush=True)
