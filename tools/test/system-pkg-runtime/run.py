#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Normal package-image boot, console/PAM, SSH and su in an owned disposable VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import threading
import time
import uuid

SOURCE = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(SOURCE/'tools/build/bazel'))
sys.path.insert(0,str(SOURCE/'tools/test/daemon-runtime'))
from qualification_artifacts import resolve_many,digest
from host_resources import HostMonitor
from serial_terminal import TerminalSizeResponder
from installed_audit import specification
import firstboot_runtime
from mtree_reconcile import reconcile

FAILURE_DIAGNOSTICS = re.compile(rb"panic:|Fatal trap|lock order reversal|non-sleepable locks held|[A-Za-z_][A-Za-z0-9_]*: parameter not set")

class Console:
    def __init__(self,process,log,monitor,started,deadline,overlay,disk_limit,rows,columns):
        self.process,self.monitor,self.started,self.deadline=process,monitor,started,deadline
        self.overlay,self.disk_limit,self.disk_peak=overlay,disk_limit,0
        self.terminal=TerminalSizeResponder(rows,columns);self.write_lock=threading.Lock()
        self.data=bytearray();self.cursor=0;self.error=None;self.last_sample=0
        self.lock=threading.Condition();self.log=log.open('xb')
        self.thread=threading.Thread(target=self.read,daemon=True);self.thread.start()
    def read(self):
        try:
            while chunk:=os.read(self.process.stdout.fileno(),65536):
                self.log.write(chunk);self.log.flush()
                with self.lock:
                    self.data.extend(chunk)
                    if len(self.data)>32*1024**2:raise ValueError('console exceeds explicit 32 MiB evidence budget')
                    self.lock.notify_all()
                for reply in self.terminal.feed(chunk):
                    self.write(reply)
        except Exception as error:self.error=error
    def tick(self,allow_exit=False):
        now=time.monotonic()
        if now-self.started>self.deadline:raise TimeoutError('explicit whole-VM deadline exceeded')
        if self.error:raise self.error
        with self.lock:
            if FAILURE_DIAGNOSTICS.search(bytes(self.data)):
                raise RuntimeError("guest kernel or startup-shell failure; see serial.log")
        if self.process.poll() is not None:
            if allow_exit:return
            raise RuntimeError('VM exited before the requested check completed')
        if now-self.last_sample>=1:
            self.monitor.observe(self.process.pid,now-self.started);self.last_sample=now
            self.disk_peak=max(self.disk_peak,self.overlay.stat().st_blocks*512)
            if self.disk_peak>self.disk_limit:raise ValueError("VM overlay exceeds explicit disk budget")
    def expect(self,pattern,seconds=180):
        until=time.monotonic()+seconds
        compiled=re.compile(pattern,re.M)
        while time.monotonic()<until:
            self.tick()
            with self.lock:
                match=compiled.search(bytes(self.data),self.cursor)
                if match:
                    before=bytes(self.data[self.cursor:match.start()]);self.cursor=match.end()
                    return before,match
                self.lock.wait(0.2)
        raise TimeoutError('console expectation timed out: '+repr(pattern))
    def write(self,payload):
        with self.write_lock:
            self.process.stdin.write(payload);self.process.stdin.flush()
    def send(self,text):
        self.write(text.encode()+b'\n')
    def command(self,text,seconds=180):
        token='BQL_'+uuid.uuid4().hex
        self.send('{ '+text+'; }; bql_status=$?; printf "\\n'+token+' %s\\n" "$bql_status"')
        output,match=self.expect(rb'^'+token.encode()+rb' ([0-9]+)\r*$',seconds)
        status=int(match.group(1))
        if status:raise RuntimeError('guest command failed '+str(status)+': '+text+'\n'+output.decode(errors='replace')[-3000:])
        return output.decode(errors='replace').replace('\r','')
    def drain(self):
        self.thread.join(timeout=5)
        if self.thread.is_alive():raise RuntimeError("serial reader did not drain after VM exit")
        if self.error:raise self.error
    def close(self):
        self.thread.join(timeout=5);self.log.close()

def main():
    if not __debug__:
        raise RuntimeError('qualification requires Python assertions enabled')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();plan=json.loads(args.plan.read_text())
    required={'format','qualification','target','image_output','report_output','qemu','qemu_img','bios','ssh',
              'qemu_data','cpus','memory_mib','deadline_seconds','max_rss_mib','max_overlay_mib',
              'console_user','password','ssh_user','user_uid','terminal_rows','terminal_columns'}
    if type(plan.get('format')) is int and plan['format']>=2:
        required.update(('metalog_output','audit_deadline_seconds'))
    if plan.get('format')==3:
        required.update(('firstboot_policy','firstboot_deadline_seconds'))
    if set(plan)!=required or type(plan['format']) is not int or plan['format'] not in (1,2,3):
        raise ValueError('exact format-1/2/3 VM plan fields required')
    if type(plan['user_uid']) is not int or not 0<plan['user_uid']<2**31:
        raise ValueError('explicit ordinary guest user UID required')
    for field in ('console_user','ssh_user'):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*',plan[field]):
            raise ValueError('invalid guest account name')
    if not plan['password'] or any(ord(c)<32 or ord(c)==127 for c in plan['password']):
        raise ValueError('single-line private fixture password required')
    if plan['format']>=2 and (type(plan['audit_deadline_seconds']) is not int or not 0<plan['audit_deadline_seconds']<=plan['deadline_seconds']):
        raise ValueError('positive audit deadline within the whole-VM budget required')
    if plan['format']==3 and (type(plan['firstboot_deadline_seconds']) is not int or not 0<plan['firstboot_deadline_seconds']<=plan['deadline_seconds']):
        raise ValueError('positive firstboot deadline within whole-VM budget required')
    TerminalSizeResponder(plan['terminal_rows'],plan['terminal_columns'])
    if not Path(plan['qemu_data']).is_absolute() or not Path(plan['qemu_data']).is_dir():
        raise ValueError('explicit QEMU data directory required')
    out=args.output.resolve()
    if out.exists() or not out.is_relative_to('/usr/obj/usr/src'):raise ValueError('fresh standard object-root VM output required')
    for key in ('cpus','memory_mib','deadline_seconds','max_rss_mib','max_overlay_mib'):
        assert type(plan[key]) is int and plan[key]>0
    if plan['cpus']>os.cpu_count() or not 512<=plan['memory_mib']<=24576:raise ValueError('invalid explicit VM resources')
    q=Path(plan['qualification']);target=plan['target']
    selections=[(target,plan['image_output']),(target,plan['report_output'])]
    if plan['format']>=2:selections.append((target,plan['metalog_output']))
    resolved=resolve_many(q,selections)
    image,build_report=resolved[0][0],json.loads(resolved[1][0].read_text())
    assert build_report['status']=='passed' and digest(image)==build_report['image_sha256']
    audit_spec=specification(resolved[2][0].read_bytes(),build_report) if plan['format']>=2 else None
    firstboot=firstboot_runtime.load(plan['firstboot_policy'],build_report,{plan['console_user'],plan['ssh_user']}) if plan['format']==3 else None
    tools={name:Path(plan[name]).resolve(strict=True) for name in ('qemu','qemu_img','bios','ssh')}
    bindings={str(path):digest(path) for path in tools.values()}
    sources=[Path(__file__),SOURCE/'tools/build/bazel/qualification_artifacts.py',SOURCE/'tools/test/daemon-runtime/host_resources.py',Path(__file__).with_name('serial_terminal.py'),Path(__file__).with_name('installed_audit.py')] + [Path(__file__).with_name(name) for name in ('firstboot_runtime.py','firstboot_accounts.py','mtree_reconcile.py')]
    source_bindings={str(path):digest(path) for path in sources}
    if firstboot is not None:source_bindings.update(firstboot['bindings'])
    out.mkdir(mode=0o700)
    if firstboot is not None:(out/'firstboot-policy.json').write_bytes(firstboot['policy_bytes'])
    if audit_spec is not None:(out/'installed.mtree').write_bytes(audit_spec)
    monitor=HostMonitor(out/'host-resources.jsonl',plan['max_rss_mib'])
    report=dict(format=1,status='running',scope='Normal complete package-image BIOS/ZFS boot, serial login/PAM, SSH password/PAM and su; not secure boot, upgrade or comparative performance',image=[b for p,b in resolved],tools=bindings,runner_sources=source_bindings,plan_sha256=digest(args.plan),checks=[])
    def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    (out/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    save();overlay=out/'guest.qcow2'
    subprocess.run([str(tools['qemu_img']),'create','-q','-f','qcow2','-F','raw','-b',str(image),str(overlay)],check=True)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    command=[str(tools['qemu']),'-L',plan['qemu_data'],'-bios',str(tools['bios']),'-accel','tcg,thread=multi',
        '-machine','q35','-cpu','max','-smp',str(plan['cpus']),'-m',str(plan['memory_mib']),'-display','none','-vga','none',
        '-monitor','none','-serial','stdio','-no-reboot','-boot','order=c',
        '-drive','file='+str(overlay)+',format=qcow2,if=virtio',
        '-netdev','user,id=net0,hostfwd=tcp:127.0.0.1:'+str(port)+'-:22',
        '-device','virtio-net-pci,netdev=net0,romfile=']
    report.update(qemu_command=command,ssh_port=port);save()
    started=time.monotonic();process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    console=Console(process,out/'serial.log',monitor,started,plan['deadline_seconds'],overlay,plan['max_overlay_mib']*1024**2,plan['terminal_rows'],plan['terminal_columns'])
    def check(name,operation,validate=None):
        value=operation()
        if validate is not None and not validate(value):
            raise AssertionError(name+': output does not satisfy the runtime contract: '+str(value))
        report['checks'].append(dict(name=name,status='passed',output=value));save();print('VM_CHECK_PASS='+name,flush=True);return value
    try:
        console.expect(rb'BAZEL_SYSTEM_BOOT_READY pid1=',plan['deadline_seconds'])
        console.expect(rb'login:\s*$',180);console.send(plan['console_user'])
        console.expect(rb'Password:\s*$',30);console.send(plan['password'])
        # A login profile may read terminal replies before the shell can accept
        # commands. Wait for the actual prompt; never feed a command into it.
        console.expect(rb'(?:^|[\r\n])[^\r\n]*[#$] $',60)
        check('console-login-pam',lambda:console.command('test "$(id -u)" -eq 0 && echo CONSOLE_ROOT_OK'))
        assert console.terminal.responses>0,'login profile terminal-size probe was not exercised'
        size=str(plan['terminal_rows'])+' '+str(plan['terminal_columns'])
        check('serial-terminal-size',lambda:console.command('test "$(/bin/stty size)" = "'+size+'" && /usr/bin/resizewin -z && echo TERMINAL_SIZE_OK'))
        check('normal-capsule-pid1',lambda:console.command('/usr/bin/procstat -b 1'),
              lambda output:'/sbin/capsule' in output)
        check('protected-pid1-signal-probe',lambda:console.command(
            'probe_output=$(/bin/kill -0 1 2>&1); probe_status=$?; '
            'test "$probe_status" -eq 1 && printf "%s\\n" "$probe_output" | '
            '/usr/bin/grep -E "Permission denied|Operation not permitted"'))
        assert build_report['filesystem']=='zfs'
        bootfs=build_report['bootfs'];assert re.fullmatch(r'[A-Za-z0-9_/-]+',bootfs)
        check('zfs-root',lambda:console.command('/sbin/mount -p; /sbin/zfs list; /sbin/bectl list -H'),
              lambda output:any(line.split()[:3]==[bootfs,'/','zfs'] for line in output.splitlines()))
        count=check('installed-packages',lambda:console.command('test "$(/root/pkg-static query -a %n | /usr/bin/wc -l | /usr/bin/tr -d " ")" -eq '+str(build_report['packages'])+' && echo PACKAGE_COUNT_OK'))
        def pam_enabled(output):
            values=[]
            for line in output.splitlines():
                fields=line.split()
                if fields and fields[0].lower()=='usepam':values.append(fields[1:])
            return values==[['yes']]
        check('sshd-pam-enabled',lambda:console.command('/usr/sbin/sshd -T'),pam_enabled)
        check('sshd-running',lambda:console.command('/usr/sbin/service sshd status'))
        keytext=console.command('/bin/cat /etc/ssh/ssh_host_ed25519_key.pub')
        keys=re.findall(r'^ssh-ed25519 [A-Za-z0-9+/=]+',keytext,re.M);assert len(keys)==1
        known=out/'known_hosts';known.write_text('[127.0.0.1]:'+str(port)+' '+keys[0]+'\n')
        askpass=out/'askpass';askpass.write_text('#!/bin/sh\nprintf "%s\\n" "$QUAL_SSH_PASSWORD"\n');askpass.chmod(0o700)
        def ssh(label,remote,password,expected=0,tty=False,answer=None):
            argv=[str(tools['ssh']),'-F','/dev/null','-p',str(port),'-o','UserKnownHostsFile='+str(known),
                '-o','GlobalKnownHostsFile=/dev/null','-o','StrictHostKeyChecking=yes','-o','IdentityAgent=none',
                '-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no','-o','KbdInteractiveAuthentication=no',
                '-o','NumberOfPasswordPrompts=1','-o','ConnectTimeout=20']
            if tty:argv.append('-tt')
            argv.extend([plan['ssh_user']+'@127.0.0.1',remote])
            env={'PATH':'/bin:/usr/bin','HOME':str(out),'LC_ALL':'C','DISPLAY':'qualification',
                'SSH_ASKPASS_REQUIRE':'force','SSH_ASKPASS':str(askpass),'QUAL_SSH_PASSWORD':password}
            child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,start_new_session=True)
            data=bytearray();until=time.monotonic()+120;sent=False
            try:
                while child.poll() is None:
                    console.tick()
                    if time.monotonic()>until:raise TimeoutError('SSH check deadline: '+label)
                    ready,_,_=select.select([child.stdout],[],[],0.2)
                    if ready:
                        chunk=os.read(child.stdout.fileno(),65536)
                        if chunk:data.extend(chunk)
                    if answer is not None and not sent and b'Password:' in data:
                        child.stdin.write(answer.encode()+b'\n');child.stdin.flush();sent=True
                data.extend(child.stdout.read());status=child.wait()
            finally:
                if child.poll() is None:child.kill();child.wait()
            text=data.decode(errors='replace');(out/(label+'.log')).write_text(text)
            assert status==expected,(label,status,text[-3000:])
            if answer is not None:assert sent,'su did not request real authentication'
            if expected==255:assert 'Permission denied' in text
            return text
        check('ssh-password-pam',lambda:ssh('ssh-positive','test "$(id -u)" -eq '+str(plan['user_uid'])+' && echo SSH_USER_OK',plan['password']))
        check('ssh-reject-wrong-password',lambda:ssh('ssh-negative','id -u',plan['password']+'-wrong',expected=255))
        check('su-password-pam',lambda:ssh('su-positive',"su -m root -c 'test \"$(id -u)\" -eq 0 && echo SU_ROOT_OK'",plan['password'],tty=True,answer=plan['password']))
        check('su-reject-wrong-password',lambda:ssh('su-negative','su -m root -c "id -u"',plan['password'],expected=1,tty=True,answer=plan['password']+'-wrong'))
        root_ssh=[str(tools['ssh']),'-F','/dev/null','-p',str(port),
            '-o','UserKnownHostsFile='+str(known),'-o','GlobalKnownHostsFile=/dev/null',
            '-o','StrictHostKeyChecking=yes','-o','IdentityAgent=none',
            '-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no',
            '-o','KbdInteractiveAuthentication=no','-o','NumberOfPasswordPrompts=1',
            '-o','ConnectTimeout=20',plan['console_user']+'@127.0.0.1']
        root_env={'PATH':'/bin:/usr/bin','HOME':str(out),'LC_ALL':'C','DISPLAY':'qualification',
            'SSH_ASKPASS_REQUIRE':'force','SSH_ASKPASS':str(askpass),'QUAL_SSH_PASSWORD':plan['password']}
        firstboot_proof=None
        if firstboot is not None:
            firstboot_until=time.monotonic()+plan['firstboot_deadline_seconds']
            report['firstboot_commands']=[]
            def root_invoke(label,remote,input_path=None):
                log_path=out/(label+'.output');begin=time.monotonic()
                with (Path(input_path) if input_path is not None else Path('/dev/null')).open('rb') as stream,log_path.open('xb') as log:
                    child=subprocess.Popen(root_ssh+[remote],stdin=stream,stdout=log,stderr=subprocess.STDOUT,env=root_env,start_new_session=True)
                    try:
                        while child.poll() is None:
                            console.tick()
                            if time.monotonic()>firstboot_until:raise TimeoutError('explicit firstboot proof deadline')
                            if log_path.stat().st_size>32*1024**2:raise ValueError('firstboot proof exceeds evidence budget')
                            time.sleep(0.2)
                    finally:
                        if child.poll() is None:child.kill();child.wait()
                report['firstboot_commands'].append(dict(label=label,command=remote,status=child.returncode,seconds=time.monotonic()-begin,output_sha256=digest(log_path)))
                save()
                if child.returncode:raise RuntimeError('guest firstboot proof failed: '+label+'; see '+str(log_path))
                if log_path.stat().st_size>32*1024**2:raise ValueError('firstboot proof exceeds evidence budget')
                return log_path.read_bytes()
            firstboot_proof=firstboot_runtime.exercise(firstboot,root_invoke,out,{plan['console_user'],plan['ssh_user']})
            check('firstboot-transitions',lambda:firstboot_proof)
        if audit_spec is not None:
            # Stream the complete spec over authenticated SSH into read-only
            # mtree. File redirection prevents pipe backpressure; monitor the
            # owned guest throughout. Never request mtree repair/update flags.
            audit_command=root_ssh+['LC_ALL=C /usr/sbin/mtree -e -f /dev/stdin -p /']
            env=root_env
            audit_log=out/'installed-audit.log'
            with (out/'installed.mtree').open('rb') as manifest,audit_log.open('xb') as log:
                child=subprocess.Popen(audit_command,stdin=manifest,stdout=log,stderr=subprocess.STDOUT,env=env,start_new_session=True)
                until=time.monotonic()+plan['audit_deadline_seconds']
                try:
                    while child.poll() is None:
                        console.tick()
                        if time.monotonic()>until:raise TimeoutError('installed mtree audit deadline')
                        if audit_log.stat().st_size>32*1024**2:raise ValueError('installed audit exceeds evidence budget')
                        time.sleep(0.2)
                finally:
                    if child.poll() is None:child.kill();child.wait()
            if audit_log.stat().st_size>32*1024**2:raise ValueError('installed audit exceeds evidence budget')
            reconciliation=[]
            reconciliation_error=None
            audit_passed=child.returncode==0 and audit_log.stat().st_size==0
            if firstboot_proof is not None and child.returncode in (0,2):
                try:
                    reconciliation=reconcile(audit_log.read_bytes(),audit_spec,
                        firstboot_proof['payload_sha256'],firstboot_proof['consumed_files'],firstboot_proof['zfs_archive_tracking'])
                    audit_passed=True
                except ValueError as error:
                    reconciliation_error=str(error);audit_passed=False
            report['installed_audit']=dict(status='passed' if audit_passed else 'failed',
                exit_status=child.returncode,reconciliation=reconciliation,reconciliation_error=reconciliation_error,firstboot_proof_sha256=digest(out/'firstboot-proof.json') if firstboot_proof is not None else None,specification_sha256=digest(out/'installed.mtree'),
                log_sha256=digest(audit_log),files=build_report['files'],directories=build_report['directories'],
                scope='All baseline types, UID/GID, modes, security flags, symlink targets and regular SHA256; format 3 separately proves declared firstboot transitions and optional archive-bit normalization; excludes timestamps, extra runtime objects and hardlink inode identity')
            save()
            if not audit_passed:raise RuntimeError('complete installed-tree audit differs; retain every difference for review, see installed-audit.log')
            check('installed-tree-audit',lambda:'complete captured baseline plus any independently verified firstboot transitions matches')
        console.send('/sbin/shutdown -p now')
        until=time.monotonic()+180
        while process.poll() is None:
            if time.monotonic()>until:raise TimeoutError('normal shutdown did not power off the guest')
            console.tick(allow_exit=True);time.sleep(0.2)
        assert process.returncode==0,process.returncode
        console.drain()
        assert not FAILURE_DIAGNOSTICS.search(bytes(console.data))
        assert digest(image)==build_report['image_sha256'],'immutable backing image changed'
        assert all(digest(Path(path))==expected for path,expected in source_bindings.items()),'runner sources changed during qualification'
        report.update(status='passed',vm_seconds=time.monotonic()-started,overlay_bytes=overlay.stat().st_blocks*512)
    except Exception as error:
        report.update(status='failed',error=repr(error));raise
    finally:
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        console.close();report['host_resources']=monitor.close();report['qemu_exit_status']=process.returncode
        report['serial_sha256']=digest(out/'serial.log');report['max_observed_overlay_bytes']=console.disk_peak;report['terminal_size_replies']=console.terminal.responses;save()
    print(out/'result.json')

if __name__=='__main__':main()
