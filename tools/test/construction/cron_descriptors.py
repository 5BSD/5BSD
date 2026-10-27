#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual cron system-table jobs in a disposable VM; not PAM/BIP qualification."""
import argparse
import hashlib
import re
import os
from pathlib import Path
import signal
import socket
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user-tables', action='store_true')
    parser.add_argument('--debug-cron', action='store_true', help='diagnostic tracing; retained explicitly in test output')
    parser.add_argument('--ktrace', type=Path)
    parser.add_argument('--kdump', type=Path)
    parser.add_argument('--pam-policy', type=Path)
    parser.add_argument('--pam-fallback', type=Path)
    args = parser.parse_args()
    if (args.ktrace is None) != (args.kdump is None):
        parser.error("syscall diagnostics require both explicit tracing tools")
    if any(args.user_tables != (p is not None) for p in (args.pam_policy, args.pam_fallback)):
        parser.error('user tables require explicit PAM service and fallback policies')
    if os.geteuid() != 0 or subprocess.check_output(
            ['/sbin/sysctl', '-n', 'kern.vm_guest'], text=True).strip() in ('', 'none'):
        raise ValueError('requires root in a disposable VM')
    # Private mechanism fixture state; normal rc and BIP layout are not exercised.
    for name in ('/etc', '/var'):
        subprocess.run(['/sbin/mount', '-t', 'tmpfs', 'tmpfs', name], check=True)
    for name in ('/var/run', '/var/cron/tabs'):
        Path(name).mkdir(parents=True, exist_ok=True)
    work = Path('/tmp/cron-descriptors'); work.mkdir(mode=0o777); work.chmod(0o777)
    master = Path('/etc/master.passwd.input')
    master.write_text('root:*:0:0::0:0:root:/root:/bin/sh\njobuser:*:12345:12345::0:0:job:/tmp:/bin/sh\n')
    denied_users = ('lockedjob', 'expiredjob') if args.user_tables else ()
    if args.user_tables:
        with master.open('a') as stream:
            stream.write('lockedjob:*LOCKED**:12346:12346::0:0:locked:/tmp:/bin/sh\n'
                         'expiredjob:*:12347:12347::0:1:expired:/tmp:/bin/sh\n')
    subprocess.run(['/tests/pwd_mkdb', '-p', '-d', '/etc', str(master)], check=True)
    Path('/etc/group').write_text('wheel:*:0:root\njobuser:*:12345:\n')
    if args.user_tables:
        Path('/etc/pam.d').mkdir()
        shutil.copyfile(args.pam_policy, '/etc/pam.d/cron')
        Path('/etc/pam.d/cron').chmod(0o644)
        shutil.copyfile(args.pam_fallback, '/etc/pam.d/other')
        Path('/etc/pam.d/other').chmod(0o644)
        for user, uid in (('root', 0), ('jobuser', 12345),
                          ('lockedjob', 12346), ('expiredjob', 12347)):
            table = Path('/var/cron/tabs') / user
            table.write_text('SHELL=/bin/sh\nMAILTO=""\n@reboot /tests/cron_job_probe > '
                '/tmp/cron-descriptors/' + user + '.out 2> /tmp/cron-descriptors/' +
                user + '.err%fixture-input\n')
            table.chmod(0o600); os.chown(table, uid, uid)
    else:
        table = Path('/etc/crontab')
        if table.exists():
            raise ValueError('fixture must not overwrite an existing system crontab')
        table.write_text('SHELL=/bin/sh\nMAILTO=""\n' + ''.join(
            '@reboot ' + user + ' /tests/cron_job_probe > /tmp/cron-descriptors/' + user +
            '.out 2> /tmp/cron-descriptors/' + user + '.err%fixture-input\n'
            for user in ('root', 'jobuser')))
        table.chmod(0o600)
    sentinel = os.open(work / 'private-descriptor', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.dup2(sentinel, 199, inheritable=True); os.close(sentinel)
    logs = []
    for path in ('/var/run/log', '/var/run/logpriv'):
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        # Burst logging from concurrent job children must fit before polling.
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        if channel.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) < 65536:
            raise ValueError('fixture log receive capacity was not established')
        channel.bind(path); channel.setblocking(False); logs.append(channel)
    observed_denials = set()
    process = None
    try:
        with (work / 'daemon.log').open('w') as log:
            command = ['/tests/cron', '-n'] + (['-x', 'misc,proc,load'] if args.debug_cron else [])
            if args.ktrace is not None:
                command = [str(args.ktrace), '-i', '-t', 'cn', '-f', str(work / 'ktrace.out'), *command]
            print('CRON_COMMAND ' + repr(command), flush=True)
            process = subprocess.Popen(command, pass_fds=(199,),
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + 80
            while time.monotonic() < deadline:
                for channel in logs:
                    while True:
                        try:
                            message = channel.recv(65536)
                        except BlockingIOError:
                            break
                        text = message.decode(errors='replace')
                        print('CRON_SYSLOG ' + text, flush=True)
                        for user in denied_users:
                            if '(' + user + ') USER (account unavailable)' in text:
                                observed_denials.add(user)
                if process.poll() is not None:
                    raise ValueError('cron exited: ' + (work / 'daemon.log').read_text())
                if observed_denials == set(denied_users) and all((work / (u + '.err')).exists() and
                       (work / (u + '.err')).read_text() == 'cron-job-stderr\n'
                       for u in ('root', 'jobuser')):
                    break
                time.sleep(0.2)
            else:
                raise ValueError('scheduled jobs did not complete: ' + (work / 'daemon.log').read_text())
            for user, uid in (('root', 0), ('jobuser', 12345)):
                actual = (work / (user + '.out')).read_text()
                expected = f'uid={uid} gid={uid} leaked=0 input=fixture-input\n'
                if actual != expected:
                    raise ValueError('job output differs: ' + repr(actual))
            for user in denied_users:
                if any((work / (user + suffix)).exists() for suffix in ('.out', '.err')):
                    raise ValueError('denied account launched a shell: ' + user)
            if denied_users:
                print('CRON_ACCOUNT_DENIAL_PASS locked expired explicit-denials no-job-output', flush=True)
            print('CRON_DESCRIPTOR_PASS root nonroot stdin stdout stderr inherited-fd-refused mode=' +
                ('user-tables-pam' if args.user_tables else 'system-table'), flush=True)
    finally:
        for path in sorted(work.iterdir()):
            if path.name == 'daemon.log' or path.suffix in ('.out', '.err'):
                print('CRON_DIAGNOSTIC ' + path.name + ' ' + repr(path.read_text(errors='replace')), flush=True)
        os.close(199)
        for channel in logs:
            channel.close()
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
        if args.kdump is not None and (work / 'ktrace.out').exists():
            dump = subprocess.check_output([str(args.kdump), '-t', 'c', '-f',
                str(work / 'ktrace.out')], text=True, timeout=20)
            print('CRON_SYSCALL_DUMP_SHA256 ' + hashlib.sha256(dump.encode()).hexdigest(), flush=True)
            for line in dump.splitlines():
                if re.search(r'\b(socket|connect|sendto|sendmsg|setsockopt|getsockopt)\b', line):
                    print('CRON_SYSCALL ' + line, flush=True)


if __name__ == '__main__':
    main()
