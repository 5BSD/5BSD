#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Observe unmodified installed media; never infer functional qualification."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import time


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate policy key: ' + key)
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("invalid JSON constant: " + value)


def canonical(value, directory=False):
    if (not isinstance(value, str) or not value.startswith('/') or
            any(c in value for c in ',\n\r\0') or str(Path(value)) != value):
        raise ValueError('invalid canonical input path')
    path = Path(value)
    if path.resolve(strict=True) != path:
        raise ValueError('aliased input path')
    if directory:
        if not path.is_dir(): raise ValueError('input is not a directory')
    elif not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('input is not a regular file')
    return path


def validate(policy):
    fields = {'format', 'qemu', 'qemu_data', 'firmware_code', 'firmware_variables',
              'boot_media', 'data_disks', 'cpus', 'memory_mib', 'seconds', 'ssh_forward_port'}
    if not isinstance(policy, dict) or type(policy.get('format')) is not int or policy['format'] not in (1, 2):
        raise ValueError('invalid observation policy format')
    if policy['format'] == 2:
        fields.add('ssh_probe')
    if set(policy) != fields:
        raise ValueError('invalid observation policy fields')
    for name, low, high in [('cpus',1,256), ('memory_mib',512,65536), ('seconds',15,7200)]:
        if type(policy[name]) is not int or not low <= policy[name] <= high:
            raise ValueError('invalid ' + name)
    port = policy['ssh_forward_port']
    if port is not None and (type(port) is not int or not 1024 <= port <= 65535):
        raise ValueError('invalid SSH forwarding port')
    if not isinstance(policy['data_disks'], list) or len(policy['data_disks']) > 16:
        raise ValueError('invalid data disk list')
    probe_inputs = []
    if policy['format'] == 2:
        probe = policy['ssh_probe']
        if (port is None or not isinstance(probe, dict) or set(probe) !=
                {'client', 'known_hosts', 'identity', 'user', 'command', 'stdout_sha256'}):
            raise ValueError('SSH probe requires forwarding and explicit inputs')
        if (not isinstance(probe['user'], str) or
                re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}', probe['user']) is None or
                not isinstance(probe['command'], str) or not probe['command'] or
                len(probe['command'].encode()) > 4096 or '\0' in probe['command'] or
                not isinstance(probe['stdout_sha256'], str) or
                re.fullmatch('[0-9a-f]{64}', probe['stdout_sha256']) is None):
            raise ValueError('invalid SSH probe command or expectation')
        probe_inputs = [probe[name] for name in ('client', 'known_hosts', 'identity')]
        for entry in probe_inputs:
            if (not isinstance(entry, dict) or not isinstance(entry.get('path'), str) or
                    any(c.isspace() or c in ('%', '$', '"', "'", chr(92)) for c in entry['path'])):
                raise ValueError('SSH input paths must not contain whitespace, quoting or expansion tokens')
    inputs = {}
    for entry in [policy[n] for n in ('qemu','firmware_code','firmware_variables','boot_media')] + policy['data_disks'] + probe_inputs:
        if (not isinstance(entry, dict) or set(entry) != {'path','sha256'} or
                not isinstance(entry['sha256'], str) or len(entry['sha256']) != 64 or
                any(c not in '0123456789abcdef' for c in entry['sha256'])):
            raise ValueError('invalid input binding')
        path = canonical(entry['path'])
        if str(path) in inputs: raise ValueError('duplicate input path')
        if digest(path) != entry['sha256']: raise ValueError('input hash differs: ' + str(path))
        inputs[str(path)] = entry['sha256']
    canonical(policy['qemu_data'], directory=True)
    if not os.access(policy['qemu']['path'], os.X_OK): raise ValueError('QEMU is not executable')
    if probe_inputs:
        if not os.access(probe['client']['path'], os.X_OK):
            raise ValueError('SSH client is not executable')
        if Path(probe['identity']['path']).stat().st_mode & 0o077:
            raise ValueError('SSH probe identity must be private')
    return inputs




def ssh_command(policy):
    probe = policy['ssh_probe']
    options = ['BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none',
        'CertificateFile=/dev/null', 'PubkeyAcceptedAlgorithms=-*-cert-v01@openssh.com',
        'PreferredAuthentications=publickey', 'HostbasedAuthentication=no',
        'StrictHostKeyChecking=yes', 'UpdateHostKeys=no',
        'UserKnownHostsFile=' + probe['known_hosts']['path'],
        'GlobalKnownHostsFile=/dev/null', 'PasswordAuthentication=no',
        'KbdInteractiveAuthentication=no', 'ClearAllForwardings=yes',
        'ControlMaster=no', 'ControlPath=none', 'PermitLocalCommand=no',
        'ConnectTimeout=3', 'ConnectionAttempts=1']
    argv = [probe['client']['path'], '-F', '/dev/null', '-T',
            '-p', str(policy['ssh_forward_port']), '-i', probe['identity']['path']]
    for option in options:
        argv.extend(['-o', option])
    return argv + ['-l', probe['user'], '127.0.0.1', probe['command']]



def identity_public_input(policy):
    """Record the optional public-key sidecar OpenSSH reads automatically."""
    if policy['format'] != 2:
        return None
    path = Path(policy['ssh_probe']['identity']['path'] + '.pub')
    try:
        path.lstat()
    except FileNotFoundError:
        return {'path': str(path), 'sha256': None}
    return {'path': str(path), 'sha256': digest(canonical(str(path)))}


def probe_ssh(policy, work, attempt, timeout):
    """One bounded external SSH command; callers retain each failed attempt."""
    stdout, stderr = (work / ('ssh-%d.%s' % (attempt, suffix))
                      for suffix in ('stdout', 'stderr'))
    code, timed_out = None, False
    with stdout.open('xb') as out, stderr.open('xb') as err:
        try:
            result = subprocess.run(ssh_command(policy), stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, timeout=timeout, close_fds=True,
                env={'PATH': '/sbin:/bin:/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
            code = result.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
    actual = digest(stdout)
    return {'attempt': attempt, 'exit_code': code, 'timed_out': timed_out,
            'stdout_sha256': actual, 'stderr_sha256': digest(stderr),
            'matched': not timed_out and code == 0 and
                actual == policy['ssh_probe']['stdout_sha256']}


def data_inventory(directory):
    """Measure a physical QEMU data tree in the trusted, quiescent builder."""
    root = canonical(str(directory), directory=True)
    entries = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        name = path.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):
            entries[name] = {'type': 'directory'}
        elif stat.S_ISREG(info.st_mode):
            entries[name] = {'type': 'file', 'size': info.st_size,
                             'sha256': digest(path)}
        else:
            raise ValueError('QEMU data requires physical directories and regular files: ' + name)
    return entries


def command(policy, work, variables, disks):
    args = [policy['qemu']['path'], '-L', policy['qemu_data'],
        '-accel', 'tcg,thread=multi', '-machine', 'q35,smm=on',
        '-global', 'driver=cfi.pflash01,property=secure,value=on',
        '-cpu', 'max', '-m', str(policy['memory_mib']), '-smp', str(policy['cpus']),
        '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=' + policy['firmware_code']['path'],
        '-drive', 'if=pflash,format=raw,unit=1,file=' + str(variables),
        '-drive', 'if=none,id=system,format=raw,readonly=on,file=' + policy['boot_media']['path'],
        '-device', 'virtio-blk-pci,drive=system,bootindex=0', '-boot', 'strict=on',
        '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(work/'serial.log'), '-no-reboot']
    for index, disk in enumerate(disks):
        identity = 'data' + str(index)
        args += ['-drive', 'if=none,id='+identity+',format=raw,file='+str(disk),
                 '-device', 'virtio-blk-pci,drive='+identity]
    port = policy['ssh_forward_port']
    args += ['-nic', 'none'] if port is None else [
        '-netdev', 'user,id=isolated,restrict=on,hostfwd=tcp:127.0.0.1:'+str(port)+'-:22',
        '-device', 'virtio-net-pci,netdev=isolated']
    return args



class SerialFailureDetector:
    """Incrementally scan an append-only QEMU log; retain any observed failure."""
    markers = (b'panic:', b'Fatal trap', b'mountroot>')

    def __init__(self):
        self.identity = None
        self.offset = 0
        self.tail = b''
        self.failed = False
        self.bytes_read = 0

    def scan(self, path):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return self.failed
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('serial log is not a regular file')
            identity = (info.st_dev, info.st_ino)
            if identity != self.identity or info.st_size < self.offset:
                self.identity, self.offset, self.tail = identity, 0, b''
            stream.seek(self.offset)
            # Bound each pass to the size observed at entry. A noisy guest
            # must not keep the poll loop reading indefinitely.
            remaining = info.st_size - self.offset
            overlap = max(map(len, self.markers)) - 1
            while remaining:
                chunk = stream.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                self.offset += len(chunk)
                self.bytes_read += len(chunk)
                window = self.tail + chunk
                self.failed |= any(marker in window for marker in self.markers)
                self.tail = window[-overlap:]
        return self.failed


def fatal_serial(path):
    return SerialFailureDetector().scan(path)


def observation_result(changed, lifecycle, failure, returncode, forced, *, ssh_required=False, ssh_matched=False):
    if changed:
        return 'INPUT_CHANGED'
    if lifecycle['error']:
        return 'HARNESS_FAILURE'
    if failure:
        return 'GUEST_FAILURE'
    if forced:
        return 'OBSERVATION_TIMEOUT'
    if returncode != 0 or not lifecycle['guest_poweroff']:
        return 'HARNESS_FAILURE'
    if ssh_required and not ssh_matched:
        return 'SSH_PROBE_FAILED'
    return 'OBSERVED'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    raw = args.policy.read_bytes()
    policy = json.loads(raw, object_pairs_hook=unique,
        parse_constant=invalid_constant)
    inputs = validate(policy)
    qemu_data = data_inventory(policy['qemu_data'])
    identity_public = identity_public_input(policy)
    work = args.work.absolute()
    if (str(work) != str(args.work) or work.resolve() != work or
            not work.is_relative_to('/usr/obj/usr/src') or work.exists() or
            any(c in str(work) for c in ',\n\r')):
        parser.error('requires a new canonical work directory under /usr/obj/usr/src')
    work.mkdir(mode=0o700)
    variables = work/'variables.fd'
    shutil.copyfile(policy['firmware_variables']['path'], variables)
    disks = []
    for index, entry in enumerate(policy['data_disks']):
        target = work/('data-'+str(index)+'.img')
        shutil.copyfile(entry['path'], target)
        if digest(target) != entry['sha256']: raise ValueError('data copy differs')
        disks.append(target)
    if digest(variables) != policy['firmware_variables']['sha256']: raise ValueError('variable copy differs')
    helper = Path(__file__).resolve().parent.parent/'software-authority/qmp_shutdown.py'
    spec = importlib.util.spec_from_file_location('qmp_shutdown',helper)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    inputs[str(Path(__file__).resolve())] = digest(__file__)
    inputs[str(helper)] = digest(helper)
    shutdown = module.ShutdownEvidence(work)
    argv = command(policy, work, variables, disks) + shutdown.arguments
    (work/'inputs.json').write_text(json.dumps({'policy':policy,'policy_sha256':hashlib.sha256(raw).hexdigest(),
        'qemu_data_inventory':qemu_data,'ssh_identity_public':identity_public,
        'files_sha256':inputs,'runner_sha256':digest(__file__),'shutdown_helper_sha256':digest(helper),
        'command':argv,'scope':'unmodified installed-media diagnostic; no functional acceptance'},indent=2)+'\n')
    detector = SerialFailureDetector()
    ssh_attempts = []
    ssh_matched = False
    next_ssh = 0
    started=time.monotonic(); forced=False; failure=False
    with (work/'qemu.log').open('x') as log:
        process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:
            # Collector startup can fail after QEMU exists (for example,
            # thread exhaustion). Keep it inside the child cleanup scope.
            shutdown.start(process)
            while process.poll() is None and time.monotonic()-started < policy['seconds']:
                serial=work/'serial.log'
                if detector.scan(serial):
                    failure=True;break
                now = time.monotonic()
                if policy['format'] == 2 and not ssh_matched and now >= next_ssh:
                    remaining = policy['seconds'] - (now - started)
                    if remaining > 0:
                        attempt = probe_ssh(policy, work, len(ssh_attempts), min(5, remaining))
                        ssh_attempts.append(attempt)
                        ssh_matched = attempt['matched']
                        next_ssh = time.monotonic() + 5
                        (work / 'ssh-attempts.json').write_text(json.dumps(ssh_attempts, indent=2) + '\n')
                time.sleep(1)
        finally:
            if process.poll() is None:
                forced=True;process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()
    # QEMU may exit between polling iterations after writing a fatal message.
    failure = detector.scan(work/'serial.log') or failure
    lifecycle=shutdown.finish()
    changed=[]
    for path, expected in inputs.items():
        try:
            matches = digest(path) == expected
        except OSError:
            matches = False
        if not matches: changed.append(path)
    try:
        data_unchanged = data_inventory(policy['qemu_data']) == qemu_data
    except (OSError, ValueError):
        data_unchanged = False
    if not data_unchanged:
        changed.append(policy['qemu_data'])
    if identity_public is not None:
        try:
            public_unchanged = identity_public_input(policy) == identity_public
        except (OSError, ValueError):
            public_unchanged = False
        if not public_unchanged:
            changed.append(identity_public['path'])
    result=observation_result(changed, lifecycle, failure, process.returncode, forced,
        ssh_required=policy['format'] == 2, ssh_matched=ssh_matched)
    report={'result':result,'scope':'installed-media diagnostic only','qemu_exit':process.returncode,
        'forced_termination':forced,'elapsed_seconds':time.monotonic()-started,'shutdown':lifecycle,
        'changed_inputs':changed,'normal_boot_qualified':False,'ssh_qualified':False,
        'ssh_probe':{'requested':policy['format'] == 2, 'matched':ssh_matched, 'attempts':ssh_attempts},
        'secure_boot_qualified':False,'system_integrity_qualified':False,
        'serial_sha256':digest(work/'serial.log') if (work/'serial.log').exists() else None,
        'retained_data':{str(p):digest(p) for p in disks},'variables_sha256':digest(variables)}
    (work/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('result','scope','qemu_exit','forced_termination')}))
    return 0 if result=='OBSERVED' else 124 if result=='OBSERVATION_TIMEOUT' else 1


if __name__=='__main__':raise SystemExit(main())
