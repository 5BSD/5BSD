#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run the staged disposable VM, recording serial evidence and checking results."""
import argparse
import os
from pathlib import Path
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('image', type=Path)
p.add_argument('--log', type=Path, required=True)
p.add_argument('--qemu', default='/usr/local/bin/qemu-system-x86_64')
p.add_argument('--library-path')
p.add_argument('--cpus', type=int, default=os.cpu_count())
p.add_argument('--timeout', type=int, default=3600)
p.add_argument('--serial-port', type=int, default=14323)
a = p.parse_args()
if not a.image.is_file():
    raise SystemExit('VM image does not exist')
if a.log.exists():
    raise SystemExit('Refusing to overwrite serial evidence')
artifacts = a.log.with_suffix('.artifacts.raw')
with artifacts.open('xb') as f:
    f.truncate(256 * 1024 * 1024)
env = dict(os.environ)
if a.library_path:
    env['LD_LIBRARY_PATH'] = a.library_path
# The input is a newly staged disposable image. snapshot=on preserves it while
# retaining guest writes across the reboot that loads the freshly built daemon.
command = [a.qemu, '-accel', 'tcg,thread=multi', '-machine', 'q35', '-cpu', 'max',
           '-m', '8192', '-smp', str(a.cpus), '-drive',
           f'file={a.image.resolve()},format=raw,if=virtio,snapshot=on',
           '-drive', f'file={artifacts.resolve()},format=raw,if=virtio',
           '-nic', 'none', '-display', 'none', '-monitor', 'none',
           '-chardev', f'socket,id=serial,host=127.0.0.1,port={a.serial_port},server=on,wait=off,logfile={a.log.resolve()}',
           '-serial', 'chardev:serial']
print('Starting isolated VM:', ' '.join(command), flush=True)
proc = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL)
deadline = time.monotonic() + a.timeout
passed = False
try:
    while time.monotonic() < deadline and proc.poll() is None:
        text = a.log.read_text(errors='replace') if a.log.exists() else ''
        if 'POLICY_GUEST_COMPLETE' in text:
            bad = ['POLICY_BUILD_FAIL', 'POLICY_VM_FAIL', 'panic:', 'Fatal trap',
                   'lock order reversal', 'KDB: enter']
            required = ['UNIX_COMPAT_PASS', 'SSH_COMPAT_PASS', 'PASSWORD_LOGIN_PASS',
                        'SESSION_ELEVATION_PASS', 'SSH_BAD_PASSWORD_DENIED_PASS',
                        'POLICY_FILE_TRUST_PASS', 'LEGACY_COMPAT_PASS',
                        'SESSION_AUTHORITY_BOUNDARIES_PASS',
                        'SSH_CONCURRENT_GRANTS_PASS', 'SSH_WRONG_KEY_DENIED_PASS']
            passed = all(x in text for x in required) and not any(x in text for x in bad)
            break
        if 'POLICY_BUILD_FAIL' in text or 'POLICY_VM_FAIL' in text or 'panic:' in text:
            break
        time.sleep(1)
finally:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
print('POLICY_QEMU_PASS' if passed else 'POLICY_QEMU_FAIL', flush=True)
raise SystemExit(0 if passed else 1)
