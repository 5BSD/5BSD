#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run the staged disposable VM, recording serial evidence and checking results."""
import argparse
import os
from pathlib import Path
import subprocess
import time
import tarfile

p = argparse.ArgumentParser()
p.add_argument('image', type=Path)
p.add_argument('--log', type=Path, required=True)
p.add_argument('--qemu', default='/usr/local/bin/qemu-system-x86_64')
p.add_argument('--library-path')
p.add_argument('--cpus', type=int, default=os.cpu_count())
p.add_argument('--timeout', type=int, default=3600)
p.add_argument('--serial-port', type=int, default=14323)
p.add_argument('--require-zfs', action='store_true', help='require real BE staging, activation, and rollback checks')
p.add_argument('--verify-only', action='store_true', help='verify saved serial and artifact evidence without starting QEMU')
a = p.parse_args()
def verify(log, artifacts):
    text = log.read_text(errors='replace')
    required = ['POLICY_GUEST_COMPLETE', 'ALL_GRANT_IDENTITY_PASS',
                'SESSION_MINT_BOUNDARY_PASS', 'UNIX_COMPAT_PASS', 'SSH_COMPAT_PASS',
                'PASSWORD_LOGIN_PASS', 'SESSION_ELEVATION_PASS',
                'SSH_BAD_PASSWORD_DENIED_PASS', 'POLICY_SNAPSHOT_PASS',
                'NEXT_BOOT_POLICY_PASS', 'SESSION_AUTHORITY_BOUNDARIES_PASS',
                'SSH_CONCURRENT_GRANTS_PASS', 'SSH_WRONG_KEY_DENIED_PASS']
    if a.require_zfs:
        required += ['ZFS_BE_STAGED_PASS', 'ZFS_BE_ACTIVATED_PASS',
                     'ZFS_BE_ROLLBACK_READY', 'ZFS_BE_ROLLBACK_PASS']
    bad = ['POLICY_BUILD_FAIL', 'POLICY_VM_FAIL', 'panic:', 'Fatal trap',
           'lock order reversal', 'KDB: enter']
    if not all(marker in text for marker in required) or any(marker in text for marker in bad):
        return False
    # Shutdown can interrupt the console's copy of the successful build log.
    # Require the original build/tool results from the exported artifact disk.
    try:
        with tarfile.open(artifacts) as archive:
            build = archive.extractfile('root/build.log').read().decode(errors='replace')
        return ('INSTALLER_GRANTS_PASS' in build and 'POLICY_TOOL_PASS' in build and 'POLICY_BUILD_PASS' in build and
                '163/163 passed (0 broken, 0 failed, 0 skipped)' in build)
    except (OSError, tarfile.TarError, KeyError, AttributeError):
        return False

if a.verify_only:
    passed = verify(a.log, a.log.with_suffix('.artifacts.raw'))
    print('POLICY_EVIDENCE_PASS' if passed else 'POLICY_EVIDENCE_FAIL')
    raise SystemExit(0 if passed else 1)

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
            passed = verify(a.log, artifacts)
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
