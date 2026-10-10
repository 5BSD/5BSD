"""Boot the actual BSDInstall target without media and verify installed identity.

This gate does not replace the full login/SSH/authorization/BE suite.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from qmp_shutdown import ShutdownEvidence


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installation', required=True, type=Path)
    parser.add_argument('--expected-kernel', required=True, type=Path)
    parser.add_argument('--work', type=Path, help='new output directory; default installed-boot inside installation')
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--qemu-data', type=Path)
    parser.add_argument('--cpus', type=int, default=os.cpu_count() or 1)
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    if not __debug__:
        parser.error('do not disable evidence assertions with Python -O')
    if args.cpus <= 0 or args.timeout <= 0:
        parser.error('cpus and timeout must be positive')
    subprocess.run([args.qemu, '--version'], check=True, stdout=subprocess.DEVNULL)
    installation = args.installation.resolve(strict=True)
    evidence = installation / 'install-result.json'
    result = json.loads(evidence.read_text())
    assert result['result'] == 'PASS' and not result['forced_termination']
    assert result['qemu_exit'] == 0 and result['shutdown_evidence']['guest_poweroff']
    disk = installation / 'installed.img'
    assert Path(result['disk']).resolve(strict=True) == disk
    expected = digest(args.expected_kernel.resolve(strict=True))
    work = args.work.resolve() if args.work else installation / 'installed-boot'
    work.mkdir(exist_ok=False)
    serial = work / 'serial.log'
    sock = work / 'serial.sock'
    command = [
        args.qemu, '-accel', 'tcg,thread=multi',
        '-machine', 'q35', '-cpu', 'max', '-m', '8192', '-smp', str(args.cpus),
        '-drive', f'file={disk},format=raw,if=none,id=target,snapshot=on',
        '-device', 'virtio-blk-pci,drive=target,serial=sw-installer-target',
        '-boot', 'c', '-nic', 'none', '-display', 'none', '-monitor', 'none',
        '-chardev', f'socket,id=serial,path={sock},server=on,wait=off,logfile={serial}',
        '-serial', 'chardev:serial',
    ]
    shutdown = ShutdownEvidence(work)
    command += shutdown.arguments
    if args.qemu_data:
        command += ['-L',str(args.qemu_data.resolve())]
    (work / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    # The shell prints result markers only after commands succeed. Keep the
    # target unchanged by using QEMU's temporary disk overlay.
    script = """sh <<'INSTALLED_CHECK'
set -eu
[ "$(hostname)" = auth-policy-vm ]
[ "$(id -u)" = 0 ]
[ "$(mount -p | awk '$2 == "/" {print $3}')" = zfs ]
[ "$(sha256 -q /boot/kernel/kernel)" = EXPECTED_KERNEL ]
[ ! -e /Capabilities/System/Auth.cap ]
[ ! -e /usr/bin/anoint ]
pkg query '%n %v' > /tmp/installed-boot-packages
test -s /tmp/installed-boot-packages
cmp /root/installed-packages.txt /tmp/installed-boot-packages
switchboardctl status
kldstat -m dtrace
printf '%s\\n' SOFTWARE_INSTALLED_IDENTITY_PASS
/usr/sbin/capsulectl poweroff
INSTALLED_CHECK
""".replace('EXPECTED_KERNEL', expected)
    (work / 'probe.sh').write_text(script)
    fatal = ('panic:', 'Fatal trap', 'lock order reversal')
    forced = False
    sent = False
    started = time.monotonic()
    with (work / 'qemu.log').open('w') as log:
        process = subprocess.Popen(command, stdout=log, stderr=log)
        shutdown.start(process)
        try:
            while process.poll() is None and time.monotonic() - started < args.timeout:
                text = serial.read_text(errors='replace') if serial.exists() else ''
                if any(marker in text for marker in fatal):
                    break
                if not sent and 'SOFTWARE_INSTALLED_ROOT_BOOTED' in text.splitlines():
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                        channel.settimeout(10)
                        channel.connect(str(sock))
                        for line in script.splitlines():
                            channel.sendall(line.encode() + b'\r')
                            time.sleep(0.1)
                    sent = True
                time.sleep(1)
        finally:
            if process.poll() is None:
                forced = True
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    shutdown_evidence = shutdown.finish()
    text = serial.read_text(errors='replace') if serial.exists() else ''
    required = ['SOFTWARE_INSTALLED_ROOT_BOOTED', 'SOFTWARE_INSTALLED_IDENTITY_PASS']
    missing = [marker for marker in required if marker not in text.splitlines()]
    passed = (sent and not missing and not forced and process.returncode == 0
              and shutdown_evidence['guest_poweroff'] and 'All buffers synced.' in text and 'Powering system off' in text and not any(x in text for x in fatal))
    output = {
        'result': 'PASS' if passed else 'FAIL',
        'shutdown_evidence': shutdown_evidence,
        'scope': 'BSDInstall target booted without media; kernel/package identity, ZFS root, control discovery and DTrace module; full integration suite still required',
        'installation_evidence_sha256': digest(evidence),
        'expected_kernel_sha256': expected, 'missing_markers': missing,
        'forced_termination': forced, 'qemu_exit': process.returncode,
        'serial_sha256': digest(serial) if serial.exists() else None,
        'elapsed_seconds': round(time.monotonic() - started, 1),
    }
    (work / 'result.json').write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps(output), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
