"""Install qualification media onto an exclusive disposable disk, without a NIC.

The media must run bsdinstall-software.conf and emit SOFTWARE_BSDINSTALL_PASS
only after bsdinstall script exits successfully. This does not qualify the
installed system; that requires a separate boot without installation media.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from qmp_shutdown import ShutdownEvidence


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iso', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--qemu-data', type=Path)
    parser.add_argument('--cpus', type=int, default=os.cpu_count() or 1)
    parser.add_argument('--timeout', type=int, default=1800)
    args = parser.parse_args()
    if not __debug__:
        parser.error('do not disable evidence assertions with Python -O')
    if args.cpus <= 0 or args.timeout <= 0:
        parser.error('cpus and timeout must be positive')
    subprocess.run([args.qemu, '--version'], check=True, stdout=subprocess.DEVNULL)
    iso = args.iso.resolve(strict=True)
    if not iso.is_file():
        parser.error('ISO must be a regular file')
    manifest_path = iso.parent / 'media.json'
    manifest = json.loads(manifest_path.read_text())
    iso_hash = sha(iso)
    if (Path(manifest['iso']).resolve() != iso
            or manifest['iso_sha256'] != iso_hash
            or manifest['scope'] != 'private installer automation media, not a public release'):
        parser.error('ISO does not match its private qualification manifest')
    manifest_hash = sha(manifest_path)
    work = args.work.resolve()
    work.mkdir(exist_ok=False)
    disk = work / 'installed.img'
    with disk.open('xb') as stream:
        stream.truncate(32 * 1024**3)
    log = work / 'install-serial.log'
    command = [
        args.qemu, '-accel', 'tcg,thread=multi',
        '-machine', 'q35', '-cpu', 'max', '-m', '8192', '-smp', str(args.cpus),
        '-drive', f'file={disk},format=raw,if=none,id=target',
        '-device', 'virtio-blk-pci,drive=target,serial=sw-installer-target',
        '-cdrom', str(iso), '-boot', 'd', '-nic', 'none', '-display', 'none',
        '-monitor', 'none', '-serial', f'file:{log}',
    ]
    shutdown = ShutdownEvidence(work)
    command += shutdown.arguments
    if args.qemu_data:
        command += ['-L',str(args.qemu_data.resolve())]
    (work / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    required = {'SOFTWARE_MULTICONSOLE_UNIX_PASS', 'SOFTWARE_BSDINSTALL_SETUP_PASS', 'SOFTWARE_BSDINSTALL_PASS'}
    fatal = ('panic:', 'Fatal trap', 'lock order reversal',
             'SOFTWARE_BSDINSTALL_FAIL', 'could not quiesce init')
    forced = False
    started = time.monotonic()
    with (work / 'qemu.log').open('w') as stderr:
        process = subprocess.Popen(command, stdout=stderr, stderr=stderr)
        shutdown.start(process)
        try:
            while process.poll() is None and time.monotonic() - started < args.timeout:
                text = log.read_text(errors='replace') if log.exists() else ''
                if any(marker in text for marker in fatal):
                    break
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
    text = log.read_text(errors='replace') if log.exists() else ''
    missing = sorted(required - set(text.splitlines()))
    passed = (not missing and not forced and process.returncode == 0
              and shutdown_evidence['guest_poweroff'] and 'All buffers synced.' in text and 'Powering system off' in text
              and not any(marker in text for marker in fatal)
              and sha(iso) == iso_hash
              and sha(manifest_path) == manifest_hash)
    result = {
        'result': 'PASS' if passed else 'FAIL',
        'shutdown_evidence': shutdown_evidence,
        'scope': 'scripted BSDInstall to a fresh virtual disk only; installed boot and service tests still required',
        'iso': str(iso), 'iso_sha256': iso_hash, 'disk': str(disk),
        'media_manifest': str(manifest_path), 'media_manifest_sha256': manifest_hash,
        'serial_sha256': sha(log) if log.exists() else None,
        'serial_log': str(log), 'missing_markers': missing,
        'forced_termination': forced, 'qemu_exit': process.returncode,
        'elapsed_seconds': round(time.monotonic() - started, 1),
    }
    (work / 'install-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
