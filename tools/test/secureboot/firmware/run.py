#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Disposable EFI application execution test, not loader/OS qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
from evidence import execution, rejection, authenticated_update, authenticated_replay


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('probe', 'variables', 'firmware', 'qemu', 'qemu-data', 'makefs', 'mkimg', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expect', choices=('enabled', 'disabled', 'rejected', 'auth-update', 'auth-replay'), required=True)
    parser.add_argument('--data-root', type=Path, help='public update inputs, required for auth-update and auth-replay')
    parser.add_argument('--control', type=Path, help='enabled positive-control result required for rejection')
    parser.add_argument('--timeout', type=int, default=45)
    args = parser.parse_args()
    if args.timeout < 10:
        parser.error('timeout must be at least 10 seconds')
    if (args.expect == 'rejected') != (args.control is not None):
        parser.error('rejection requires an enabled control; other cases forbid it')
    if (args.expect in ('auth-update', 'auth-replay')) != (args.data_root is not None):
        parser.error('auth-update and auth-replay require data-root; other cases forbid it')
    paths = {name: getattr(args, name).resolve(strict=True) for name in
             ('probe', 'variables', 'firmware', 'qemu', 'qemu_data', 'makefs', 'mkimg')}
    work = args.work.resolve()
    if not work.is_relative_to('/usr/obj/usr/src') or work == Path('/usr/obj/usr/src'):
        parser.error('work must be a fresh directory below /usr/obj/usr/src')
    if any(',' in str(p) or '\n' in str(p) or '\r' in str(p) for p in [work, *paths.values()]):
        parser.error('QEMU paths must not contain commas or newlines')
    for name, path in paths.items():
        if name != 'qemu_data' and not path.is_file():
            parser.error(name + ' must be a regular file')
    inputs = {name: {'path': str(path), 'sha256': digest(path)}
              for name, path in paths.items() if path.is_file()}
    inputs['evidence'] = {'path': str(Path(__file__).with_name('evidence.py').resolve()),
                          'sha256': digest(Path(__file__).with_name('evidence.py'))}
    inputs['runner'] = {'path': str(Path(__file__).resolve()),
                        'sha256': digest(Path(__file__))}
    control_digest = None
    if args.control is not None:
        control_path = args.control.resolve(strict=True)
        control = json.loads(control_path.read_text())
        control_digest = digest(control_path)
        transcript = control_path.parent / 'serial.log'
        if (control.get('result') != 'PASS' or control.get('expect') != 'enabled' or
                control.get('forced_termination') or control.get('qemu_exit') != 0 or
                digest(transcript) != control.get('serial_sha256') or
                not execution(transcript.read_text(errors='replace'), True)):
            parser.error('control does not establish enabled execution')
        for name in ('variables', 'firmware', 'qemu', 'runner', 'evidence'):
            if control['inputs'][name]['sha256'] != inputs[name]['sha256']:
                parser.error('control input differs: ' + name)
    payloads = {}
    if args.data_root is not None:
        payloads = {name: args.data_root.resolve(strict=True) / name for name in
                    ('db.expected', 'db.valid.auth', 'db.newer.auth' if args.expect == 'auth-replay' else 'db.invalid.auth')}
        for name, path in payloads.items():
            if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 65536:
                parser.error('invalid update input: ' + name)
            inputs['payload:' + name] = {'path': str(path), 'sha256': digest(path)}
    work.mkdir(parents=True, exist_ok=False)
    esp = work / 'esp/EFI/BOOT'
    esp.mkdir(parents=True)
    shutil.copyfile(paths['probe'], esp / 'BOOTX64.EFI')
    shutil.copyfile(paths['variables'], work / 'vars.fd')
    for name, path in payloads.items():
        shutil.copyfile(path, work / 'esp' / name)
    with (work / 'image.log').open('w') as log:
        subprocess.run([str(paths['makefs']), '-t', 'msdos', '-s', '32m', '-o', 'fat_type=16',
                        str(work / 'esp.fat'), str(work / 'esp')], check=True, stdout=log, stderr=log)
        subprocess.run([str(paths['mkimg']), '-s', 'gpt', '-f', 'raw', '-p',
                        'efi:=' + str(work / 'esp.fat'), '-o', str(work / 'guest.img')],
                       check=True, stdout=log, stderr=log)
    cmd = [str(paths['qemu']), '-L', str(paths['qemu_data']), '-accel', 'tcg,thread=multi',
           '-machine', 'q35,smm=on', '-global', 'driver=cfi.pflash01,property=secure,value=on',
           '-cpu', 'max', '-m', '2048', '-smp', '2',
           '-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={paths["firmware"]}',
           '-drive', f'if=pflash,format=raw,unit=1,file={work}/vars.fd',
           '-drive', f'if=virtio,format=raw,snapshot=on,file={work}/guest.img',
           '-nic', 'none', '-display', 'none', '-monitor', 'none',
           '-serial', f'file:{work}/serial.log', '-no-reboot']
    forced = False
    killed = False
    stop_reason = None
    with (work / 'qemu.log').open('w') as log:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        deadline = time.monotonic() + args.timeout
        try:
            while proc.poll() is None:
                serial_path = work / 'serial.log'
                if (args.expect == 'rejected' and serial_path.exists() and
                        rejection(serial_path.read_text(errors='replace'))):
                    stop_reason = 'firmware-rejection-observed'
                    break
                if time.monotonic() >= deadline:
                    stop_reason = 'timeout'
                    break
                time.sleep(0.1)
        finally:
            if proc.poll() is None:
                forced = True
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    killed = True
                    proc.kill()
                    proc.wait()
    serial = (work / 'serial.log').read_text(errors='replace')
    if args.expect == 'rejected':
        passed = (stop_reason == 'firmware-rejection-observed' and not killed and
                  proc.returncode in (0, -15) and rejection(serial))
        passed = passed and digest(control_path) == control_digest
    elif args.expect == 'auth-replay':
        passed = not forced and proc.returncode == 0 and authenticated_replay(serial)
    elif args.expect == 'auth-update':
        passed = not forced and proc.returncode == 0 and authenticated_update(serial)
    else:
        passed = (not forced and proc.returncode == 0 and
                  execution(serial, args.expect == 'enabled'))
    for value in inputs.values():
        if digest(Path(value['path'])) != value['sha256']:
            passed = False
    result = {'scope': 'firmware application execution only', 'result': 'PASS' if passed else 'FAIL',
              'expect': args.expect, 'command': cmd, 'inputs': inputs,
              'forced_termination': forced, 'qemu_exit': proc.returncode,
              'stop_reason': stop_reason, 'killed': killed,
              'control_sha256': control_digest,
              'control': str(args.control) if args.control else None,
              'serial_sha256': digest(work / 'serial.log'),
              'variables_after_sha256': digest(work / 'vars.fd')}
    (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(serial)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
