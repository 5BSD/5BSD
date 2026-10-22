#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Live HyperTrace/DTrace validation inside a rootless QEMU guest.

Builds a guest image from a buildworld/buildkernel object tree (NO_ROOT
install, METALOG, makefs/mkimg), bakes in live-qemu-guest.sh and the pid/USDT
test sources, boots it under QEMU (TCG) and parses the per-check verdicts the
guest prints on its serial console ("HTQ <name> PASS|FAIL ...").

Nothing touches the host: no install, no kldload, no host /dev/dtrace.  QEMU
provides no VirtIO DTrace device and (TCG) no SVM NRIP-save, so a bhyve
HyperTrace host/guest session cannot run here; the guest records whether
vmm(4) attaches.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

SOURCE = Path(__file__).resolve().parents[3]
TESTS = Path(__file__).resolve().parent
GUEST_FILES = ['live-qemu-guest.sh', 'pid-target.c', 'pid-target-switch.c',
               'pid-target-asm.S', 'pid-late.d', 'pid-late-lib.c',
               'pid-late-target.c', 'pid-usdt-exe.d', 'pid-usdt-exe.c']


def run_logged(command, log, **kwargs):
    with log.open('wb') as output:
        subprocess.run(command, cwd=SOURCE, stdout=output,
                       stderr=subprocess.STDOUT, check=True, **kwargs)


def stage_config(stage, arch, select):
    console = '/dev/ttyu0'
    config = {
        'etc/fstab': '/dev/vtbd0p2\t/\tufs\trw\t1\t1\n'
                     'tmpfs\t/tmp\ttmpfs\trw,mode=1777\t0\t0\n',
        'etc/rc.conf': 'hostname="hypertrace-live"\nsendmail_enable="NONE"\n'
                       'sshd_enable="NO"\ndumpdev="NO"\ndevmatch_enable="NO"\n',
        'boot/loader.conf': ('console="comconsole"\n' if arch == 'amd64' else '') +
                            'autoboot_delay="1"\ndtraceall_load="YES"\n'
                            'dttransport_load="YES"\n'
                            'kern.msgbufsize="1048576"\n',
        'etc/rc.local': f'(sleep 2; /bin/sh /root/ht/live-qemu-guest.sh {select}) '
                        f'>{console} 2>&1 &\n',
    }
    for name, value in config.items():
        path = stage / name
        path.write_text(value)
        path.chmod(0o755 if name == 'etc/rc.local' else 0o644)
    ttys = stage / 'etc/ttys'
    text, count = re.subn(r'^(ttyu0\s+"[^"]+"\s+\S+)\s+onifconsole',
                          r'\1 off', ttys.read_text(), flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError('could not reserve ttyu0 for test output')
    ttys.write_text(text)
    ht = stage / 'root/ht'
    ht.mkdir(parents=True)
    for name in GUEST_FILES:
        shutil.copyfile(TESTS / name, ht / name)
        config[f'root/ht/{name}'] = None
    return config


def normalize_metalog(stage, output, config):
    records = {}
    for line in (stage / 'METALOG').read_text().splitlines():
        if line and not line.startswith('#'):
            records[line.split(' ', 1)[0]] = line
    for name in config:
        mode = '0755' if name.endswith(('rc.local', '.sh')) else '0644'
        records[f'./{name}'] = f'./{name} type=file uname=root gname=wheel mode={mode}'
    for base, directories, _ in os.walk(stage):
        for name in directories:
            path = Path(base) / name
            if path.is_symlink():
                continue
            key = './' + path.relative_to(stage).as_posix()
            if key not in records:
                mode = stat.S_IMODE(path.stat().st_mode)
                records[key] = f'{key} type=dir uname=root gname=wheel mode={mode:04o}'
    for key, line in records.items():
        path = stage / key.removeprefix('./')
        if 'type=file' in line and 'size=' in line and path.is_file():
            records[key] = re.sub(r'\bsize=\d+', f'size={path.stat().st_size}', line)
    output.write_text('#mtree 2.0\n' + '\n'.join(records[k] for k in sorted(records)) + '\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('output', type=Path)
    ap.add_argument('--arch', choices=('amd64', 'arm64', 'riscv64'), default='amd64')
    ap.add_argument('--obj', type=Path, required=True, help='MAKEOBJDIRPREFIX of the builds')
    ap.add_argument('--kernconf', default='GENERIC-DEBUG')
    ap.add_argument('--select', choices=('full', 'kyua'), default='full')
    ap.add_argument('--smp', type=int, default=4)
    ap.add_argument('--mem', default='4096')
    ap.add_argument('--timeout', type=int, default=7200)
    ap.add_argument('--image', type=Path, help='reuse an existing stage/image dir')
    args = ap.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to('/usr/obj') or out.exists():
        ap.error('output must be a new directory under /usr/obj')
    out.mkdir(parents=True)
    target = {'amd64': ('amd64', 'amd64'), 'arm64': ('arm64', 'aarch64'),
              'riscv64': ('riscv', 'riscv64')}[args.arch]
    stage = out / 'root'
    stage.mkdir()
    env = {**os.environ, 'MAKEOBJDIRPREFIX': str(args.obj)}
    common = ['make', f'-j{os.cpu_count() or 1}', f'TARGET={target[0]}',
              f'TARGET_ARCH={target[1]}', f'DESTDIR={stage}', 'NO_ROOT=yes',
              'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null', 'WITHOUT_LIB32=yes']
    run_logged(common + ['installworld'], out / 'installworld.log', env=env)
    run_logged(common + [f'KERNCONF={args.kernconf}', 'installkernel'],
               out / 'installkernel.log', env=env)
    run_logged(common + ['distribution'], out / 'distribution.log', env=env)
    config = stage_config(stage, args.arch, args.select)
    metalog = out / 'METALOG.sorted'
    normalize_metalog(stage, metalog, config)
    ufs, image = out / 'root.ufs', out / 'guest.img'
    run_logged(['makefs', '-t', 'ffs', '-s', '10g', '-F', str(metalog), '-o',
                'version=2', str(ufs), str(stage)], out / 'makefs.log')
    if args.arch == 'amd64':
        parts = ['-b', str(stage / 'boot/pmbr'), '-p', f"freebsd-boot:={stage / 'boot/gptboot'}"]
    else:
        esp = out / 'esp/EFI/BOOT'
        esp.mkdir(parents=True)
        (esp / ('BOOTAA64.EFI' if args.arch == 'arm64' else 'BOOTRISCV64.EFI')).write_bytes(
            (stage / 'boot/loader.efi').read_bytes())
        run_logged(['makefs', '-t', 'msdos', '-s', '64m', '-o',
                    'fat_type=32,sectors_per_cluster=1', str(out / 'esp.img'),
                    str(out / 'esp')], out / 'makefs-esp.log')
        parts = ['-p', f"efi:={out / 'esp.img'}"]
    run_logged(['mkimg', '-s', 'gpt', '-f', 'raw', *parts, '-p', f'freebsd-ufs:={ufs}',
                '-o', str(image)], out / 'mkimg.log')
    os.remove(ufs)
    shutil.rmtree(stage)	# keep the image only; the stage is large
    serial = out / 'serial.log'
    vars_image = out / 'edk2-riscv-vars.fd'
    if args.arch == 'riscv64':
        shutil.copyfile('/usr/local/share/qemu/edk2-riscv-vars.fd', vars_image)
    platform = {
        'amd64': ['-machine', 'q35', '-cpu', 'max,svm=on,npt=on'],
        'arm64': ['-machine', 'virt,gic-version=3', '-cpu', 'cortex-a57',
                  '-bios', '/usr/local/share/qemu/edk2-aarch64-code.fd'],
        'riscv64': ['-machine', 'virt,acpi=off,pflash0=pflash0,pflash1=pflash1',
                    '-cpu', 'rv64', '-blockdev',
                    'node-name=pflash0,driver=file,read-only=on,'
                    'filename=/usr/local/share/qemu/edk2-riscv-code.fd',
                    '-blockdev', f'node-name=pflash1,driver=file,filename={vars_image}'],
    }[args.arch]
    disk = 'virtio-blk-pci' if args.arch == 'amd64' else 'virtio-blk-device'
    qemu = f"/usr/local/bin/qemu-system-{ {'amd64': 'x86_64', 'arm64': 'aarch64', 'riscv64': 'riscv64'}[args.arch] }"
    command = [qemu, '-L', '/usr/local/share/qemu', '-accel', 'tcg,thread=multi', *platform,
               '-m', args.mem, '-smp', str(args.smp), '-drive',
               f'file={image},format=raw,if=none,id=root,snapshot=on', '-device',
               f'{disk},drive=root,bootindex=1', '-display', 'none', '-monitor', 'none',
               '-serial', f'file:{serial}', '-no-reboot']
    (out / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    qenv = {**os.environ, 'LD_LIBRARY_PATH': '/usr/obj/5BSD-hypertrace-qemu/hostlib'}
    error = None
    try:
        run_logged(command, out / 'qemu.log', timeout=args.timeout, env=qenv)
    except subprocess.TimeoutExpired:
        error = f'guest did not finish within {args.timeout} s'
    except subprocess.CalledProcessError as e:
        error = f'QEMU exited with status {e.returncode}'
    text = serial.read_text(errors='replace') if serial.exists() else ''
    checks = [{'check': m.group(1), 'verdict': m.group(2), 'detail': m.group(3).strip()}
              for m in re.finditer(r'^HTQ (\S+) (PASS|FAIL|INFO) ?(.*)$', text, re.M)]
    result = {'arch': args.arch, 'kernconf': args.kernconf, 'select': args.select,
              'done': 'HTQ-DONE' in text, 'panic': 'panic:' in text,
              'qemu_error': error, 'checks': checks,
              # vmm-attach is the nested-virtualization probe: recorded, not judged.
              'failed': [c['check'] for c in checks if c['verdict'] == 'FAIL' and
                         c['check'] != 'vmm-attach']}
    result['passed'] = result['done'] and not result['panic'] and not error and \
        not result['failed']
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('done', 'panic', 'qemu_error', 'failed',
                                             'passed')}, indent=2))
    for c in checks:
        print(f"{c['verdict']:5} {c['check']} {c['detail'][:120]}")


if __name__ == '__main__':
    main()
