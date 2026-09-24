#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Crash/reboot private ZFS overlays; never change the backing images or host pool."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time


def run(cmd, log, marker, timeout, cut):
    with log.open('wb') as stream:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=stream,
                                stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                data = log.read_text(errors='replace').replace('\r', '')
                if 'Enter full pathname of shell or RETURN for /bin/sh:' in data:
                    raise RuntimeError(f'{log}: guest entered recovery shell')
                if 'LINUXULATOR_GATE_BEGIN' in data.splitlines():
                    raise RuntimeError(f'{log}: image booted normal gate instead of crash script')
                if marker in data.splitlines():
                    if cut:
                        proc.kill()  # Only the child created above.
                    return proc.wait(timeout=60)
                if proc.poll() is not None:
                    raise RuntimeError(f'{log}: exit {proc.returncode} before {marker}')
                time.sleep(0.1)
            raise TimeoutError(f'{log}: missing {marker}')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gate-results', type=Path, required=True,
                        help='Completed normal gate JSON supplying matching QEMU commands')
    parser.add_argument('--images', type=Path, required=True,
                        help='Images booting guest-rwf-durability.sh, named amd64.img/arm64.img')
    parser.add_argument('--qemu-img', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    args.output.mkdir()  # Never reuse a prior crash image.
    gates = json.loads(args.gate_results.read_text())
    results = {}
    for arch in ('amd64', 'arm64'):
        if not gates[arch]['passed']:
            raise RuntimeError(f'{arch}: normal gate must pass first')
        backing = (args.images / f'{arch}.img').resolve()
        overlay = (args.output / f'{arch}.qcow2').resolve()
        subprocess.run([str(args.qemu_img), 'create', '-f', 'qcow2', '-F', 'raw',
                        '-b', str(backing), str(overlay)], check=True)
        cmd = list(gates[arch]['command'])
        drives = [i + 1 for i, word in enumerate(cmd) if word == '-drive']
        if len(drives) != 1:
            raise RuntimeError('Expected exactly one guest disk')
        cmd[drives[0]] = f'file={overlay},format=qcow2,if=virtio,cache=writeback'
        record = results[arch] = {'command': cmd, 'backing': str(backing), 'passed': False}
        try:
            cutlog = args.output / f'{arch}-cut.console.log'
            checklog = args.output / f'{arch}-reboot.console.log'
            record['cut_exit'] = run(cmd, cutlog, 'RWF_DURABILITY_CUT_NOW', args.timeout, True)
            record['reboot_exit'] = run(cmd, checklog, 'RWF_DURABILITY_DONE', args.timeout, False)
            cut = cutlog.read_text(errors='replace').replace('\r', '')
            check = checklog.read_text(errors='replace').replace('\r', '')
            record['passed'] = (record['cut_exit'] == -9 and record['reboot_exit'] == 0
                                and all(f'RWF_DURABILITY_WRITTEN {abi}' in cut.splitlines()
                                        and f'RWF_DURABILITY_VERIFIED {abi}' in check.splitlines()
                                        for abi in ('native', 'linux'))
                                and 'RWF_DURABILITY_ROOT_ZFS' in cut.splitlines()
                                and 'RWF_DURABILITY_ROOT_ZFS' in check.splitlines()
                                and not re.search(r'panic:|lock order reversal|Fatal trap', cut + check))
        except Exception as exc:
            record['error'] = str(exc)
        (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        print(arch, 'PASS' if record['passed'] else 'FAIL', flush=True)
    return 0 if all(r['passed'] for r in results.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
