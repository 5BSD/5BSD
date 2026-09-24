#!/usr/bin/env python3
"""Run the amd64 ptrace/socket/multicast regression image without queue suites."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time

SINGLE = {
    'PTRACE': 'fp_read fp_write fp_setregset fp_bad_mxcsr gpr_read gpr_write gpr_partial gpr_rax gpr_bad_base lengths faults unknown xstate_read protected_memory bounds permissions unprivileged gpr_fault_progress tls_write thread_target repeated',
    'PTRACE_OPTIONS': 'linux_ptrace_lifecycle linux_ptrace_user linux_ptrace_metadata linux_ptrace_sigmask linux_proc_task linux_ptrace_kill_native user_unprivileged',
    'COOKIE': 'identity lifetime rights bounds faults churn unprivileged caps',
}
MATRIX = {
    'XSTATE': 'roundtrip write_resume lengths invalid init_state faults metadata',
    'MCAST': 'mixed mixed_delivery mixed_churn roundtrip replace leave lengths invalid faults lifetime duplicates delivery interfaces churn',
    'PEER': 'inet4 inet6 local pathname state faults lifetime',
    'EVENT': 'exec fork vfork clone exit signal vfork_done selective isolation waitid',
    'PENDING': 'shared thread standard validation faults reattach lifetime',
    'TRANSITIONS': 'transitions transition_delivery',
}
NATIVE = ('PTRACE_NATIVE', 'PTRACE_CAPMODE', 'MCAST_NATIVE', 'PEER_CAPS', 'EXIT_NATIVE')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--firmware-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    command = [str(args.qemu), '-L', str(args.firmware_dir), '-accel', 'tcg,thread=multi',
               '-m', '1024', '-smp', '2', '-nic', 'user,model=virtio-net-pci,restrict=on',
               '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot',
               '-machine', 'q35', '-cpu', 'max', '-drive',
               f'file={args.image.resolve()},format=raw,if=virtio,snapshot=on']
    record = {'command': command, 'started': time.time(), 'passed': False}
    expected = set()
    for n in (1, 2, 3):
        for tag, names in SINGLE.items():
            expected.update(f'GATE_{tag} {n} {name} 0' for name in names.split())
        for tag, names in MATRIX.items():
            expected.update(f'GATE_{tag} {n} {user} {name} 0'
                            for user in ('root', 'unprivileged') for name in names.split())
        expected.update(f'GATE_{tag} {n} 0' for tag in NATIVE)
    try:
        record['qemu_version'] = subprocess.check_output([str(args.qemu), '--version'], text=True)
        with (args.output / 'amd64.console.log').open('wb') as log:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=args.timeout, check=False)
        record['exit_code'] = result.returncode
        text = (args.output / 'amd64.console.log').read_text(errors='replace').replace('\r', '')
        tags = '|'.join(SINGLE.keys() | MATRIX.keys() | set(NATIVE))
        rows = re.findall(rf'^GATE_(?:{tags}) .+$', text, re.M)
        diagnostics = re.findall(r'panic:|KDB: enter|lock order reversal|non-sleepable locks held|'
                                 r'Fatal trap|use-after-free|acquiring duplicate lock', text, re.I)
        record.update(expected_count=len(expected), actual_count=len(rows), records=rows,
                      missing=sorted(expected - set(rows)), unexpected=sorted(set(rows) - expected),
                      diagnostics=diagnostics)
        markers = ('GATE_PTRACE_DONE', 'GATE_COOKIE_DONE', 'GATE_XSTATE_MCAST_DONE',
                   'GATE_PEER_EVENTS_DONE', 'GATE_SIGNAL_MODES_DONE', 'SIGNAL_MODES_REGRESSION_DONE',
                   'all pools are healthy', 'All buffers synced.', 'Powering system off')
        record['missing_markers'] = [marker for marker in markers if marker not in text]
        record['passed'] = (result.returncode == 0 and len(rows) == len(expected)
                            and set(rows) == expected and not diagnostics
                            and not record['missing_markers'])
    except (OSError, subprocess.SubprocessError) as exc:
        record['error'] = str(exc)
    record['finished'] = time.time()
    (args.output / 'results.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({key: record.get(key) for key in
                      ('passed', 'expected_count', 'actual_count', 'missing', 'unexpected', 'diagnostics', 'error')}, indent=2))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
