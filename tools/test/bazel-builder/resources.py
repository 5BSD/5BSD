#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Measure and bound a command in a disposable FreeBSD qualification VM.

Samples are observations, not an IO benchmark or complete peak-memory accounting.
The caller supplies budgets before execution; exceeding them fails the run.
"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import time

MEMORY_KEYS = ('hw.pagesize', 'hw.physmem', 'vm.stats.vm.v_page_count',
    'vm.stats.vm.v_free_count', 'vm.stats.vm.v_inactive_count',
    'vm.stats.vm.v_active_count', 'vm.stats.vm.v_wire_count',
    'vm.stats.vm.v_laundry_count')
BUDGET_KEYS = {'max_physical_memory_bytes', 'max_elapsed_seconds',
    'min_free_memory_bytes', 'min_free_disk_bytes', 'max_used_disk_growth_bytes',
    'sample_interval_seconds'}


def budget_document(value):
    if not isinstance(value, dict) or set(value) != BUDGET_KEYS:
        raise ValueError('explicit complete resource budget required')
    for key, number in value.items():
        if type(number) not in (int, float) or not math.isfinite(number) or number < 0:
            raise ValueError('invalid resource budget: ' + key)
    for key in BUDGET_KEYS - {'max_elapsed_seconds', 'sample_interval_seconds'}:
        if type(value[key]) is not int:
            raise ValueError('byte budgets must be integers: ' + key)
    if not 1 <= value['max_physical_memory_bytes'] <= 24 * 1024**3:
        raise ValueError('qualification RAM budget must not exceed 24 GiB')
    if not 1 <= value['max_elapsed_seconds'] <= 86400:
        raise ValueError('elapsed budget must be between 1 and 86400 seconds')
    if not 0.1 <= value['sample_interval_seconds'] <= 30:
        raise ValueError('sample interval must be between 0.1 and 30 seconds')
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate resource budget field: ' + key)
        result[key] = value
    return result


def command_output(argv):
    return subprocess.check_output(argv, text=True, timeout=10,
        env={'PATH': '/sbin:/bin:/usr/sbin:/usr/bin', 'LC_ALL': 'C'})


def memory_sample(text):
    values = text.split()
    if len(values) != len(MEMORY_KEYS) or any(not v.isdigit() for v in values):
        raise ValueError('unexpected memory sysctl output')
    data = dict(zip(MEMORY_KEYS, map(int, values)))
    if data['hw.pagesize'] <= 0 or data['hw.physmem'] <= 0:
        raise ValueError('invalid memory geometry')
    return data


def sample(filesystems, devices, started):
    memory = memory_sample(command_output(['/sbin/sysctl', '-n', *MEMORY_KEYS]))
    disks = {}
    for path in filesystems:
        stat = os.statvfs(path)
        disks[str(path)] = {'total_bytes': stat.f_blocks * stat.f_frsize,
            'free_bytes': stat.f_bfree * stat.f_frsize,
            'available_bytes': stat.f_bavail * stat.f_frsize,
            'used_bytes': (stat.f_blocks - stat.f_bfree) * stat.f_frsize}
    io = command_output(['/usr/sbin/iostat', '-x', '-d', '-I', *devices])
    present = {line.split()[0] for line in io.splitlines() if line.split()}
    if not set(devices) <= present:
        raise ValueError('iostat omitted a selected measurement device')
    return {'elapsed_seconds': time.monotonic() - started, 'memory': memory,
        'filesystems': disks,
        'iostat_cumulative_raw': io}


def violations(row, initial, budget):
    failures = []
    memory = row['memory']
    if memory['hw.physmem'] > budget['max_physical_memory_bytes']:
        failures.append('physical-memory capacity exceeds budget')
    if memory['vm.stats.vm.v_free_count'] * memory['hw.pagesize'] < budget['min_free_memory_bytes']:
        failures.append('free-memory reserve below budget')
    if row['elapsed_seconds'] > budget['max_elapsed_seconds']:
        failures.append('elapsed time exceeds budget')
    for path, disk in row['filesystems'].items():
        if disk['available_bytes'] < budget['min_free_disk_bytes']:
            failures.append('available disk reserve below budget: ' + path)
        if disk['used_bytes'] - initial['filesystems'][path]['used_bytes'] > budget['max_used_disk_growth_bytes']:
            failures.append('disk usage growth exceeds budget: ' + path)
    return failures


def stop_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def supervise(command, output, filesystems, devices, budget):
    output.mkdir(mode=0o700)  # Exclusive: never overwrite previous evidence.
    report = {'format': 1, 'scope': 'disposable-vm-command-resources',
        'result': 'FAIL', 'command': command, 'budget': budget,
        'filesystems': list(map(str, filesystems)), 'devices': devices,
        'limitations': ['Samples can miss between-sample peaks.',
            'Free memory excludes reclaimable inactive pages; raw counts retained.',
            'Child maximum RSS is not aggregate process-tree or guest peak RSS.',
            'iostat is cumulative device activity, not a latency-distribution benchmark.']}
    pid = None
    waited = False
    started = time.monotonic()
    try:
        with (output / 'samples.jsonl').open('x') as samples:
            initial = sample(filesystems, devices, started)
            samples.write(json.dumps(initial) + '\n'); samples.flush()
            errors = violations(initial, initial, budget)
            if errors:
                raise ValueError('; '.join(errors))
            with (output / 'stdout').open('xb') as stdout, (output / 'stderr').open('xb') as stderr:
                ready_read, ready_write = os.pipe()
                pid = os.fork()
                if pid == 0:
                    try:
                        os.close(ready_read)
                        os.setsid()
                        os.write(ready_write, b'1'); os.close(ready_write)
                        os.dup2(stdout.fileno(), 1); os.dup2(stderr.fileno(), 2)
                        with open('/dev/null', 'rb') as source:
                            os.dup2(source.fileno(), 0)
                        os.execvp(command[0], command)
                    except Exception:
                        os._exit(127)
                os.close(ready_write)
                with os.fdopen(ready_read, 'rb') as ready:
                    if ready.read(1) != b'1':
                        raise RuntimeError('command process-group setup failed')
                while True:
                    done, status, usage = os.wait4(pid, os.WNOHANG)
                    if done:
                        waited = True
                    row = sample(filesystems, devices, started)
                    samples.write(json.dumps(row) + '\n'); samples.flush()
                    errors = violations(row, initial, budget)
                    if errors:
                        raise ValueError('; '.join(errors))
                    if done:
                        break
                    time.sleep(min(budget['sample_interval_seconds'],
                        max(0.01, budget['max_elapsed_seconds'] - row['elapsed_seconds'])))
                report.update(exit_status=os.waitstatus_to_exitcode(status),
                    child_user_cpu_seconds=usage.ru_utime,
                    child_system_cpu_seconds=usage.ru_stime,
                    child_max_rss_kib=usage.ru_maxrss,
                    child_block_input_operations=usage.ru_inblock,
                    child_block_output_operations=usage.ru_oublock)
                if report['exit_status'] != 0:
                    raise ValueError('measured command failed')
                report['result'] = 'PASS'
    except Exception as error:
        report['error'] = str(error)
    finally:
        if pid is not None:
            stop_group(pid)  # Also remove surviving descendants on normal exit.
            if not waited:
                _, status, usage = os.wait4(pid, 0)
                report.update(terminated_exit_status=os.waitstatus_to_exitcode(status),
                    child_user_cpu_seconds=usage.ru_utime,
                    child_system_cpu_seconds=usage.ru_stime,
                    child_max_rss_kib=usage.ru_maxrss,
                    child_block_input_operations=usage.ru_inblock,
                    child_block_output_operations=usage.ru_oublock)
        report['elapsed_seconds'] = time.monotonic() - started
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-vm', action='store_true', required=True)
    parser.add_argument('--budget', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--filesystem', type=Path, action='append', required=True)
    parser.add_argument('--device', action='append', required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if os.geteuid() != 0 or command_output(['/sbin/sysctl', '-n', 'kern.vm_guest']).strip() == 'none':
        parser.error('requires root in a disposable VM')
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or not os.path.isabs(command[0]):
        parser.error('explicit absolute command executable required')
    if any(not re.fullmatch(r'vtbd[0-9]+', device) for device in args.device):
        parser.error('explicit virtio measurement device names required')
    for path in args.filesystem:
        if not path.is_dir() or path.resolve(strict=True) != path:
            parser.error('measurement filesystems must be canonical absolute directories')
    budget = budget_document(json.loads(args.budget.read_text(), object_pairs_hook=unique_object))
    result = supervise(command, args.output, args.filesystem, args.device, budget)
    if result['result'] != 'PASS':
        raise SystemExit(result.get('error', 'resource qualification failed'))


if __name__ == '__main__':
    main()
