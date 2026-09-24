#!/usr/bin/env python3
"""Run the Linux64 proc/topology guest plus the complete filesystem inventory."""
import argparse
import json
import re
import subprocess
import time
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--image', required=True)
p.add_argument('--qemu', default='qemu-system-x86_64')
p.add_argument('--firmware-dir')
p.add_argument('--output', required=True)
p.add_argument('--stress', action='store_true', help='require security and concurrent stress inventory')
p.add_argument('--timeout', type=int, default=900)
p.add_argument('--topology', default='4,sockets=1,cores=2,threads=2')
p.add_argument('--cpu-model', default='max,vendor=GenuineIntel')
a = p.parse_args()
out = Path(a.output)
out.mkdir(parents=True, exist_ok=True)
cmd = [a.qemu]
if a.firmware_dir:
    cmd += ['-L', a.firmware_dir]
cmd += ['-accel', 'tcg,thread=multi', '-m', '1024', '-smp', a.topology,
        '-nic', 'user,model=virtio-net-pci,restrict=on', '-display', 'none',
        '-monitor', 'none', '-serial', 'stdio', '-no-reboot', '-machine', 'q35',
        '-cpu', a.cpu_model, '-drive',
        f'file={Path(a.image).resolve()},format=raw,if=virtio,snapshot=on']
timed_out = False
with (out / 'console.log').open('wb') as log:
    child = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log,
                             stderr=subprocess.STDOUT)
    deadline = time.monotonic() + a.timeout
    while child.poll() is None:
        text = (out / 'console.log').read_text(errors='replace')
        if re.search(r'panic:|Fatal trap|lock order reversal|non-sleepable locks held', text):
            child.kill()
            child.wait()
            break
        if time.monotonic() >= deadline:
            timed_out = True
            child.kill()
            child.wait()
            break
        time.sleep(0.5)
s = (out / 'console.log').read_text(errors='replace').replace('\r', '')
records = re.findall(r'^FS_(ROOT|UNPRIV) (\d+) (\w+) (\d+)$', s, re.M)
expected = {(u, str(i), c, '0') for i in range(1, 4)
            for u, cases in [('ROOT', ['mount', 'invalid', 'limits',
                                       'sysfs_mount', 'cpu', 'network', 'options', 'inode',
                                       'readonly', 'bind', 'faults', 'permissions',
                                       'stream', 'counters', 'many', 'race']),
                             ('UNPRIV', ['cpu', 'network', 'stream', 'counters'])] for c in cases}
links = re.findall(r'^FS_LINK (\d+) (\w+) (\d+)$', s, re.M)
expected_links = {(str(i), c, '0') for i in range(1, 4) for c in
                  ['down', 'up', 'old', 'renamed', 'gone', 'churn', 'host_after_jail']}
jails = re.findall(r'^FS_JAIL (\d+) (\d+)$', s, re.M)
reloads = re.findall(r'^FS_RELOAD (\d+) (\d+)$', s, re.M)
diagnostics = re.findall(r'^.*(?:panic:|Fatal trap|lock order reversal|'
                         r'non-sleepable locks held).*$', s, re.M)
proc_records = re.findall(r'^PROC_VIEW (\d+) (\w+) (\w+) (\d+)$', s, re.M)
expected_proc = {(str(i), u, c, '0') for i in range(1, 4)
                 for u in ['root', 'unprivileged']
                 for c in ['names', 'memory', 'filesystems', 'topology', 'threads', 'churn', 'comm', 'taskfiles', 'statfields', 'descriptors', 'mountids', 'fdchurn', 'mounttree', 'fdpermissions', 'fdresolve', 'fdexec', 'tasklinks', 'fdextra', 'fdscale', 'sockettables']}
passed = (len(proc_records) == len(expected_proc) and set(proc_records) == expected_proc
          and re.findall(r'^FUSE_CLIENT (\w+) (\d+)$', s, re.M) ==
          [('base', '0'), ('default_permissions', '0'), ('allow_other', '0')]
          and 'FUSE_CLIENT_DONE' in s and 'FUSE_OPTIONS_PASS' in s
          and 'COMMON_RELOAD_PASS' in s
          and 'NATIVE_PROC_PASS' in s and 'PROC_RELOAD_PASS' in s
          and not timed_out and child.returncode == 0 and not diagnostics
          and len(records) == len(expected) and set(records) == expected
          and len(links) == len(expected_links) and set(links) == expected_links
          and jails == [('1', '0'), ('2', '0'), ('3', '0')]
          and reloads == [('1', '0'), ('2', '0'), ('3', '0')]
          and '\nPROC_VIEWS_DONE\n' in s and 'all pools are healthy' in s
          and 'All buffers synced.' in s and 'Powering system off' in s)
stress_records = re.findall(r'^PROC_STRESS (\d+) (\w+) (\w+) (\d+) (\d+)$', s, re.M)
force_records = re.findall(r'^PROC_FORCE (\d+) (\d+)$', s, re.M)
if a.stress:
    expected_stress = {(str(r), u, c, str(i), '0') for r in range(1, 9)
                       for u in ['root', 'unprivileged']
                       for c in ['fdchurn', 'churn', 'fdpermissions', 'descriptors', 'fdextra', 'fdscale', 'sockettables', 'tasklinks']
                       for i in range(1, 5)}
    passed = (passed and len(stress_records) == len(expected_stress)
              and set(stress_records) == expected_stress
              and re.findall(r'^PROC_NET_JAIL (\d+) (\d+)$', s, re.M) ==
              [(str(i), '0') for i in range(1, 4)]
              and force_records == [(str(i), '0') for i in range(1, 9)]
              and re.findall(r'^PROC_NATIVE_(\w+)_PASS$', s, re.M) ==
              ['JAIL', 'CREDENTIAL', 'CAPRIGHTS', 'OFFSET']
              and re.findall(r'^PROC_EXEC_STRESS (\d+) (\d+)$', s, re.M) ==
              [(str(i), '0') for i in range(1, 65)]
              and '\nPROC_STRESS_DONE\n' in s)
result = dict(passed=passed, stress_records=stress_records, force_records=force_records, command=cmd, exit_code=child.returncode,
              timed_out=timed_out, proc_records=proc_records, records=records, links=links, jails=jails, reloads=reloads,
              diagnostics=diagnostics)
(out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
raise SystemExit(0 if passed else 1)
