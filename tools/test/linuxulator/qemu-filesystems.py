#!/usr/bin/env python3
"""Run the staged Linux filesystem ABI guest and validate its complete inventory."""
import argparse
import json
import re
import subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--image', required=True)
p.add_argument('--qemu', default='qemu-system-x86_64')
p.add_argument('--firmware-dir')
p.add_argument('--output', required=True)
p.add_argument('--timeout', type=int, default=900)
p.add_argument('--cpus', type=int, default=2)
a = p.parse_args()
out = Path(a.output)
out.mkdir(parents=True, exist_ok=True)
cmd = [a.qemu]
if a.firmware_dir:
    cmd += ['-L', a.firmware_dir]
cmd += ['-accel', 'tcg,thread=multi', '-m', '1024', '-smp', str(a.cpus),
        '-nic', 'user,model=virtio-net-pci,restrict=on', '-display', 'none',
        '-monitor', 'none', '-serial', 'stdio', '-no-reboot', '-machine', 'q35',
        '-cpu', 'max', '-drive',
        f'file={Path(a.image).resolve()},format=raw,if=virtio,snapshot=on']
timed_out = False
with (out / 'console.log').open('wb') as log:
    child = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log,
                             stderr=subprocess.STDOUT)
    try:
        child.wait(timeout=a.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        child.kill()
        child.wait()
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
passed = (not timed_out and child.returncode == 0 and not diagnostics
          and len(records) == len(expected) and set(records) == expected
          and len(links) == len(expected_links) and set(links) == expected_links
          and jails == [('1', '0'), ('2', '0'), ('3', '0')]
          and reloads == [('1', '0'), ('2', '0'), ('3', '0')]
          and '\nFILESYSTEMS_DONE\n' in s and 'all pools are healthy' in s
          and 'All buffers synced.' in s and 'Powering system off' in s)
result = dict(passed=passed, command=cmd, exit_code=child.returncode,
              timed_out=timed_out, records=records, links=links, jails=jails, reloads=reloads,
              diagnostics=diagnostics)
(out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
raise SystemExit(0 if passed else 1)
