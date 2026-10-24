# SPDX-License-Identifier: BSD-2-Clause
"""Sample the explicitly launched QEMU process; never infer complete peak usage."""
import json
import math
import re
import subprocess


def cpu_seconds(value):
    match = re.fullmatch(r'(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)', value)
    if match is None:
        raise ValueError('unsupported ps CPU duration')
    days, hours, minutes, seconds = match.groups()
    minutes, seconds = int(minutes), float(seconds)
    if minutes >= 60 and hours is not None or seconds >= 60:
        raise ValueError('invalid ps CPU duration')
    return int(days or 0)*86400 + int(hours or 0)*3600 + minutes*60 + seconds


def parse_process(text, pid):
    fields = text.split()
    if len(fields) != 4 or any(not x.isdigit() for x in fields[:3]) or int(fields[0]) != pid:
        raise ValueError('unexpected ps process resource record')
    return {'pid': pid, 'rss_bytes': int(fields[1])*1024,
            'virtual_bytes': int(fields[2])*1024, 'cpu_seconds': cpu_seconds(fields[3])}


def sample_process(pid):
    result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'pid=', '-o', 'rss=',
        '-o', 'vsz=', '-o', 'time='], capture_output=True, text=True, timeout=5,
        env={'PATH':'/sbin:/bin:/usr/sbin:/usr/bin', 'LC_ALL':'C'})
    if result.returncode == 1 and not result.stdout.strip() and not result.stderr.strip():
        return None  # Caller must confirm process exit; absence alone is not success.
    if result.returncode or result.stderr:
        raise ValueError('ps resource observation failed: ' + result.stderr.strip())
    return parse_process(result.stdout, pid)


class HostMonitor:
    def __init__(self, path, max_rss_mib):
        if type(max_rss_mib) is not int or not 0 <= max_rss_mib <= 65536:
            raise ValueError('host RSS budget must be 0..65536 MiB')
        self.stream = path.open('x')
        self.limit = max_rss_mib*1024**2
        self.count = 0
        self.maximum = 0
        self.last_cpu = 0

    def observe(self, pid, elapsed):
        if not math.isfinite(elapsed) or elapsed < 0:
            raise ValueError('invalid resource sample time')
        row = sample_process(pid)
        if row is None:
            return False
        row['elapsed_seconds'] = elapsed
        self.stream.write(json.dumps(row)+'\n'); self.stream.flush()
        self.count += 1
        self.maximum = max(self.maximum, row['rss_bytes'])
        self.last_cpu = row['cpu_seconds']
        if self.limit and row['rss_bytes'] > self.limit:
            raise ValueError('QEMU host RSS exceeds explicit budget')
        return True

    def close(self):
        self.stream.close()
        return {'scope':'sampled QEMU process only; excludes between-sample peaks and host page cache',
                'samples':self.count,'max_observed_rss_bytes':self.maximum,
                'last_observed_cpu_seconds':self.last_cpu,
                'max_rss_budget_bytes':self.limit or None,
                'budget_enforced':bool(self.limit)}
