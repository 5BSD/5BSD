#!/usr/bin/env python3
"""Verify the complete disposable PF smoke log after observing QEMU exit."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

p = argparse.ArgumentParser()
p.add_argument('directory', type=Path)
p.add_argument('tag')
p.add_argument('--qemu-exit', required=True, type=int)
p.add_argument('--bridge', action='store_true', help='require bridge retirement regression')
a = p.parse_args()
logfile = a.directory / (a.tag + '-console.log')
raw = logfile.read_bytes()
s = raw.decode(errors='replace').replace('\r', '')
manifest = json.loads((a.directory / (a.tag + '-manifest.json')).read_text())
errors = []
if a.qemu_exit != 0:
    errors.append('QEMU did not exit successfully')
for marker in ['PF_SMOKE_BEGIN', 'PF_NETWORK_PASS', 'DNCTL_RESULT 0',
               'PF_TEST_RESULT 0', 'PF_SMOKE_DONE', 'PF_SMOKE_EXIT 0',
               'All buffers synced.', 'all pools are healthy']:
    if s.count(marker) != 1:
        errors.append('missing or duplicate marker: ' + marker)
if not re.search(r"kldload: can't load ipfw: No such file or directory", s):
    errors.append('missing IPFW load rejection')
if re.search(r'^panic:|UNEXPECTED_IPFW_|Fatal trap', s, re.M):
    errors.append('kernel or IPFW isolation failure')
actual = re.findall(r'^SHA256 \((.+)\) = ([0-9a-f]{64})$', s, re.M)
if len(actual) != len(manifest) or dict(actual) != manifest:
    errors.append('runtime artifact hashes differ from manifest')
expected = ['dnctl_test:syntax', 'dnctl_test:rejects', 'dnctl_test:config_file',
            'pass_block:enable_disable', 'pass_block:v4', 'pass_block:v6',
            'match:dummynet', 'nat:dummynet_mask', 'pflog:matches',
            'limiters:show_aliases']
if a.bridge:
    expected.append('pass_block:bridge_filter')
results = re.findall(r'^===> ([^\n]+)\nResult:\s+([^\n]+)', s, re.M)
if Counter(x[0] for x in results) != Counter(expected):
    errors.append('missing, duplicate or unexpected ATF cases')
for case, result in results:
    if result != 'passed':
        errors.append(case + ': ' + result)
out = {'passed': not errors, 'qemu_exit': a.qemu_exit,
       'log_sha256': hashlib.sha256(raw).hexdigest(),
       'verified_artifacts': len(actual), 'cases': dict(results), 'errors': errors}
(a.directory / (a.tag + '-results.json')).write_text(json.dumps(out, indent=2) + '\n')
print(json.dumps(out, indent=2))
raise SystemExit(bool(errors))
