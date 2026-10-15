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
p.add_argument('--normal-boot', action='store_true', help='require expanded startup/consumer/ABI tests')
p.add_argument('--followup-only', action='store_true', help='require IPv4/IPv6, SNMP and common shaper follow-up cases')
a = p.parse_args()
if a.followup_only and (a.normal_boot or a.bridge):
    p.error('follow-up-only mode is separate from the complete startup gate')
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
    if a.followup_only and marker == 'DNCTL_RESULT 0':
        continue
    if s.count(marker) != 1:
        errors.append('missing or duplicate marker: ' + marker)
if a.normal_boot:
    for marker in ['PF_NORMAL_BOOT_PASS', 'COMMON_TEST_RESULT 0']:
        if s.count(marker) != 1:
            errors.append('missing or duplicate marker: ' + marker)
if a.followup_only and s.count('COMMON_TEST_RESULT 0') != 1:
    errors.append('missing or duplicate marker: COMMON_TEST_RESULT 0')
# kldload ipfw fails either because the module is gone or because the
# capability plane denies late loads; the guest checks both and the absence
# of ipfw.ko, then prints PF_IPFW_ABSENT.
if s.count('PF_IPFW_ABSENT') != 1:
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
if a.normal_boot:
    expected += ['flow_abi_test:flow_layout', 'pass_block:blocklist_helpers',
                 'snmp:retired_bridge_filter', 'dummynet:pf_pipe', 'dummynet:pf_pipe_v6',
                 'dummynet:pf_codel', 'dummynet:pf_wf2q_heap']
if a.bridge or a.normal_boot:
    expected.append('pass_block:bridge_filter')
if a.followup_only:
    expected = ['pass_block:v4', 'pass_block:v6',
                'snmp:retired_bridge_filter', 'dummynet:pf_pipe',
                'dummynet:pf_pipe_v6', 'dummynet:pf_codel',
                'dummynet:pf_wf2q_heap']
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
