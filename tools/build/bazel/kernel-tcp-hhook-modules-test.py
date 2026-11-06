# SPDX-License-Identifier: BSD-2-Clause
"""Check actual generated kernel options against native module/install inventories."""
import argparse
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser(description=__doc__)
for name in ['header', 'cc', 'helper', 'helper-install']:
    parser.add_argument('--'+name, type=Path, required=True)
parser.add_argument('--expected', choices=['yes', 'no'], required=True)
args = parser.parse_args()
enabled = bool(re.search(r'^#define\s+TCP_HHOOK\b', args.header.read_text(), re.M))
assert enabled == (args.expected == 'yes'), 'generated header disagrees with requested setting'
base = {'cc_newreno.ko', 'cc_cubic.ko', 'cc_dctcp.ko', 'cc_htcp.ko'}
hooks = {'cc_cdg.ko', 'cc_chd.ko', 'cc_hd.ko', 'cc_vegas.ko'}

def members(path):
    data = json.loads(path.read_text())
    assert data['format'] == 1
    names = [Path(r['runtime']).name for r in data['modules']]
    assert len(names) == len(set(names)), 'duplicate serialized module member'
    return set(names)

cc = members(args.cc)
helper = members(args.helper)
assert cc == base | (hooks if enabled else set()), 'CC selection disagrees with actual TCP_HHOOK header'
assert helper == ({'h_ertt.ko'} if enabled else set()), 'helper selection disagrees with actual TCP_HHOOK header'
installation = json.loads(args.helper_install.read_text())
assert installation['format'] == 1
if enabled:
    expected = {Path(row[key]).name
                for row in json.loads(args.helper.read_text())['modules']
                for key in ('runtime', 'debug') if row[key] is not None}
    assert len(installation['files']) == len(expected)
    assert {Path(r['destination']).name for r in installation['files']} == expected
else:
    assert installation['files'] == [], 'disabled helper has installed payload'
print('KERNEL_TCP_HHOOK_MODULES='+json.dumps(dict(enabled=enabled,cc=sorted(cc),helper=sorted(helper)),sort_keys=True))
