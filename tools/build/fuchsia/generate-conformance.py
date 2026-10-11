#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Generate upstream GIDL conformance tests for the native C++ codec.

The pinned upstream suite is compiled unchanged. Resource declarations and
protocols are removed only from the IR used to generate native bindings:
non-resource FIDL types cannot contain handles, and GIDL guards every
resource or handle case with __Fuchsia__, so those cases are compiled out.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--src', type=Path, default=Path('/usr/src'))
p.add_argument('--tools', type=Path, default=Path('/usr/obj/5bsd-fidl'))
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
suite = a.src / 'contrib/fuchsia/src/tests/fidl/conformance_suite'
out = a.out
out.mkdir(parents=True, exist_ok=True)
fidl = sorted(suite.glob('*.test.fidl'))
gidl = sorted(suite.glob('*.gidl'))
if not fidl or not gidl:
    raise SystemExit('missing upstream conformance suite: ' + str(suite))

# Upstream BUILD.gn: available test:2 and fuchsia:HEAD, versioned test:1.
full = out / 'conformance.json'
cmd = [str(a.tools / 'fidlc'), '--json', str(full), '--available', 'test:2',
       '--available', 'fuchsia:HEAD', '--versioned', 'test:1',
       '--files', str(a.src / 'lib/libfidl/tests/zx.fidl'), '--files']
subprocess.run(cmd + [str(f) for f in fidl], check=True)


def has_handle(value):
    if isinstance(value, dict):
        if value.get('kind_v2') in ('handle', 'endpoint'):
            return True
        return any(has_handle(v) for v in value.values())
    if isinstance(value, list):
        return any(has_handle(v) for v in value)
    return False


ir = json.loads(full.read_text())
dropped = set()
for key in ('struct_declarations', 'table_declarations', 'union_declarations'):
    dropped |= {d['name'] for d in ir[key] if d.get('resource')}
    ir[key] = [d for d in ir[key] if not d.get('resource')]
for key in ('protocol_declarations', 'service_declarations',
            'experimental_resource_declarations'):
    dropped |= {d['name'] for d in ir[key]}
    ir[key] = []
for key in ('alias_declarations', 'new_type_declarations'):
    dropped |= {d['name'] for d in ir[key] if has_handle(d)}
    ir[key] = [d for d in ir[key] if not has_handle(d)]
if has_handle({k: v for k, v in ir.items() if k.endswith('_declarations')}):
    raise SystemExit('host conformance IR still contains handles')
ir['declaration_order'] = [n for n in ir['declaration_order'] if n not in dropped]
ir['declarations'] = {n: v for n, v in ir['declarations'].items() if n not in dropped}
host = out / 'conformance-host.json'
host.write_text(json.dumps(ir))

subprocess.run([sys.executable, str(a.src / 'tools/build/fuchsia/generate-bsd.py'),
                '--json', str(host), '--root', str(out / 'gen')], check=True)
subprocess.run([str(a.tools / 'gidl'), '-json', str(full), '-language', 'cpp',
                '-type', 'conformance', '-out', str(out / 'conformance_test.cc')]
               + [str(g) for g in gidl], check=True)
(out / 'summary.json').write_text(json.dumps({
    'fidl_files': len(fidl), 'gidl_files': len(gidl),
    'dropped_resource_or_protocol_declarations': len(dropped),
}, indent=2) + '\n')
