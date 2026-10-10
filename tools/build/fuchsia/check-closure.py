#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Verify that every libfidl_bsd archive member is reachable from consumers.

Resolves undefined symbols of the runtime, C binding and conformance test
objects (and any extra objects given) against the archive, as a static link
would, and fails if a member is never needed. Keep the runtime source lists
limited to the proven codec closure.
"""
import argparse
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-fidl-runtime'))
p.add_argument('extra', type=Path, nargs='*', help='additional consumer objects')
a = p.parse_args()
DEFINED = set('TDBRVWCui')


def symbols(path):
    output = subprocess.run(['nm', '-P', '-g', str(path)], check=True,
                            capture_output=True, text=True).stdout
    result = {}
    current = str(path)
    for line in output.splitlines():
        if line.endswith(':') and ' ' not in line:
            current = line[:-1]
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        defined, undefined = result.setdefault(current, (set(), set()))
        if fields[1] == 'U':
            undefined.add(fields[0])
        elif fields[1] in DEFINED:
            defined.add(fields[0])
    return result


archive = a.obj / 'libfidl_bsd.a'
members = symbols(archive)
consumers = [x for pattern in ('runtime_test-*.o', 'c_binding_test-*.o', 'conformance_test-*.o')
             for x in a.obj.glob(pattern)] + a.extra
if len(consumers) < 3:
    raise SystemExit('missing consumer objects; run build-runtime.py --test first')
needed, provided = set(), set()
for consumer in consumers:
    for defined, undefined in symbols(consumer).values():
        needed |= undefined
        provided |= defined
pulled = set()
changed = True
while changed:
    changed = False
    for member, (defined, undefined) in members.items():
        if member not in pulled and (needed - provided) & defined:
            pulled.add(member)
            needed |= undefined
            provided |= defined
            changed = True
unused = sorted(set(members) - pulled)
if unused:
    raise SystemExit('unreachable libfidl_bsd members: ' + ' '.join(unused))
print('%d libfidl_bsd archive members, all reachable from %d consumer objects: PASS'
      % (len(members), len(consumers)), flush=True)
