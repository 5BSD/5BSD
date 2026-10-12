# SPDX-License-Identifier: BSD-2-Clause
"""Emit versioned build-plan records without interpreting argument contents."""
import json
import sys

kind, *values = sys.argv[1:]
record = {'schema': 'org.5bsd.build-plan.v1', 'record': kind}
if kind == 'request':
    names = ('action', 'target', 'target_arch', 'kernel', 'board', 'build_profile',
             'signing', 'jobs', 'build_backend', 'hardware_backend')
    if len(values) != len(names):
        raise SystemExit('invalid request record')
    record.update(zip(names, values))
    record['jobs'] = int(record['jobs'])
elif kind == 'step':
    if len(values) < 3:
        raise SystemExit('invalid step record')
    number, name, *argv = values
    record.update(number=int(number), name=name, argv=argv)
else:
    raise SystemExit('unknown plan record')
print(json.dumps(record, ensure_ascii=True, separators=(',', ':')))
