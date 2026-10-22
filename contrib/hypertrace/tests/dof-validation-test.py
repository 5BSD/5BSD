#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Mutation checks for the offline DOF oracle using a real compiler artifact."""
import json
from pathlib import Path
import struct
import sys
from dof_validation import validate_dof

original = Path(sys.argv[1]).read_bytes()
validate_dof(original)
assert original[5] == 1, 'mutation fixture requires little-endian DOF'
secoff = struct.unpack_from('<Q', original, 32)[0]
secsize, count = struct.unpack_from('<II', original, 24)
sections = [struct.unpack_from('<IIIIQQ', original, secoff+i*secsize) for i in range(count)]
ecb = next(i for i,s in enumerate(sections) if s[0] == 3)
probe = next(i for i,s in enumerate(sections) if s[0] == 4)
string = next(i for i,s in enumerate(sections) if s[0] == 8)
mutations = [
    ('magic', 0, 'I', 0, 'invalid DOF header'),
    ('encoding', 5, 'B', 0, 'invalid model or encoding'),
    ('header-size', 20, 'I', 0, 'undersized headers'),
    ('section-size', 24, 'I', 0, 'undersized headers'),
    ('file-size', 48, 'Q', len(original)+1, 'invalid file/load sizes'),
    ('table-range', 32, 'Q', len(original), 'section table outside loadable data'),
    ('header-pad', 56, 'Q', 1, 'nonzero header padding'),
    ('section-align', secoff+4, 'I', 3, 'invalid section alignment'),
    ('section-range', secoff+16, 'Q', len(original)+4096, 'section outside file'),
    ('ecb-link-range', sections[ecb][4], 'I', count, 'section link outside table'),
    ('ecb-link-type', sections[ecb][4], 'I', string, 'section link has wrong type'),
    ('probe-string-range', sections[probe][4]+4, 'I', 0xffffffff, 'probe string outside string table'),
    ('string-termination', sections[string][4]+sections[string][5]-1, 'B', 65, None),
]
results = []
for name, offset, fmt, value, diagnostic in mutations:
    data = bytearray(original)
    struct.pack_into('<'+fmt, data, offset, value)
    try:
        validate_dof(data)
    except ValueError as error:
        assert diagnostic is None or diagnostic in str(error), (name, str(error))
        results.append({'case': name, 'rejected': True, 'diagnostic': str(error)})
    else:
        raise AssertionError('corruption accepted: '+name)
print(json.dumps(results, indent=2))
