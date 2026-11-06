# SPDX-License-Identifier: BSD-2-Clause
"""Check MAN against the complete source-owned world inventory, including aliases."""
import json
import os
from pathlib import Path

root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
record = json.loads((root / 'world_package_inventory.json').read_text())
assert record['scope'] == 'world-package-inventory'
enabled = record['configuration']['man']
assert type(enabled) is bool
manuals = [entry['destination'] for rows in record['packages'].values() for entry in rows
           if entry['type'] != 'dir' and entry['destination'].startswith(('/usr/share/man/', '/usr/share/openssl/man/'))]
indexes = [path for path in record['construction']
           if path.startswith(('/usr/share/man/', '/usr/share/openssl/man/'))]
if enabled:
    assert manuals, 'MAN enabled but the complete world has no manual payload'
else:
    assert not manuals, 'MAN disabled but manual payload remains: ' + repr(manuals[:20])
    assert not indexes, 'MAN disabled but manual construction outputs remain: ' + repr(indexes)
print('Whole-world MAN setting checked: enabled=%s manual_payloads=%d manual_indexes=%d' %
      (enabled, len(manuals), len(indexes)))
