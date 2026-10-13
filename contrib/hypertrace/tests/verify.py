#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Verify the pinned vendor overlay without network access."""
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path(__file__).resolve().parents[1]
m=json.loads((root/'upstream-manifest.json').read_text())
expected=set()
for entry in m['files']:
 p=root/'upstream'/entry['path']
 if entry['status']=='D':
  assert not p.exists(),p
  continue
 expected.add(entry['path'])
 assert hashlib.sha256(p.read_bytes()).hexdigest()==entry['sha256'],p
 assert bool(p.stat().st_mode&0o111)==(entry['mode']=='100755'),p
actual={str(p.relative_to(root/'upstream')) for p in (root/'upstream').rglob('*') if p.is_file()}
assert actual==expected,(actual-expected,expected-actual)
assert hashlib.sha256((root/'upstream.patch').read_bytes()).hexdigest()==(root/'upstream.patch.sha256').read_text().strip()
print('PASS pristine vendor overlay:',len(expected),'files')
