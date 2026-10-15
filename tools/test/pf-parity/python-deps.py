#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Copy an identified Python runtime and pinned Scapy into a disposable stage."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('root', type=Path)
p.add_argument('wheel', type=Path)
a = p.parse_args()
root = a.root.resolve()
if not str(root).startswith('/usr/obj/5BSD-pf-parity/') or not (root/'root/pf-parity-disposable').is_file():
    p.error('destination must be a marked disposable PF parity root')
wheel = a.wheel.resolve()
if hashlib.sha256(wheel.read_bytes()).hexdigest() != '88a998572049b511a1f3e44f4aa7c62dd39c6ea2aa1bb58434f503956641789d':
    p.error('expected pinned Scapy 2.6.1 wheel')
stdlib = Path('/usr/local/lib/python3.12')
dest = root/'usr/local/lib/python3.12'
if dest.exists():
    p.error('Python already staged; preserve the existing dependency evidence')
dest.parent.mkdir(parents=True, exist_ok=True)
shutil.copytree(stdlib, dest, symlinks=True,
                ignore=shutil.ignore_patterns('site-packages', '__pycache__'))
manifest = {}
def copy_file(src):
    target = root/str(src).lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        target.unlink()
    shutil.copy2(src, target)
    manifest[str(src)] = hashlib.sha256(target.read_bytes()).hexdigest()
copy_file(Path('/usr/local/bin/python3.12'))
# Resolve dependencies from the executable and C extension modules, including
# their transitive dependencies as returned by the host's dynamic loader.
objects = [Path('/usr/local/bin/python3.12')] + list((stdlib/'lib-dynload').glob('*.so'))
libs = set()
for obj in objects:
    output = subprocess.check_output(['ldd', str(obj)], text=True)
    if 'not found' in output:
        raise RuntimeError('unresolved host dependency: '+str(obj))
    libs.update(Path(x) for x in re.findall(r'=> (/usr/local/\S+)', output))
for lib in sorted(libs):
    copy_file(lib)
(root/'usr/local/bin/python3').symlink_to('python3.12')
site = dest/'site-packages'
site.mkdir()
with zipfile.ZipFile(wheel) as archive:
    for entry in archive.infolist():
        path = Path(entry.filename)
        if path.is_absolute() or '..' in path.parts:
            raise RuntimeError('unsafe wheel member')
    archive.extractall(site)
scapy = root/'usr/local/bin/scapy'
scapy.write_text('#!/usr/local/bin/python3\nfrom scapy.main import interact\ninteract()\n')
scapy.chmod(0o755)
for item in dest.rglob('*'):
    if item.is_file():
        manifest['/'+str(item.relative_to(root))] = hashlib.sha256(item.read_bytes()).hexdigest()
manifest['/usr/local/bin/scapy'] = hashlib.sha256(scapy.read_bytes()).hexdigest()
(root/'root/python-artifacts.json').write_text(json.dumps(manifest, indent=2)+'\n')
# The guest verifies the full dependency manifest; the outer image manifest
# binds that manifest and the interpreter/library entry points.
paths = set((root/'root/pf-artifacts').read_text().splitlines())
paths.update(['/root/python-artifacts.json', '/usr/local/bin/python3.12', '/usr/local/lib/libpython3.12.so.1.0'])
(root/'root/pf-artifacts').write_text('\n'.join(sorted(paths))+'\n')
print('Staged Python/Scapy files:', len(manifest))
