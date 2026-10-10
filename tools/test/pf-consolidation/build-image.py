#!/usr/bin/env python3
"""Build a new immutable test input from an already staged disposable root."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

p = argparse.ArgumentParser()
p.add_argument('directory', type=Path)
p.add_argument('tag')
a = p.parse_args()
b = a.directory.resolve()
if not str(b).startswith('/usr/obj/') or not re.fullmatch(r'[a-z0-9-]+', a.tag):
    p.error('use a directory under /usr/obj and an alphanumeric tag')
r = b / 'root'
outputs = [b / (a.tag + '.mtree'), b / ('rootfs-' + a.tag + '.zfs'),
           b / ('guest-' + a.tag + '.img'), b / (a.tag + '-manifest.json')]
if any(x.exists() for x in outputs):
    p.error('tag already exists; preserve previous evidence')
paths = (r / 'root/pf-artifacts').read_text().splitlines()
manifest = {x: hashlib.sha256((r / x.lstrip('/')).read_bytes()).hexdigest()
            for x in paths}
outputs[3].write_text(json.dumps(manifest, indent=2) + '\n')

def escape(s):
    return ''.join('\\%03o' % ord(c) if c.isspace() or c in '\\#' else c
                   for c in s)

with outputs[0].open('w') as f:
    f.write('. type=dir uid=0 gid=0 mode=0755\n')
    for parent, dirs, files in os.walk(r):
        for name in sorted(dirs + files):
            x = Path(parent) / name
            kind = 'link' if x.is_symlink() else ('dir' if x.is_dir() else 'file')
            f.write('./' + escape(str(x.relative_to(r))) + ' type=' + kind +
                    ' uid=0 gid=0 mode=%04o' % (x.lstat().st_mode & 0o7777) +
                    (' link=' + escape(os.readlink(x)) if kind == 'link' else '') + '\n')
subprocess.run(['makefs', '-t', 'zfs', '-s', '6g', '-o', 'poolname=linuxgate',
                '-o', 'bootfs=linuxgate', '-o', 'rootpath=/',
                str(outputs[1]), str(outputs[0])], cwd=r, check=True)
subprocess.run(['mkimg', '-s', 'gpt', '-f', 'raw', '-b', str(r / 'boot/pmbr'),
                '-p', 'freebsd-boot:=' + str(r / 'boot/gptzfsboot'),
                '-p', 'freebsd-zfs:=' + str(outputs[1]),
                '-o', str(outputs[2])], check=True)
print(outputs[2])
