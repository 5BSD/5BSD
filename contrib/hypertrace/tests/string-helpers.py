#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import hashlib, json, subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
production = root/'cddl/contrib/opensolaris/lib/libdtrace/common/dt_string.c'
source = Path(__file__).with_suffix('.c')
binary = out/'string-helpers'
command = ['cc', '-g', '-O1', '-UNDEBUG', '-fsanitize=address,undefined',
           '-fno-sanitize-recover=all', '-I'+str(production.parent),
           str(source), str(production), '-Wl,--wrap=malloc', '-o', str(binary)]
build = subprocess.run(command, capture_output=True, text=True)
(out/'build.log').write_text(build.stdout + build.stderr)
if build.returncode: raise SystemExit('Build failed')
run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
(out/'run.log').write_text(run.stdout + run.stderr)
paths = [Path(__file__), source, production, production.with_suffix('.h'), binary]
(out/'results.json').write_text(json.dumps({'status':run.returncode,'command':command,
 'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}},indent=2)+'\n')
print(run.stdout + run.stderr, end='')
raise SystemExit(run.returncode)
