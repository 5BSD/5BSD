#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Sanitized production list, daemon configuration and migration I/O tests."""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
tests = Path(__file__).resolve().parent
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
common = root/'cddl/contrib/opensolaris/lib/libdtrace/common'
suites = {
 'list-model': ('cc', [tests/'list-model.c',common/'dt_list.c'], [common], []),
 'config-properties': ('c++', [tests/'config-properties.cc'], [root/'usr.sbin/dtraced'], ['-std=c++17']),
 'migration-fd-faults': ('cc', [tests/'migration-fd-faults.c',root/'usr.sbin/bhyve/migration_session.c'],
                        [root/'usr.sbin/bhyve'], ['-Wl,--wrap=read,--wrap=write,--wrap=poll','-lz','-lnv']),
}
def run(item):
 name, (compiler, sources, includes, extra) = item
 binary = out/name
 command = [compiler, '-O1', '-g', '-UNDEBUG', '-Wall', '-Wextra',
            '-fsanitize=address,undefined', '-fno-sanitize-recover=all']
 command += ['-I'+str(p) for p in includes] + [str(p) for p in sources] + extra + ['-o',str(binary)]
 build = subprocess.run(command,capture_output=True,text=True)
 (out/(name+'-build.log')).write_text(build.stdout+build.stderr)
 result = {'name':name,'command':command,'build_status':build.returncode}
 if not build.returncode:
  test = subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
  (out/(name+'.log')).write_text(test.stdout+test.stderr)
  result['test_status'] = test.returncode
  result['output'] = test.stdout+test.stderr
 paths = sources + [Path(__file__)]
 for inc in includes: paths += list(inc.glob('*.h'))
 if binary.exists(): paths.append(binary)
 result['sha256']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
 return result
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
 results = list(pool.map(run, suites.items()))
(out/'results.json').write_text(json.dumps({'results':results,'live_testing':False},indent=2)+'\n')
for r in results: print(r['name'],r.get('test_status','build failed'),r.get('output',''))
raise SystemExit(0 if all(r.get('test_status')==0 for r in results) else 1)
