#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run the complete rootless ATF migration state-machine model suite."""
from pathlib import Path
import concurrent.futures, json, os, re, subprocess, sys
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
binary=out/'migration-session'
r=subprocess.run(['cc','-Wall','-Wextra','-Werror','-pthread','-fsanitize=address,undefined',str(root/'tests/sys/kern/vsock_device_harness/migration_session_test.c'),'-lprivateatf-c','-lz','-o',str(binary)],capture_output=True,text=True)
(out/'build.log').write_text(r.stdout+r.stderr)
if r.returncode: raise SystemExit('Compilation failed; inspect build.log')
listing=subprocess.check_output([str(binary),'-l'],text=True)
cases=re.findall(r'^ident: ([a-z0-9_]+)$',listing,re.M)
if not cases or len(set(cases))!=len(cases): raise SystemExit('Invalid test inventory')
def run_case(case):
 work=out/case; work.mkdir(exist_ok=True)
 try:
  r=subprocess.run([str(binary),'-r',str(work/'result'),case],cwd=work,capture_output=True,text=True,timeout=45)
  (work/'output.log').write_text(r.stdout+r.stderr)
  verdict=(work/'result').read_text().strip() if (work/'result').exists() else 'missing result'
  return {'case':case,'exit':r.returncode,'result':verdict,'status':0 if r.returncode==0 and verdict=='passed' else 1}
 except subprocess.TimeoutExpired:
  return {'case':case,'status':1,'result':'timeout'}
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
 results=list(pool.map(run_case,cases))
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
for item in results:
 if item['status']: print(item)
if any(x['status'] for x in results): raise SystemExit(1)
print(f'PASS: {len(results)} isolated socketpair/codec/model ATF migration cases; no VM execution')
