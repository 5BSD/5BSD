#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Rerun offline library suites and measure one current whole-library mapping."""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
out, world, prior = [Path(s).resolve() for s in sys.argv[1:]]
if out.exists() or not all(p.is_relative_to('/usr/obj') for p in (out,world,prior)):
    raise SystemExit('Use a new /usr/obj output and existing build/baseline paths')
out.mkdir(parents=True)
tests=Path(__file__).resolve().parent
library=world/'cddl/lib/libdtrace/libdtrace.so.2'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
# Prior export supplies the file inventory, never its counters or old identity.
old=json.loads(prior.read_text())
paths=[Path(f['filename']) for f in old['data'][0]['files']]
before={str(p):sha(p) for p in paths}
binary_hash=sha(library)
(out/'start-provenance.json').write_text(json.dumps({'binary_sha256':binary_hash,
 'source_sha256':before},indent=2)+'\n')
env=os.environ.copy();env['LD_LIBRARY_PATH']=':'.join(str(world/p) for p in
 ['cddl/lib/libdtrace','cddl/lib/libctf','lib/libproc','lib/librtld_db'])
first=[('elf-library',world),('compiler-api-offline',library),('linker-offline',world),
 ('cli-offline',world),('ctf-linker-bounds',world.parents[3],'--native'),('printf-records-offline',library),
 ('llquantize-bounds',library),('program-inspection-offline',library),('strtab-properties',library),
 ('consume-ingestion',world),('linker-corpus',world),
 ('options-properties',library),('compiler-diagnostics',library),
 ('elf-options',library),('instr-size-differential',library),
 ('dtraced-client',world),('pid-placement',world),
 ('analysis-modref',library),('program-verify-mutation',world),
 ('consume-records',world),('printf-conversions',world),('printf-faults',world),
 ('aggregate-walk',world),('program-properties',world),('subr-handle',world),
 ('subr-faults',world),('frontend-parser-scoped',world),('frontend-runtime-open',world),
 ('instr-size-exhaustive',library),('usdt-link',world),
 ('frontend-parser-fold',world),('frontend-parser-corpus',world),('frontend-parser-printers',world),('frontend-parser-symbols',world),('frontend-parser-oom',world),('frontend-codegen-arith',world),('frontend-codegen-lang',world),('frontend-codegen-cc',world),('frontend-codegen-unit',world),('frontend-codegen-oom',world),('frontend-runtime-utils',world),('frontend-runtime-options',world),('frontend-runtime-provider',world),('frontend-runtime-module',world),
 ('typing-inference',world),('elf-coverage-matrix',world),
 ('frontend-parser-kernel',world),('frontend-codegen-link',world)]
def run(item):
 name,*args=item
 profiles=out/(name+'-profiles');profiles.mkdir()
 local=env.copy();local['LLVM_PROFILE_FILE']=str(profiles/'%p-%m.profraw')
 command=[sys.executable,str(tests/(name+'.py')),str(out/name),*map(str,args)]
 with (out/(name+'.log')).open('w') as log:
  result=subprocess.run(command,env=local,stdout=log,stderr=subprocess.STDOUT,timeout=1800)
 return {'suite':name,'status':result.returncode,'command':command}
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
 results=list(pool.map(run,first))
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
assert all(r['status']==0 for r in results),results
corpus=out/'elf-library/compiler-offline/results.json'
# Some drivers place their compiler corpus directly under the suite directory.
if not corpus.exists():
 candidates=list((out/'elf-library').rglob('results.json'))
 corpus=next(p for p in candidates if 'compiler-offline' in str(p))
for item in [('compiler-differential',library,corpus),('disassembly-offline',world,corpus)]:
 results.append(run(item))
 (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 assert results[-1]['status']==0,results[-1]
assert sha(library)==binary_hash
assert all(sha(Path(p))==h for p,h in before.items())
for log in out.rglob('*.log'):
 assert 'LLVM Profile Error' not in log.read_text(errors='replace'),log
raw=sorted(out.rglob('*.profraw'));assert raw
listing=out/'profiles.txt';listing.write_text('\n'.join(map(str,raw))+'\n')
with (out/'merge.log').open('w') as log:
 subprocess.run(['llvm-profdata','merge','-sparse','-f',str(listing),'-o',str(out/'passing.profdata')],stdout=log,stderr=subprocess.STDOUT,check=True)
with (out/'coverage.json').open('w') as log,(out/'export.log').open('w') as err:
 subprocess.run(['llvm-cov','export',str(library),'-instr-profile='+str(out/'passing.profdata')],stdout=log,stderr=err,check=True)
assert (out/'merge.log').stat().st_size==0 and (out/'export.log').stat().st_size==0
coverage=json.loads((out/'coverage.json').read_text())['data'][0]
assert {f['filename'] for f in coverage['files']}==set(before)
subset=[f for f in coverage['files'] if '/libdtrace/' in f['filename']]
subset_summary={}
for metric in ('lines','branches','functions'):
 count=sum(f['summary'][metric]['count'] for f in subset)
 covered=sum(f['summary'][metric]['covered'] for f in subset)
 subset_summary[metric]={'count':count,'covered':covered,'percent':100*covered/count if count else 0}
summary={'source_sha256':before,'binary_sha256':binary_hash,'mapped_object_totals':coverage['totals'], 'library_path_subset':subset_summary,
 'subset_rule':"Paths containing /libdtrace/; excludes other mapped production sources. Full object totals remain authoritative for the whole mapping.",
 'passing_profiles':len(raw),'suites':results,'live_testing':False,
 'note':'Only fresh profiles from this run. Standalone helper profiles are not merged.'}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(coverage['totals']),flush=True)
