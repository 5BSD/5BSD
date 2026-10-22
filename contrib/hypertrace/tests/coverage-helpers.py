#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Measure isolated helper suites; retain complete mapped-source denominators."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
tests = Path(__file__).resolve().parent
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj') or out.exists():
    raise SystemExit('Use a new /usr/obj directory')
out.mkdir(parents=True)
wrappers = out/'bin'; wrappers.mkdir()
for name in ('cc','c++'):
    path = wrappers/name
    path.write_text('#!/bin/sh\nexec /usr/bin/'+name+' -fprofile-instr-generate -fcoverage-mapping -fprofile-update=atomic "$@"\n')
    path.chmod(0o755)
paths=[]
for folder in ['usr.sbin/bhyve','usr.sbin/dtraced','cddl/contrib/opensolaris/lib/libdtrace/common']:
    paths += list((root/folder).glob('*.h')) + list((root/folder).glob('*.c'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
before={str(p):sha(p) for p in paths}
(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
results=[]
suites=[('discovery-helpers',['list-model','config-properties','migration-fd-faults']),
        ('string-helpers',['string-helpers']), ('credential-properties',['credential-properties'])]
for suite,binaries in suites:
    profiles=out/(suite+'-profiles');profiles.mkdir()
    env=os.environ.copy();env['PATH']=str(wrappers)+':'+env['PATH']
    env['LLVM_PROFILE_FILE']=str(profiles/'%m-%p.profraw')
    with (out/(suite+'.log')).open('w') as log:
        subprocess.run([sys.executable,str(tests/(suite+'.py')),str(out/suite)],
                       env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=120)
    raw=sorted(profiles.glob('*.profraw'));assert raw
    listing=out/(suite+'-profiles.txt');listing.write_text('\n'.join(map(str,raw))+'\n')
    merged=out/(suite+'.profdata')
    with (out/(suite+'-merge.log')).open('w') as log:
        subprocess.run(['llvm-profdata','merge','-sparse','-f',str(listing),'-o',str(merged)],
                       stdout=log,stderr=subprocess.STDOUT,check=True)
    assert (out/(suite+'-merge.log')).stat().st_size==0
    for name in binaries:
        binary=out/suite/name
        export=out/(name+'-coverage.json');errors=out/(name+'-export.log')
        with export.open('w') as log,errors.open('w') as err:
            subprocess.run(['llvm-cov','export',str(binary),'-instr-profile='+str(merged)],
                           stdout=log,stderr=err,check=True)
        assert errors.stat().st_size==0
        data=json.loads(export.read_text())['data'][0]
        mapped={}
        for f in data['files']:
            p=Path(f['filename'])
            if str(p) in before:
                assert sha(p)==before[str(p)],p
                mapped[str(p)]={'summary':f['summary'],'sha256':sha(p)}
        results.append({'suite':suite,'binary':str(binary),'binary_sha256':sha(binary),
                        'mapped_production_files':mapped})
        for path,info in mapped.items():
            summary=info['summary']
            print(name,Path(path).name,'lines',round(summary['lines']['percent'],2),
                  'branches',round(summary['branches']['percent'],2),flush=True)
(out/'summary.json').write_text(json.dumps({'results':results,'live_testing':False,
 'limitations':['Standalone configurations, not full linked production components.',
               'Unmapped/uninstantiated header code remains unmeasured.',
               'Full LLVM exports retained including harness code; reported production rows exclude harness.']},indent=2)+'\n')
