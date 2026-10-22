#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Execute built drti with loader/device operations replaced at link time."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
out,obj=(Path(x).resolve() for x in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out,obj)) or out.exists():
    raise SystemExit('Use new /usr/obj output and existing runtime object')
root=Path(__file__).resolve().parents[3]
source=root/'cddl/contrib/opensolaris/lib/libdtrace/common/drti.c'
if not obj.is_file() or obj.stat().st_mtime_ns < source.stat().st_mtime_ns:
    raise SystemExit('Rebuild the runtime object from current source before testing')
out.mkdir(parents=True)
fixture=Path(__file__).with_suffix('.c')
binary=out/'drti-test'
command=['/usr/bin/cc','-g','-fprofile-instr-generate',
    '-I'+str(root/'sys/cddl/compat/opensolaris'),
    '-I'+str(root/'cddl/compat/opensolaris/include'),
    '-I'+str(root/'sys/cddl/contrib/opensolaris/uts/common'),
    '-I'+str(root/'sys'),str(fixture),str(obj),'-Wl,--wrap=dlinfo,--wrap=open,--wrap=close,--wrap=ioctl','-o',str(binary)]
subprocess.run(command,check=True)
results=[]
for name in ('disabled','loader-fail','loader-null','corrupt','open-fail','add-fail','success','remove-fail','null-name','empty-name','plain-name','corrupt1','corrupt2','corrupt3','exec-image','cleanup-open-fail','quiet-success','quiet-open-fail','default-device'):
    env=os.environ.copy()
    for k in ('DTRACE_DOF_INIT_DISABLE','DTRACE_DOF_INIT_DEBUG','DTRACE_DOF_INIT_DEVNAME'): env.pop(k,None)
    env.update(HT_FINAL_PROFILE=str(out/('final-'+name+'.profraw')),HT_CASE=name,DTRACE_DOF_INIT_DEVNAME='/offline/helper',DTRACE_DOF_INIT_DEBUG='1',LLVM_PROFILE_FILE=str(out/(name+'-%p.profraw')))
    if name.startswith('quiet-'):
        env.pop('DTRACE_DOF_INIT_DEBUG')
        env['HT_CASE']=name.removeprefix('quiet-')
    if name=='default-device': env.pop('DTRACE_DOF_INIT_DEVNAME')
    if name=='disabled': env['DTRACE_DOF_INIT_DISABLE']='1'
    p=subprocess.run([str(binary)],env=env,capture_output=True,text=True,timeout=10)
    r=json.loads(p.stdout) if p.returncode==0 else {'passed':False}
    r.update(case=name,status=p.returncode,stderr=p.stderr)
    results.append(r)
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'command':command,'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (obj,fixture,Path(__file__),binary,root/'cddl/contrib/opensolaris/lib/libdtrace/common/drti.c')},'boundary':'link-time wrappers: dlinfo/open/close/ioctl; no real helper-device calls'},indent=2)+'\n')
for r in results:
    if not r['passed']: print(r)
print(f"{sum(r['passed'] for r in results)}/{len(results)} runtime cases passed")
if not all(r['passed'] for r in results): raise SystemExit(1)
# Early atexit profiles omit destructor work; merge only explicit final dumps.
profiles=sorted(out.glob('final-*.profraw'))
if len(profiles)!=len(results) or any(p.stat().st_size==0 for p in profiles):
    raise SystemExit('Missing final destructor profiles')
(out/'profiles.txt').write_text('\n'.join(map(str,profiles))+'\n')
subprocess.run(['llvm-profdata','merge','-sparse','-f',str(out/'profiles.txt'),
                '-o',str(out/'passing.profdata')],check=True)
with (out/'coverage.json').open('w') as stdout,(out/'coverage-errors.log').open('w') as stderr:
    subprocess.run(['llvm-cov','export',str(binary),'-instr-profile='+str(out/'passing.profdata')],
                   stdout=stdout,stderr=stderr,check=True)
if (out/'coverage-errors.log').read_text().strip():
    raise SystemExit('Coverage export diagnostics require investigation')
files=json.loads((out/'coverage.json').read_text())['data'][0]['files']
source=root/'cddl/contrib/opensolaris/lib/libdtrace/common/drti.c'
rows=[r for r in files if Path(r['filename']).resolve()==source]
if len(rows)!=1: raise SystemExit('Missing or ambiguous original runtime mapping')
metrics=rows[0]['summary']
# Freeze the observed full-file denominator. Source/configuration changes need
# an explicit baseline review; losing mapping must not silently improve a score.
baseline={'lines':(86,89),'branches':(45,46),'functions':(3,3)}
checks={}
for name,(minimum,total) in baseline.items():
    actual=metrics[name]
    checks[name]={'covered':actual['covered'],'count':actual['count'],
        'minimum_covered':minimum,'expected_count':total,
        'regression_passed':actual['count']==total and actual['covered']>=minimum,
        'target_97_met':actual['count']>0 and actual['covered']*100>=actual['count']*97}
report={'metrics':metrics,'checks':checks,'regression_passed':all(c['regression_passed'] for c in checks.values()),
    'target_97_met':all(c['target_97_met'] for c in checks.values()),
    'scope':'Full drti.c mapping, FreeBSD amd64; actual built object with mocked loader and helper-device operations',
    'live_qualification':'deferred','excluded_counters':'Premature exit profiles; only final-*.profraw merged',
    'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest()}
(out/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(checks))
raise SystemExit(not report['regression_passed'])
