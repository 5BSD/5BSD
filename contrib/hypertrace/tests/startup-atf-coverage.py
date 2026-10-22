#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run an explicit allowlist of portable VMM ATF suites with original mappings."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib,json,os,re,subprocess,sys
SUITES=('vmm_startup_event_test','vmm_startup_mode_test','vmm_startup_request_test','vmm_startup_run_request_test',
    'vmm_startup_handshake_test','vmm_startup_controller_test',
    'vmm_startup_entry_owner_test')
# Dedicated-suite baselines only; overlapping mappings are never summed.
# Denominator changes require explicit review, even when coverage rises.
BASELINES = {
    'vmm_startup_event_test': ((362,363),(350,354),(22,22)),
    'vmm_startup_mode_test': ((722,748),(522,650),(47,47)),
    'vmm_startup_request_test': ((144,146),(154,160),(6,6)),
    'vmm_startup_run_request_test': ((41,41),(47,48),(4,4)),
    'vmm_startup_handshake_test': ((343,350),(242,258),(17,17)),
    'vmm_startup_controller_test': ((143,145),(108,114),(11,11)),
    'vmm_startup_entry_owner_test': ((620,676),(442,614),(31,31)),
}
def coverage_gate(metrics, baseline):
    rows = {}
    for key, (covered, count) in zip(('lines','branches','functions'), baseline):
        actual = metrics[key]
        rows[key] = {
            'expected_count': count, 'minimum_covered': covered,
            'actual_count': actual['count'], 'actual_covered': actual['covered'],
            'regression_passed': actual['count'] == count and actual['covered'] >= covered,
            'target_97_met': actual['count'] > 0 and
                actual['covered'] * 100 >= actual['count'] * 97,
        }
    return {'metrics': rows,
        'regression_passed': all(r['regression_passed'] for r in rows.values()),
        'target_97_met': all(r['target_97_met'] for r in rows.values())}
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj') or out.exists():raise SystemExit('Use new /usr/obj output')
out.mkdir(parents=True);root=Path(__file__).resolve().parents[3]
def run_suite(name):
    folder=out/name;folder.mkdir();profiles=folder/'profiles';profiles.mkdir()
    source=root/'tests/sys/vmm'/(name+'.c');binary=folder/name
    command=['/usr/bin/cc','-O0','-g','-fprofile-instr-generate','-fcoverage-mapping','-fprofile-update=atomic','-I'+str(root/'sys'),'-include',str(root/'sys/sys/errno.h'),str(source),'-lprivateatf-c','-o',str(binary)]
    built=subprocess.run(command,capture_output=True,text=True)
    (folder/'build.log').write_text(built.stdout+built.stderr)
    if built.returncode:raise RuntimeError('Build failed: '+str(folder))
    listing=subprocess.run([str(binary),'-l'],capture_output=True,text=True,check=True,
        env={**os.environ,'LLVM_PROFILE_FILE':str(folder/'listing.profraw')})
    (folder/'listing.txt').write_text(listing.stdout)
    names=re.findall(r'^ident: (.+)$',listing.stdout,re.M)
    if not names or len(set(names))!=len(names):raise RuntimeError('Invalid ATF listing')
    cases=[]
    for case in names:
        result=folder/(case+'.result')
        env={**os.environ,'LLVM_PROFILE_FILE':str(profiles/(case+'-%p.profraw'))}
        proc=subprocess.run([str(binary),'-r',str(result),case],env=env,cwd=folder,capture_output=True,text=True,timeout=60)
        text=result.read_text() if result.exists() else ''
        (folder/(case+'.log')).write_text(proc.stdout+proc.stderr)
        cases.append({'case':case,'status':proc.returncode,'result':text,
            'passed':proc.returncode==0 and text.strip()=='passed' and 'LLVM Profile Error' not in proc.stderr})
    (folder/'results.json').write_text(json.dumps(cases,indent=2)+'\n')
    if not all(r['passed'] for r in cases):raise RuntimeError('Test failed: '+str(folder))
    raw=sorted(profiles.glob('*.profraw'))
    if len(raw)!=len(cases):raise RuntimeError('Profile count does not match case processes')
    (folder/'profiles.txt').write_text('\n'.join(map(str,raw))+'\n')
    subprocess.run(['llvm-profdata','merge','-sparse','-f',str(folder/'profiles.txt'),'-o',str(folder/'passing.profdata')],check=True)
    with (folder/'coverage.json').open('w') as stdout,(folder/'coverage-errors.log').open('w') as stderr:
        subprocess.run(['llvm-cov','export',str(binary),'-instr-profile='+str(folder/'passing.profdata')],stdout=stdout,stderr=stderr,check=True)
    if (folder/'coverage-errors.log').read_text().strip():raise RuntimeError('Export diagnostics: '+str(folder))
    rows=json.loads((folder/'coverage.json').read_text())['data'][0]['files']
    production=[r for r in rows if '/sys/dev/vmm/' in r['filename']]
    if not production:raise RuntimeError('Missing original-source mapping')
    report={'suite':name,'cases':len(cases),'command':command,
        'metrics':{r['filename']:r['summary'] for r in production},
        'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [source,binary,*[Path(r['filename']) for r in production]]},
        'scope':'Portable ATF suite, original .c includes; errno macro provenance normalized with source header; not live kernel execution'}
    dedicated = [r for r in production if Path(r['filename']).name == name.removesuffix('_test')+'.c']
    if len(dedicated) != 1:raise RuntimeError('Missing or ambiguous dedicated source')
    report['coverage_gate'] = coverage_gate(dedicated[0]['summary'], BASELINES[name])
    (folder/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    if not report['coverage_gate']['regression_passed']:
        raise RuntimeError('Coverage regression or denominator change: '+str(folder))
    return report
with ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
    results=list(pool.map(run_suite,SUITES))
(out/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
for r in results:
    print(r['suite'],r['cases'],'passed')
    for path,m in r['metrics'].items():
        if path.endswith('.c'):print(Path(path).name,{k:round(m[k]['percent'],3) for k in ('lines','branches','functions')})
