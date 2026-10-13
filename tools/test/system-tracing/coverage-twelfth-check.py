#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Verify probe contracts, executable SDT/DOF sites and offline installed profiles.
No module loading, live DTrace, daemon start, installation or VM execution.
"""
import argparse, concurrent.futures, hashlib, importlib.util, json, os, re, struct, subprocess
from pathlib import Path

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, default=Path('/usr/src'))
    parser.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-dtrace-twelfth-validation'))
    args = parser.parse_args()
    src, out = args.src, args.obj
    tests = src / 'tools/test/system-tracing'
    inv = json.loads((tests / 'coverage-twelfth.json').read_text())
    for name, digest in inv['sources'].items():
        assert hashlib.sha256((src/name).read_bytes()).hexdigest() == digest, name
    contracts = load('contracts', tests/'coverage-third-profile-check.py')
    dof = load('dof', tests/'coverage-fourth-dof.py')
    elf = load('objects', tests/'coverage-sixth-objects.py')
    profiles = src/'cddl/usr.sbin/bsdinstruments/profiles'
    installed = subprocess.check_output(['make','-C',str(profiles.parent),'-m',str(src/'share/mk'),'-V','PROFILES'],text=True).split()
    for name in inv['profiles']:
        assert name+'.d' in installed, name
        contracts.check_contracts((profiles/(name+'.d')).read_text(),inv['probes']+inv['dependencies'])
    (out/'profiles').mkdir(exist_ok=True)
    def profile(job):
        name, filtered = job
        command = ['bsdinstruments','generate','-f',str(profiles/(name+'.d'))]
        if filtered: command += ['--pid','42','--duration','1']
        text = subprocess.check_output(command,text=True)
        assert '@bsdinstruments-' not in text
        target = out/'profiles'/(name+('-filtered' if filtered else '')+'.d')
        target.write_text(text)
        result = subprocess.run(['dtrace','-e','-Z','-s',str(target)],capture_output=True,text=True)
        target.with_suffix('.log').write_text(result.stdout+result.stderr)
        return dict(profile=name,filtered=filtered,status=result.returncode)
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        results = list(pool.map(profile,[(p,f) for p in inv['profiles'] for f in (False,True)]))
    (out/'profile-results.json').write_text(json.dumps(results,indent=2)+'\n')
    assert not [r for r in results if r['status']], results
    print(len(results),'offline profile checks;',len(installed),'install entries',flush=True)
    records=[]
    for source in sorted({p['source'] for p in inv['probes'] if p['kind']=='kernel'}):
        wanted=[p for p in inv['probes'] if p['source']==source]
        for enabled in (True,False):
            stem=Path(source).stem
            path=out/'kernel'/(stem+'-'+str(enabled)+'.o')
            obj=elf.Object(path); symbols={s['name']:s for s in obj.symbols};sites=obj.tracepoints()
            for p in wanted:
                name='sdt_'+'_'.join([p['provider'],p['module'],p['function'],p['name'].replace('-','__')])
                pattern=re.compile(r'(?:^|\.)'+re.escape(name)+r'(?:\.[0-9]+)?$')
                definitions=[sym for n,sym in symbols.items() if pattern.search(n)]
                if not enabled:
                    assert not definitions,(path,name);continue
                assert definitions,(path,name)
                if p['name']=='dmu-assign-done':
                    assert len(definitions)==2,(path,'both completion sites required')
                for sym in definitions:
                    location=(sym['section'],sym['value'])
                    matches=[(patch,target) for probe,patch,target in sites if probe==location]
                    assert matches,(path,name,sym['name'])
                    if p['provider']=='pf':
                        assert len(matches)>={'decision':7,'pressure':5,'eligible':2}[p['name']],(path,name,len(matches))
                    for patch,target in matches:
                        for sec,offset in (patch,target):
                            assert obj.sections[sec][2]&4 and 0<=offset<obj.sections[sec][5]
                        sec,offset=patch
                        assert obj.section_data(sec)[offset:offset+5]==bytes.fromhex('660f1f0400'),(path,name)
            if stem=='zfs_vnops_os':
                # Access is defined in kmod_core, so identify its external
                # relocation by symbol name, not the undefined section/value.
                index=obj.names.get('set_sdt_tracepoint_set')
                count=0
                if index is not None:
                    for i,sec in enumerate(obj.sections):
                        if sec[1]!=4 or sec[7]!=index:continue
                        data=obj.section_data(i)
                        for off in range(0,len(data),sec[9]):
                            offset,info,addend=struct.unpack_from('<QQq',data,off)
                            if offset % 32 == 0 and obj.symbols[info >> 32]['name']=='sdt_zfs___access':
                                count+=1
                assert count==(2 if enabled else 0),(path,'normal and fast-success access',count)
            records.append(dict(object=str(path),hooks=enabled,checked=len(wanted),status=0))
    (out/'object-results.json').write_text(json.dumps(records,indent=2)+'\n')
    print(len(records),'kernel objects: real executable NOP sites / no-hooks absence PASS')

if __name__=='__main__':main()
