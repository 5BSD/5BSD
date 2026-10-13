#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Verify probe contracts, executable DOF sites and offline installed profiles.
No module loading, live DTrace, daemon start, installation or VM execution.
"""
import argparse, concurrent.futures, hashlib, importlib.util, json, os, subprocess
from pathlib import Path

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, default=Path('/usr/src'))
    parser.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-dtrace-fourteenth-validation'))
    args = parser.parse_args()
    src, out = args.src, args.obj
    tests = src / 'tools/test/system-tracing'
    inv = json.loads((tests / 'coverage-fourteenth.json').read_text())
    for name, digest in inv['sources'].items():
        assert hashlib.sha256((src/name).read_bytes()).hexdigest() == digest, name
    contracts = load('contracts', tests/'coverage-third-profile-check.py')
    dof = load('dof', tests/'coverage-fourth-dof.py')
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
    for component, binary, providers in [('usr.sbin_extattr', 'rmextattr', ['attrtool']), ('bin_getfacl', 'getfacl', ['aclread']), ('bin_setfacl', 'setfacl', ['aclwrite']), ('usr.bin_fsync', 'fsync', ['filesync']), ('bin_cat', 'cat', ['catio']), ('usr.bin_tee', 'tee', ['teeio']), ('usr.bin_split', 'split', ['splitio']), ('usr.bin_wc', 'wc', ['wordcountio']), ('usr.bin_tail', 'tail', ['tailwait']), ('usr.bin_cksum', 'cksum', ['checksumtool']), ('sbin_kldstat', 'kldstat', ['modulequery']), ('bin_kenv', 'kenv', ['envquery']), ('usr.sbin_chroot', 'chroot', ['rootchange']), ('usr.bin_procstat', 'procstat', ['processquery']), ('bin_pwait', 'pwait', ['processwait']), ('usr.bin_brandelf', 'brandelf', ['elfbrand']), ('usr.bin_vmstat', 'vmstat', ['vmquery'])]:
        on=out/'base'/(component+'-yes')/binary
        off=out/'base'/(component+'-no')/binary
        actual=dof.dof_probes(dof.elf_sections(on).get('.SUNW_dof',b''))
        disabled=dof.dof_probes(dof.elf_sections(off).get('.SUNW_dof',b''))
        wanted=[p for p in inv['probes'] if p['provider'].rstrip('*') in providers]
        for p in wanted:
            matches=[a for a in actual if a['name']==p['name'] and a['provider']==p['provider'].rstrip('*')]
            assert matches and all(a['argc']==len(p['types']) and a['offsets']>0 for a in matches),(on,p)
            assert all(a['enabled_offsets']>0 for a in matches),(on,p,'guard missing')
        assert not [p for p in disabled if p['provider'] in providers],off
        records.append(dict(binary=str(on),checked=len(wanted),sites=actual,disabled_absent=True))
    (out/'dof-results.json').write_text(json.dumps(records,indent=2)+'\n')
    print(len(records),'linked USDT binaries and disabled counterparts PASS',flush=True)

if __name__=='__main__':main()
