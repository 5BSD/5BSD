# SPDX-License-Identifier: BSD-2-Clause
"""Real release-anchor/manifest/file/private-buffer root reader; no firmware."""
import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[3]
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/f'tools/build/capimage/{name}.py')
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--compiled-probe',type=Path,required=True)
    parser.add_argument('--openssl',type=Path,required=True)
    args=parser.parse_args()
    os.umask(0o077)
    run=Path(tempfile.mkdtemp(prefix='root-reader-',dir=args.work))
    boot=module('generation_boot');artifacts=module('verity_artifacts')
    image=run/'system.ufs';image.write_bytes(bytes(8192))
    artifacts.build(run,dict(format=1,block_size=4096,salt_hex='aabb'),
        artifacts.digest(image),image.stat().st_size)
    descriptor=(run/'root.descriptor').read_bytes()
    cases=[('generation','generation',descriptor,False,False),
        ('firmware','firmware',descriptor,False,False),
        ('application','application',descriptor,False,False),
        ('repository','repository',descriptor,False,False),
        ('revoked','generation',descriptor,True,False),
        ('changed-file','generation',descriptor,False,True),
        ('oversized','generation',descriptor+b'x',False,False),
        ('short','generation',descriptor[:-1],False,False)]
    results=[]
    for name,role,payload,revoked,tamper in cases:
        folder=run/name;folder.mkdir(mode=0o700)
        manifest=b'root.descriptor sha256='+hashlib.sha256(payload).hexdigest().encode()+b'\n'
        signed,_=boot.sign_loader_manifest(manifest,
            dict(key=str(args.work/role/'private.key'),certificate=str(args.work/role/'public.crt'),
                 openssl=str(args.openssl)),folder)
        for member,content in signed.items():(folder/member).write_bytes(content)
        path=folder/'root.descriptor'
        path.write_bytes(bytes([payload[0]^1])+payload[1:] if tamper else payload)
        result=subprocess.run([str(args.compiled_probe),str(args.work/'firmware/public.crt'),
            str(args.work/'generation/public.crt') if revoked else '-',
            '--root-descriptor',str(path)],capture_output=True,text=True,timeout=30,
            env=dict(os.environ,VE_VERBOSE='0'))
        accepted=result.returncode==0 and result.stdout.endswith('descriptor accepted\n')
        expected=name=='generation'
        if expected:
            reason=result.returncode==0 and result.stderr==''
        elif name in ('firmware','application','repository'):
            reason=result.returncode==2 and 'BR_ERR_X509_NOT_TRUSTED' in result.stdout
        elif name=='revoked':
            reason=result.returncode==2 and 'Certificate is on forbidden list' in result.stdout
        elif name=='changed-file':
            reason=result.returncode==2 and f'Secure Boot: verification failed: {path} (-3)' in result.stderr
        else:
            reason=result.returncode==1 and result.stderr==f'descriptor rejected errno={errno.EINVAL}\n'

        results.append(dict(case=name,expected_accept=expected,accepted=accepted,
            exit=result.returncode,stdout=result.stdout,stderr=result.stderr,
            reason_matched=reason,passed=accepted==expected and reason,
            descriptor_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    report=dict(scope='native-production-root-reader-with-real-manifest-cryptography',
        result='PASS' if all(c['passed'] for c in results) else 'FAIL',cases=results,
        firmware_verified=False,kernel_admission_qualified=False,
        probe_sha256=hashlib.sha256(args.compiled_probe.read_bytes()).hexdigest())
    (run/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f"{report['result']}: {len(cases)} root-reader cases; {run/'results.json'}")
    if report['result']!='PASS':raise SystemExit(1)
if __name__=='__main__':main()
