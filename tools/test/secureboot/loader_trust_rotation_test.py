# SPDX-License-Identifier: BSD-2-Clause
"""Build explicit release-anchor profiles and test native key rotation boundaries."""
import argparse,hashlib,json,os,subprocess,tempfile
from pathlib import Path
import manifest_trust_crypto_test as trust
ROOT=trust.ROOT

def sha(path):
    with Path(path).open('rb') as file:return hashlib.file_digest(file,'sha256').hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--make',type=Path,required=True)
    parser.add_argument('--openssl',type=Path,required=True)
    parser.add_argument('--jobs',type=int,required=True)
    args=parser.parse_args()
    if args.jobs<1:parser.error('jobs must be positive')
    for tool in (args.make,args.openssl):
        if not tool.is_absolute() or not os.access(tool,os.X_OK):parser.error('tools must be absolute executables')
    parent=args.work.resolve(strict=True)
    if any(c.isspace() for c in str(parent)):parser.error('make anchor-list paths cannot contain whitespace')
    os.umask(0o077)
    work=Path(tempfile.mkdtemp(prefix='loader-trust-rotation-',dir=parent))
    fixtures=work/'fixtures'
    roles=('firmware','generation','next','application','repository')
    trust.prepare(fixtures,args.openssl,roles=roles)
    profiles={};cases=[]
    for name,anchors in [('old',('generation',)),('overlap',('generation','next')),('new',('next',))]:
        output=work/name;output.mkdir(mode=0o700)
        public=[fixtures/a/'public.crt' for a in anchors]
        command=[str(args.make),'-C',str(ROOT/'tools/test/secureboot/manifest-trust-probe'),
                 '-j',str(args.jobs),'SRCCONF=/dev/null','__MAKE_CONF=/dev/null',
                 'WITH_BEARSSL=yes','WITH_LOADER_EFI_SECUREBOOT=yes',
                 'WITHOUT_LOADER_EFI_TRUST_DB=yes','TRUST_ANCHORS='+' '.join(map(str,public)),'all']
        inputs={'argv':command,'MAKEOBJDIR':str(output),'anchors':{str(p):sha(p) for p in public}}
        (output/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
        with (output/'build.log').open('w') as log:
            subprocess.run(command,env=dict(os.environ,MAKEOBJDIR=str(output)),
                           stdout=log,stderr=subprocess.STDOUT,check=True,timeout=300)
        probe=output/'manifest_trust_probe'
        assert all(sha(p)==inputs['anchors'][str(p)] for p in public)
        profiles[name]=dict(inputs=inputs,probe_sha256=sha(probe),table_sha256=sha(output/'ta.h'),
                            build_log_sha256=sha(output/'build.log'))
        scenarios=[(role,None,role in anchors) for role in roles]
        for revoked in anchors:
            scenarios += [(role,revoked,role!=revoked) for role in anchors]
        for role,revoked,expected in scenarios:
            command=[str(probe),str(fixtures/'firmware/public.crt'),
                     str(fixtures/revoked/'public.crt') if revoked else '-',
                     str(fixtures/role/'manifest.sig')]
            result=subprocess.run(command,capture_output=True,text=True,timeout=30)
            accepted=result.returncode==0 and result.stdout=='accepted\n' and not result.stderr
            if expected:reason=accepted
            elif revoked==role:reason=result.returncode==1 and 'Certificate is on forbidden list' in result.stderr
            else:reason=result.returncode==1 and 'BR_ERR_X509_NOT_TRUSTED' in result.stderr
            cases.append(dict(profile=name,signer=role,revoked=revoked,expected_accept=expected,
                              accepted=accepted,passed=(accepted==expected and reason),
                              command=command,exit=result.returncode,stdout=result.stdout,stderr=result.stderr))
    report=dict(scope='native production manifest cryptography; injected firmware variable transport',
                result='PASS' if all(c['passed'] for c in cases) else 'FAIL',profiles=profiles,cases=cases,
                tools={str(args.make):sha(args.make),str(args.openssl):sha(args.openssl)},
                firmware_rotation_qualified=False,kernel_admission_qualified=False,
                upgrade_recovery_qualified=False)
    (work/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f"{report['result']}: {len(cases)} release-anchor rotation cases; {work/'results.json'}")
    if report['result']!='PASS':raise SystemExit(1)
if __name__=='__main__':main()
