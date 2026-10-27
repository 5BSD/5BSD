#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the libutil provider generation and in-place object rewrite contract."""
from pathlib import Path
import argparse,json,shutil,subprocess,shlex
from libmd_environment import BuildEnvironment,digest
parser=argparse.ArgumentParser(description=__doc__)
for key in ('src','objtop','profile','output'):parser.add_argument('--'+key,type=Path,required=True)
a=parser.parse_args();src=a.src.resolve(strict=True);obj=a.objtop.resolve(strict=True);out=a.output.resolve()
if out.exists() or out==Path('/usr/obj') or not out.is_relative_to('/usr/obj') or any(p.is_relative_to(out) or out.is_relative_to(p) for p in (src,obj)):raise ValueError('fresh nonoverlapping output below /usr/obj required')
out.mkdir()
e=BuildEnvironment(src,obj,a.profile,Path('/usr/bin/make'));keys=['DTRACE','DTRACEFLAGS','_DTRACE_SYSROOT_FLAG','PATH'];rows=e.query([v for k in keys for v in ['-v',k]],component=src/'lib/libutil').splitlines();m=dict(zip(keys,rows));runenv=dict(e.env,PATH=m['PATH']);commands=[]
log=e.query(['logincap_provider.h'],obj=out,component=src/'lib/libutil');(out/'make-header.stdout').write_text(log)
(out/'probe.c').write_text('#include "logincap_provider.h"\nvoid qualification_probe(void) { LOGINCAP_SETUSERCONTEXT("qualification", 1001, 0, 0); }\n')
def run(name,argv):
 p=subprocess.run(argv,cwd=out,env=runenv,capture_output=True,text=True);commands.append({'name':name,'argv':argv,'exit_status':p.returncode,'stdout':p.stdout,'stderr':p.stderr});(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert p.returncode==0,(name,p.stderr);return p.stdout
cc=e.cc
provider_source=src/'lib/libutil/logincap_provider.d'
provider_sha=digest(provider_source)
for variant,flags in [('regular',[]),('pic',['-fpic','-DPIC'])]:
 original=out/(variant+'.o');patched=out/(variant+'-patched.o');provider=out/(variant+'-provider.o')
 run('compile-'+variant,[*cc,*flags,'-I'+str(out),'-c',str(out/'probe.c'),'-o',str(original)])
 before=digest(original);shutil.copyfile(original,patched)
 run('provider-'+variant,[*shlex.split(m['DTRACE']),*shlex.split(m['DTRACEFLAGS']),*shlex.split(m['_DTRACE_SYSROOT_FLAG']),'-G','-o',str(provider),'-s',str(src/'lib/libutil/logincap_provider.d'),str(patched)])
 assert digest(original)==before,'original input changed'
 assert digest(patched)!=before,'expected DTrace object rewrite absent'
 raw=run('provider-sections-'+variant,['/usr/bin/readelf','-SW',str(provider)]);assert '.SUNW_dof' in raw
 run('patched-symbols-'+variant,['/usr/bin/readelf','-sW',str(patched)])
commands_tools={name:shutil.which(name,path=m['PATH']) for name in ['dtrace','cpp','ld','objcopy']}
e.verify();assert digest(provider_source)==provider_sha;receipt={'status':'passed','scope':'Make-generated libutil header, DTrace regular/PIC object mutation and preservation of original inputs; not native Bazel DTrace support','provider_source':{'path':str(provider_source),'sha256':provider_sha},'tools':commands_tools,'tool_sha256':{p:digest(Path(p)) for p in commands_tools.values()},'files':{str(p):digest(p) for p in out.iterdir() if p.suffix in ['.c','.h','.o']},'environment':e.receipt(),'limitations':['Uses the host-selected DTrace and execution runtime.','No installed tracing or kernel probe activation was tested.']};(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print('PASS: DTrace mutates regular/PIC copies; original objects preserved; provider DOF sections present')
