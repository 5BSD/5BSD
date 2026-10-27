#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise maintained buildenv command notices and command status propagation."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
from libmd_environment import BuildEnvironment


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('src','objtop','profile'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    env=BuildEnvironment(args.src,args.objtop,args.profile,Path('/usr/bin/make'))
    checks=[]
    with tempfile.TemporaryDirectory(prefix='buildenv-command-') as temporary:
        # Test executable-name dispatch without requiring an installed Zsh.
        named_shell=Path(temporary)/'zsh';named_shell.symlink_to('/bin/sh')
        cases=[('word argument',['/bin/echo','zsh'],False,0,'zsh\n'),
               ('path argument',['/bin/echo','/usr/src/bin/zsh'],False,0,'/usr/src/bin/zsh\n'),
               ('selected executable',[str(named_shell),'-c','exit 0'],True,0,''),
               ('command failure',['/bin/sh','-c','exit 23'],False,None,'')]
        for name,command,notice,status,payload in cases:
            argv=[str(env.make),'-C',str(env.src),*env.fixed,*env.options,'buildenv','BUILDENV_SHELL='+shlex.join(command)]
            result=subprocess.run(argv,env=env.env,capture_output=True,text=True)
            prefix='Entering world for amd64:amd64\n'
            if not result.stdout.startswith(prefix):raise AssertionError('unexpected buildenv prefix')
            body=result.stdout[len(prefix):]
            if notice:
                line,sep,body=body.partition('\n')
                if not sep or not line.startswith('For ZSH you must run: export CPUTYPE='):raise AssertionError('missing selected-shell notice')
            if status is not None:
                if result.returncode!=status or body!=payload:
                    raise AssertionError(name+': '+repr((result.returncode,result.stdout,result.stderr)))
            else:
                # Make maps a failing child to its own nonzero exit code.
                if result.returncode==0 or 'Error code 23' not in result.stdout+result.stderr:
                    raise AssertionError('buildenv lost command failure')
            checks.append({'case':name,'status':'passed','make_exit_status':result.returncode})
    # The real zsh component query must have exactly the requested values.
    values=env.query(['-v','PROG','-v','MACHINE_ARCH'],component=env.src/'bin/zsh')
    if values!='zsh\namd64\n':raise AssertionError('component query contaminated: '+repr(values))
    env.verify()
    print(json.dumps({'status':'passed','checks':checks,'zsh_component_query':values,'scope':'Make buildenv dispatch/output; not Zsh runtime qualification','environment':env.receipt()},indent=2))


if __name__=='__main__':main()
